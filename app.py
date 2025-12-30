import os
import io
import json
import re
import time
import hmac
import hashlib
import secrets
import tempfile
import logging
import base64
import multiprocessing as mp
import queue as _queue  # for Queue.Empty
from datetime import datetime, timedelta, timezone
from typing import Dict, Tuple, Optional

from flask import Flask, request, jsonify, send_file, make_response
from flask.cli import load_dotenv
from flask_cors import CORS
import jwt
from PyPDF2 import PdfReader, PdfWriter
from PyPDF2.errors import FileNotDecryptedError
from werkzeug.exceptions import RequestEntityTooLarge

# Rate limiting (memory backend works for local / single-process)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Crypto (AES-GCM for encrypting api_secret at rest)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ============================
# Env / Config
# ============================
# Pick correct .env file automatically
ENV = os.getenv("ENV", "prod").strip().lower()
load_dotenv(f".env.{ENV}")

print(f" Loaded config from .env.{ENV}")

# JWT for first-party request tokens (browser flow)
SECRET_KEY = os.environ.get("FLASK_SECRET", "change-me-in-prod")
API_ISSUER = os.environ.get("API_ISSUER", "pdf-tools")
REQ_TOKEN_TTL_SEC = int(os.environ.get("REQ_TOKEN_TTL_SEC", "120"))  # 2 minutes

# Request size limit (MB)
MAX_BODY_MB = int(os.environ.get("MAX_BODY_MB", "25"))

# Persistent keystore and usage store
HMAC_KEYS_PATH = os.environ.get("HMAC_KEYS_PATH", "hmac_keys.json")
HMAC_USAGE_PATH = os.environ.get("HMAC_USAGE_PATH", "hmac_usage.json")

# Daily per-key quota
DAILY_LIMIT = int(os.environ.get("DAILY_LIMIT", "5"))  # 5/day

# Limiter storage (in-memory by default)
REDIS_URL = os.environ.get("REDIS_URL", "memory://")  # keep memory for local

# Allowed CORS origins (read from env; comma-separated). Tolerate trailing slashes.
_raw_origins = (os.environ.get("ALLOWED_ORIGINS") or "").split(",")
ALLOWED_ORIGINS = [o.strip().rstrip("/") for o in _raw_origins if o.strip()]

# PDF processing guardrails
PDF_TIMEOUT_SEC = int(os.environ.get("PDF_TIMEOUT_SEC", "30"))  # sec
MAX_PAGES = int(os.environ.get("MAX_PAGES", "500"))

# AES-GCM master key (Base64-encoded 32 bytes). REQUIRED for prod.
# Example to generate: base64.urlsafe_b64encode(os.urandom(32)).decode()
MASTER_KEY_B64 = os.environ.get("MASTER_KEY_B64", "")
if not MASTER_KEY_B64 and ENV != "local":
    raise RuntimeError("MASTER_KEY_B64 must be set in non-local environments.")
try:
    MASTER_KEY: Optional[bytes] = base64.urlsafe_b64decode(MASTER_KEY_B64) if MASTER_KEY_B64 else None
except Exception:
    MASTER_KEY = None
    if ENV != "local":
        raise

# ============================
# App & Logging
# ============================
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_BODY_MB * 1024 * 1024

CORS(
    app,
    resources={r"/api/*": {"origins": ALLOWED_ORIGINS}},  # match your API routes
    supports_credentials=False,
    allow_headers=[
        "Content-Type",
        "X-REQ-TOKEN",
        "X-API-KEY",
        "X-API-TIMESTAMP",
        "X-API-SIGNATURE",
    ],
    methods=["POST", "GET", "DELETE", "OPTIONS"],
)

logging.basicConfig(
    level=logging.INFO if ENV != "local" else logging.DEBUG,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("pdf-tools")

# Limiter: we’ll use memory:// for now; rules defined per-route
limiter = Limiter(
    key_func=get_remote_address,   # not used for /api/key/generate (we override per-route)
    storage_uri=REDIS_URL,
    app=app,
)

# ============================
# Helpers (time, hashing, HMAC)
# ============================
def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def today_utc_str() -> str:
    return now_utc().strftime("%Y-%m-%d")

def midnight_reset_epoch() -> int:
    now = now_utc()
    tomorrow = (now + timedelta(days=1)).date()
    reset_dt = datetime.combine(tomorrow, datetime.min.time(), tzinfo=timezone.utc)
    return int(reset_dt.timestamp())

def sha256_hex(raw: bytes) -> str:
    return hashlib.sha256(raw or b"").hexdigest()

def sign_hmac(method: str, path: str, ts: str, body_hex: str, secret: str) -> str:
    msg = "\n".join([method.upper(), path, ts, body_hex]).encode("utf-8")
    return hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()

# Allowed: lowercase letters, digits, hyphens; max length 16
NAME_RE = re.compile(r'^[a-z0-9-]{1,16}$')

def _is_name_taken(name_norm: str) -> bool:
    """Check if a normalized name already exists (active or inactive)."""
    for rec in _KEY_STORE.values():
        if (rec.get("name") or "").strip().lower() == name_norm:
            return True
    return False

# ============================
# AES-GCM secret encryption
# ============================
def _aesgcm() -> AESGCM:
    key = MASTER_KEY or (b"\x00" * 32)  # local fallback for dev (DO NOT USE IN PROD)
    return AESGCM(key)

def encrypt_secret(plaintext: str) -> str:
    """
    Returns base64url(nonce || ciphertext_with_tag)
    """
    aes = _aesgcm()
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, plaintext.encode("utf-8"), associated_data=None)
    blob = nonce + ct
    return base64.urlsafe_b64encode(blob).decode()

def decrypt_secret(enc_b64: str) -> str:
    aes = _aesgcm()
    blob = base64.urlsafe_b64decode(enc_b64.encode())
    nonce, ct = blob[:12], blob[12:]
    pt = aes.decrypt(nonce, ct, associated_data=None)
    return pt.decode()

# ============================
# First-party request token (IP binding removed)
# ============================
_used_jti: Dict[str, float] = {}

def prune_used():
    t = time.time()
    stale = [k for k, exp in _used_jti.items() if exp < t]
    for k in stale:
        _used_jti.pop(k, None)

def mark_used(jti: str, exp_ts: float):
    prune_used()
    _used_jti[jti] = exp_ts

def already_used(jti: str) -> bool:
    prune_used()
    return jti in _used_jti

def issue_req_token() -> str:
    iat = now_utc()
    exp = iat + timedelta(seconds=REQ_TOKEN_TTL_SEC)
    jti = secrets.token_urlsafe(20)
    payload = {
        "iss": API_ISSUER,
        "aud": "request",
        "iat": int(iat.timestamp()),
        "exp": int(exp.timestamp()),
        "jti": jti,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def verify_req_token(token: str) -> Tuple[bool, str]:
    try:
        decoded = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=["HS256"],
            audience="request",
            issuer=API_ISSUER,
        )
        jti = decoded.get("jti") or ""
        if already_used(jti):
            return False, "replayed"
        mark_used(jti, decoded["exp"])
        return True, "ok"
    except jwt.ExpiredSignatureError:
        return False, "expired"
    except Exception:
        return False, "bad_token"

# ============================
# Keystore (encrypted secret at rest)
# ============================
# Store structure:
# {
#   "<api_key>": {
#       "secret_enc": "<base64(nonce||ct)>",
#       "secret_hash": "<sha256 hex of plaintext secret>",
#       "name": "<provided self-serve name>",
#       "created_at": "...",
#       "active": true
#   },
#   ...
# }

_KEY_STORE: Dict[str, Dict] = {}

def _atomic_write_json(path: str, data: dict):
    dir_ = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(dir_, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=dir_)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass

def _load_key_store() -> Dict[str, Dict]:
    if os.path.exists(HMAC_KEYS_PATH):
        with open(HMAC_KEYS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

def _save_key_store(store: Dict[str, Dict]):
    _atomic_write_json(HMAC_KEYS_PATH, store)

def _gen_key_id(n=12) -> str:
    return base64.urlsafe_b64encode(os.urandom(n)).decode().rstrip("=")

def _gen_secret(n=40) -> str:
    return secrets.token_urlsafe(n)

# On boot
_KEY_STORE = _load_key_store()

def get_secret_for_key(api_key: str) -> Optional[str]:
    rec = _KEY_STORE.get(api_key)
    if not rec or not rec.get("active", True):
        return None
    enc = rec.get("secret_enc")
    if not enc:
        return None
    try:
        return decrypt_secret(enc)
    except Exception:
        return None

# ============================
# Usage / Quota persistence
# ============================
def _load_usage_store() -> Dict[str, Dict[str, int]]:
    if os.path.exists(HMAC_USAGE_PATH):
        try:
            with open(HMAC_USAGE_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def _save_usage_store(store: Dict[str, Dict[str, int]]):
    _atomic_write_json(HMAC_USAGE_PATH, store)

_USAGE_STORE: Dict[str, Dict[str, int]] = _load_usage_store()

def get_usage(api_key: str, day_str: str) -> int:
    return int(_USAGE_STORE.get(api_key, {}).get(day_str, 0))

def set_usage(api_key: str, day_str: str, count: int) -> None:
    if api_key not in _USAGE_STORE:
        _USAGE_STORE[api_key] = {}
    _USAGE_STORE[api_key][day_str] = int(count)
    _save_usage_store(_USAGE_STORE)

def increment_usage(api_key: str, day_str: str) -> int:
    cnt = get_usage(api_key, day_str) + 1
    set_usage(api_key, day_str, cnt)
    return cnt

def ratelimit_headers(remaining: int) -> Dict[str, str]:
    return {
        "X-RateLimit-Limit": str(DAILY_LIMIT),
        "X-RateLimit-Remaining": str(max(0, remaining)),
        "X-RateLimit-Reset": str(midnight_reset_epoch()),
    }

# ============================
# HMAC verification (uses decrypted secret on demand)
# ============================
def verify_hmac(req) -> Tuple[bool, str]:
    api_key = req.headers.get("X-API-KEY")
    ts = req.headers.get("X-API-TIMESTAMP")
    sig = req.headers.get("X-API-SIGNATURE", "")
    if not api_key or not ts or not sig:
        return False, "missing_headers"

    secret = get_secret_for_key(api_key)
    if not secret:
        return False, "bad_api_key"

    # timestamp skew check ±300s
    try:
        t = float(ts) if str(ts).isdigit() else datetime.fromisoformat(str(ts).replace("Z", "+00:00")).timestamp()
    except Exception:
        return False, "bad_timestamp"
    if abs(time.time() - t) > 300:
        return False, "skew: Timestamp outside allowed window (±300s). Use current UNIX seconds or ISO-8601 UTC."

    raw = req.get_data(cache=True)
    expected = sign_hmac(req.method, req.path, ts, sha256_hex(raw), secret)
    if not hmac.compare_digest(sig, expected):
        return False, "bad_signature: HMAC does not match. Recompute using UPPER(method)\\npath\\ntimestamp\\nsha256_hex(raw_body) with your plaintext api_secret."

    return True, "ok"

# ============================
# PDF helper (timeout + isolation)
# ============================
def _unlock_worker(fd_bytes: bytes, password: str, out_q: mp.Queue, max_pages: int):
    try:
        if not fd_bytes.startswith(b"%PDF"):
            raise ValueError("Only PDF files are supported")

        bio = io.BytesIO(fd_bytes)
        reader = PdfReader(bio)

        if getattr(reader, "is_encrypted", False):
            ok = reader.decrypt(password)
            if not ok:
                raise ValueError("Incorrect password")

        try:
            total_pages = len(reader.pages)
        except FileNotDecryptedError:
            raise ValueError("Incorrect password")

        if total_pages > max_pages:
            raise ValueError("PDF too large")

        writer = PdfWriter()
        for p in reader.pages:
            writer.add_page(p)

        out = io.BytesIO()
        writer.write(out)
        out.seek(0)
        out_q.put(out.getvalue())

    except FileNotDecryptedError:
        out_q.put(ValueError("Incorrect password"))
    except Exception as e:
        out_q.put(e)

def unlock_with_timeout(file_storage, password: str, timeout_sec: int, max_pages: int) -> io.BytesIO:
    fd_bytes = file_storage.read()
    mb = max(1, len(fd_bytes) // (1024 * 1024))
    extra = max(0, min(20, mb - 2))
    effective_timeout = max(timeout_sec, timeout_sec + extra)

    q = mp.Queue(1)
    p = mp.Process(target=_unlock_worker, args=(fd_bytes, password, q, max_pages))
    p.start()
    try:
        result = q.get(timeout=effective_timeout)
    except _queue.Empty:
        if p.is_alive():
            p.terminate()
        p.join()
        raise TimeoutError("pdf_processing_timeout")
    finally:
        if p.is_alive():
            p.terminate()
        p.join()

    if isinstance(result, Exception):
        raise result

    buf = io.BytesIO(result)
    buf.seek(0)
    return buf

# ============================
# Global security headers
# ============================
@app.after_request
def add_security_headers(resp):
    # Frame protections (force-set, not setdefault)
    resp.headers["X-Frame-Options"] = "DENY"
    # Strong CSP (update/merge if you already have one elsewhere)
    resp.headers["Content-Security-Policy"] = (
        "frame-ancestors 'none'; "
        "default-src 'none'; "
        "base-uri 'none'; "
        "form-action 'none'"
    )
    # Sniffing / referrer
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    # HSTS only when explicitly enabled and behind TLS
    if os.environ.get("ENABLE_HSTS", "0") == "1":
        resp.headers["Strict-Transport-Security"] = "max-age=15552000; includeSubDomains"
    return resp

# ============================
# Routes
# ============================
@app.get("/health")
def health():
    return "ok", 200

# ---------- FIRST-PARTY (IP binding removed) ----------
@app.post("/api/prepare")
def prepare():
    origin = (request.headers.get("Origin") or "").rstrip("/")
    if ALLOWED_ORIGINS and origin and origin not in ALLOWED_ORIGINS:
        return jsonify({"error": "origin_not_allowed"}), 403
    token = issue_req_token()  # no IP binding
    return jsonify({"req_token": token}), 200

@app.post("/api/remove_password")
def remove_password_first_party():
    req_token = request.headers.get("X-REQ-TOKEN", "")
    ok, reason = verify_req_token(req_token)
    if not ok:
        return jsonify({"error": reason or "bad_token"}), 401

    uploaded = request.files.get("file") or request.files.get("pdfFile")
    if request.form.get("passwords"):
        return jsonify({"error": "multiple_passwords_not_allowed"}), 400
    password = (request.form.get("password") or "").strip()

    if not uploaded or not password:
        return jsonify({"error": "Missing file or password"}), 400

    try:
        pdf_io = unlock_with_timeout(uploaded, password, PDF_TIMEOUT_SEC, MAX_PAGES)
        return send_file(
            pdf_io,
            mimetype="application/pdf",
            as_attachment=True,
            download_name="unlocked.pdf",
        )
    except TimeoutError:
        return jsonify({"error": "processing_timeout"}), 504
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        log.exception("first-party processing_error")
        return jsonify({"error": "processing_error", "message": str(e)}), 500

# ---------- SELF-SERVE KEY MANAGEMENT ----------
def _normalized_name_from_request() -> str:
    data = request.get_json(silent=True) or {}
    return (data.get("name") or "").strip().lower()

# Rate limit: 1 per minute PER NAME (no IP involved)
_self_serve_rule = "1 per minute"

@limiter.limit(_self_serve_rule, key_func=lambda: f"name::{_normalized_name_from_request()}")
@app.post("/api/key/generate")
def self_serve_generate_key():
    """
    Body: { "name": "acme" }
    Returns: { api_key, api_secret, created_at, name }
    """
    data = request.get_json(silent=True) or {}
    raw_name = (data.get("name") or "").strip()
    name = raw_name.lower()

    if not name:
        return jsonify({"error": "name_required"}), 400

    # format validation
    if not NAME_RE.fullmatch(name):
        return jsonify({
            "error": "name_invalid",
            "message": "Name must be 1–16 chars, lowercase letters, digits, or hyphens only."
        }), 400

    # uniqueness (case-insensitive across all keys)
    if _is_name_taken(name):
        return jsonify({
            "error": "name_taken",
            "message": "This name is already in use. Choose a different one."
        }), 400

    # Create key + secret
    api_key = _gen_key_id()
    api_secret = _gen_secret()
    created_at = now_utc().isoformat()

    secret_enc = encrypt_secret(api_secret)
    secret_hash = sha256_hex(api_secret.encode("utf-8"))

    _KEY_STORE[api_key] = {
        "secret_enc": secret_enc,
        "secret_hash": secret_hash,
        "name": name,  # store normalized
        "created_at": created_at,
        "active": True,
    }
    _save_key_store(_KEY_STORE)

    log.info("self_serve_create name=%s key=%s", name, api_key[:4] + "...")

    return jsonify({
        "api_key": api_key,
        "api_secret": api_secret,  # show ONCE
        "name": name,
        "created_at": created_at,
    }), 201

@app.delete("/api/keys/<api_key>")
def self_serve_delete_key(api_key):
    """
    Deactivate a key. (You can add a lightweight confirmation model later.)
    """
    rec = _KEY_STORE.get(api_key)
    if not rec:
        return jsonify({"error": "not_found"}), 404

    rec["active"] = False
    _save_key_store(_KEY_STORE)
    log.info("self_serve_delete key=%s", api_key[:4] + "...")
    return jsonify({"ok": True}), 200

# ---------- THIRD-PARTY HMAC API ----------
@app.post("/api/v1/remove_password")
def remove_password_hmac():
    ok, reason = verify_hmac(request)
    api_key = request.headers.get("X-API-KEY", "")
    day = today_utc_str()

    def with_rl_headers(resp, remaining: int):
        for k, v in ratelimit_headers(remaining).items():
            resp.headers[k] = v
        return resp

    if not ok:
        remaining = max(0, DAILY_LIMIT - get_usage(api_key, day)) if api_key else DAILY_LIMIT
        return with_rl_headers(jsonify({"error": reason}), remaining), 401

    current = get_usage(api_key, day)
    if current >= DAILY_LIMIT:
        return with_rl_headers(
            jsonify({"error": "daily_quota_exceeded", "message": "You have exceeded your daily API calls"}),
            0
        ), 429

    uploaded = request.files.get("file") or request.files.get("pdfFile")
    if request.form.get("passwords"):
        return with_rl_headers(jsonify({"error": "multiple_passwords_not_allowed"}), DAILY_LIMIT - current), 400
    password = (request.form.get("password") or "").strip()

    if not uploaded or not password:
        remaining_now = max(0, DAILY_LIMIT - current)
        return with_rl_headers(jsonify({"error": "Missing file or password"}), remaining_now), 400

    try:
        pdf_io = unlock_with_timeout(uploaded, password, PDF_TIMEOUT_SEC, MAX_PAGES)
        used_after = increment_usage(api_key, day)
        remaining_after = max(0, DAILY_LIMIT - used_after)

        resp = make_response(send_file(
            pdf_io,
            mimetype="application/pdf",
            as_attachment=True,
            download_name="unlocked.pdf",
        ))
        return with_rl_headers(resp, remaining_after)
    except TimeoutError:
        remaining_now = max(0, DAILY_LIMIT - current)
        return with_rl_headers(jsonify({"error": "processing_timeout"}), remaining_now), 504
    except ValueError as ve:
        remaining_now = max(0, DAILY_LIMIT - current)
        return with_rl_headers(jsonify({"error": str(ve)}), remaining_now), 400
    except Exception as e:
        remaining_now = max(0, DAILY_LIMIT - current)
        log.exception("third-party processing_error key=%s", api_key[:4] + "...")
        return with_rl_headers(jsonify({"error": "processing_error", "message": str(e)}), remaining_now), 500

# ============================
# Error handlers (consistent JSON)
# ============================
@app.errorhandler(RequestEntityTooLarge)
def handle_413(e):
    api_key = request.headers.get("X-API-KEY", "")
    day = today_utc_str()
    remaining = max(0, DAILY_LIMIT - get_usage(api_key, day)) if api_key else DAILY_LIMIT
    resp = jsonify({"error": "payload_too_large", "message": "Request body exceeds limit"})
    resp.headers["X-RateLimit-Limit"] = str(DAILY_LIMIT)
    resp.headers["X-RateLimit-Remaining"] = str(remaining)
    resp.headers["X-RateLimit-Reset"] = str(midnight_reset_epoch())
    return resp, 413

@app.errorhandler(404)
def handle_404(e):
    return jsonify({"error": "not_found"}), 404

@app.errorhandler(405)
def handle_405(e):
    return jsonify({"error": "method_not_allowed"}), 405

@app.errorhandler(Exception)
def handle_500(e):
    log.exception("unhandled_exception")
    return jsonify({"error": "processing_error", "message": "Unexpected server error"}), 500

# ============================
# Main
# ============================
if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5000")),
        debug=(ENV == "local"),
        threaded=True,
    )
