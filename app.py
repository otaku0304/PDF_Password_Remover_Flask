import os, io, json, time, hmac, hashlib, secrets
from datetime import datetime, timedelta, timezone
from typing import Dict, Tuple

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import jwt
from PyPDF2 import PdfReader, PdfWriter

# ----------------------------
# Env / Config
# ----------------------------
ENV = os.environ.get("ENV", "local")  # local | prod
SECRET_KEY = os.environ.get("FLASK_SECRET", "change-me-in-prod")           # JWT for first-party request tokens
API_ISSUER = os.environ.get("API_ISSUER", "pdf-tools")
REQ_TOKEN_TTL_SEC = int(os.environ.get("REQ_TOKEN_TTL_SEC", "120"))        # 2 minutes
MAX_BODY_MB = int(os.environ.get("MAX_BODY_MB", "25"))                     # sanity limit

# HMAC keys for /api/v1/*
HMAC_KEYS: Dict[str, str] = json.loads(os.environ.get("HMAC_KEYS_JSON", '{"demo-key-id":"demo-secret-verylong"}'))

# Allowed CORS origins (add your prod frontend domain)
ALLOWED_ORIGINS = [
    "http://localhost:4200",
    "https://pdf-fe-kappa.vercel.app",
]

# ----------------------------
# App
# ----------------------------
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_BODY_MB * 1024 * 1024

CORS(
    app,
    supports_credentials=False,
    origins=ALLOWED_ORIGINS,
    allow_headers=["Content-Type", "X-REQ-TOKEN", "X-API-KEY", "X-API-TIMESTAMP", "X-API-SIGNATURE"],
    methods=["POST", "OPTIONS"]
)

# ----------------------------
# Helpers
# ----------------------------
_used_jti: Dict[str, float] = {}  # jti -> expiry ts (for replay detection)

def now_utc() -> datetime:
    return datetime.now(timezone.utc)

def prune_used():
    """Prune expired JTIs (simple in-memory GC)."""
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

def issue_req_token(ip: str) -> str:
    iat = now_utc()
    exp = iat + timedelta(seconds=REQ_TOKEN_TTL_SEC)
    jti = secrets.token_urlsafe(20)
    payload = {
        "iss": API_ISSUER,
        "aud": "request",
        "iat": int(iat.timestamp()),
        "exp": int(exp.timestamp()),
        "jti": jti,
        "ip": ip,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def verify_req_token(token: str, ip: str) -> Tuple[bool, str]:
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"], audience="request", issuer=API_ISSUER)
        jti = decoded.get("jti") or ""
        tok_ip = decoded.get("ip") or ""
        if already_used(jti):
            return False, "replayed"
        if ip and tok_ip and ip != tok_ip:
            return False, "ip_mismatch"
        # Mark single-use
        mark_used(jti, decoded["exp"])
        return True, "ok"
    except jwt.ExpiredSignatureError:
        return False, "expired"
    except Exception:
        return False, "bad_token"

def sha256_hex(raw: bytes) -> str:
    return hashlib.sha256(raw or b"").hexdigest()

def sign_hmac(method: str, path: str, ts: str, body_hex: str, secret: str) -> str:
    msg = "\n".join([method.upper(), path, ts, body_hex]).encode("utf-8")
    return hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()

def verify_hmac(req) -> Tuple[bool, str]:
    api_key = req.headers.get("X-API-KEY")
    ts = req.headers.get("X-API-TIMESTAMP")
    sig = req.headers.get("X-API-SIGNATURE", "")
    if not api_key or not ts or not sig:
        return False, "missing_headers"
    secret = HMAC_KEYS.get(api_key)
    if not secret:
        return False, "bad_api_key"
    # timestamp skew check ±300s
    try:
        t = float(ts) if ts.isdigit() else datetime.fromisoformat(ts.replace("Z","+00:00")).timestamp()
    except Exception:
        return False, "bad_timestamp"
    if abs(time.time() - t) > 300:
        return False, "skew"
    raw = req.get_data(cache=True)
    expected = sign_hmac(req.method, req.path, ts, sha256_hex(raw), secret)
    if not hmac.compare_digest(sig, expected):
        return False, "bad_signature"
    return True, "ok"

def unlock_pdf_stream(uploaded_file, password: str) -> io.BytesIO:
    reader = PdfReader(uploaded_file)
    if getattr(reader, "is_encrypted", False):
        ok = reader.decrypt(password)
        if not ok:
            raise ValueError("Incorrect password")
    out = io.BytesIO()
    writer = PdfWriter()
    for p in reader.pages:
        writer.add_page(p)
    writer.write(out)
    out.seek(0)
    return out

# ----------------------------
# Routes
# ----------------------------
@app.post("/api/prepare")
def prepare():
    """First-party: mint a short-lived, single-use request token bound to client IP."""
    origin = request.headers.get("Origin") or ""
    if origin and origin not in ALLOWED_ORIGINS:
        return jsonify({"error": "origin_not_allowed"}), 403
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
    token = issue_req_token(ip)
    return jsonify({"req_token": token}), 200

@app.post("/api/remove_password")
def remove_password_first_party():
    """First-party: must send X-REQ-TOKEN from /api/prepare, single-use, short TTL."""
    req_token = request.headers.get("X-REQ-TOKEN", "")
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
    ok, reason = verify_req_token(req_token, ip)
    if not ok:
        return jsonify({"error": reason or "bad_token"}), 401

    uploaded = request.files.get("file") or request.files.get("pdfFile")
    password = request.form.get("password")
    if not uploaded or not password:
        return jsonify({"error": "Missing file or password"}), 400

    name = (uploaded.filename or "").lower()
    if not (name.endswith(".pdf") or (uploaded.mimetype or "").endswith("pdf")):
        return jsonify({"error": "Only PDF files are supported"}), 400

    try:
        pdf_io = unlock_pdf_stream(uploaded, password)
        return send_file(pdf_io, mimetype="application/pdf", as_attachment=True, download_name="unlocked.pdf")
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        return jsonify({"error": f"processing_error: {e}"}), 500

@app.post("/api/v1/remove_password")
def remove_password_hmac():
    """Third-party: HMAC-signed server-to-server."""
    ok, reason = verify_hmac(request)
    if not ok:
        return jsonify({"error": reason}), 401

    uploaded = request.files.get("file") or request.files.get("pdfFile")
    password = request.form.get("password")
    if not uploaded or not password:
        return jsonify({"error": "Missing file or password"}), 400

    name = (uploaded.filename or "").lower()
    if not (name.endswith(".pdf") or (uploaded.mimetype or "").endswith("pdf")):
        return jsonify({"error": "Only PDF files are supported"}), 400

    try:
        pdf_io = unlock_pdf_stream(uploaded, password)
        return send_file(pdf_io, mimetype="application/pdf", as_attachment=True, download_name="unlocked.pdf")
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        return jsonify({"error": f"processing_error: {e}"}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5000")), debug=(ENV=="local"))
