from flask import Flask, request, send_file
from PyPDF2 import PdfReader, PdfWriter
from flask_cors import CORS
import tempfile

from config import Config

app = Flask(__name__)

# Configure CORS to allow requests from your Angular app
CORS(app, resources=Config.CORS_RESOURCES)


@app.route('/remove_password', methods=['POST'])
def unlock_pdf():
    password = request.form.get('password')
    uploaded_file = request.files['pdfFile']

    if not password or not uploaded_file:
        return "Missing password or PDF file", 400

    try:
        # Create a temporary file to store the unlocked PDF
        temp_output = tempfile.NamedTemporaryFile(delete=False)

        # Create a PDF reader and writer
        pdf_reader = PdfReader(uploaded_file)
        pdf_writer = PdfWriter()

        # Decrypt the PDF using the provided password
        if pdf_reader.decrypt(password):
            for page_num in range(len(pdf_reader.pages)):
                pdf_writer.add_page(pdf_reader.pages[page_num])

            # Write the unlocked PDF to the temporary file
            pdf_writer.write(temp_output)

            # Close the temporary file
            temp_output.close()

            # Send the unlocked PDF file as an attachment
            return send_file(temp_output.name, as_attachment=True)

        return "Incorrect password", 400

    except Exception as e:
        return "An error occurred while processing the PDF: " + str(e), 500


if __name__ == '__main__':
    app.run(debug=True)
