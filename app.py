# below code is working fine for pdf, xml, json, csv, excel...!

from flask import Flask, request, send_file, render_template
from werkzeug.utils import secure_filename
from PyPDF2 import PdfReader, PdfWriter
from cryptography.fernet import Fernet
import os
import io
import json
import xml.etree.ElementTree as ET
import csv

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['ALLOWED_EXTENSIONS'] = {'pdf', 'json', 'xml', 'csv', 'xlsx', 'xls'}

# Ensure upload folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# ---------- Fernet Utilities ----------
def generate_cipher(password):
    key = password.encode('utf-8')
    key = key.ljust(32, b'0')[:32]  # Ensure 32 bytes
    return Fernet(Fernet.generate_key())

# ---------- PDF Handling ----------
def encrypt_pdf(file_stream, password):
    try:
        reader = PdfReader(file_stream)
        writer = PdfWriter()
        for page in reader.pages:
            writer.add_page(page)
        writer.encrypt(password)
        output = io.BytesIO()
        writer.write(output)
        output.seek(0)
        return output
    except Exception as e:
        print(f"PDF encryption failed: {e}")
        return None

# ---------- JSON Handling ----------
def encrypt_json(file_contents, password):
    try:
        data = json.loads(file_contents)
        cipher = generate_cipher(password)
        return cipher.encrypt(json.dumps(data).encode('utf-8'))
    except Exception as e:
        print(f"JSON encryption failed: {e}")
        return None

def decrypt_json(file_contents, password):
    try:
        cipher = generate_cipher(password)
        decrypted_data = cipher.decrypt(file_contents)
        return json.loads(decrypted_data.decode('utf-8'))
    except Exception as e:
        print(f"JSON decryption failed: {e}")
        return None

# ---------- XML Handling ----------
def encrypt_xml(file_contents, password):
    try:
        ET.fromstring(file_contents)
        cipher = generate_cipher(password)
        return cipher.encrypt(file_contents.encode('utf-8'))
    except Exception as e:
        print(f"XML encryption failed: {e}")
        return None

def decrypt_xml(file_contents, password):
    try:
        cipher = generate_cipher(password)
        decrypted = cipher.decrypt(file_contents)
        ET.fromstring(decrypted.decode('utf-8'))
        return decrypted
    except Exception as e:
        print(f"XML decryption failed: {e}")
        return None

# ---------- CSV Handling ----------
def encrypt_csv(file_contents, password):
    try:
        cipher = generate_cipher(password)
        return cipher.encrypt(file_contents.encode('utf-8'))
    except Exception as e:
        print(f"CSV encryption failed: {e}")
        return None

def decrypt_csv(file_contents, password):
    try:
        cipher = generate_cipher(password)
        decrypted = cipher.decrypt(file_contents)
        return decrypted
    except Exception as e:
        print(f"CSV decryption failed: {e}")
        return None

# ---------- Excel Handling (XLSX) ----------
def encrypt_excel_fernet(file_contents, password):
    try:
        cipher = generate_cipher(password)
        return cipher.encrypt(file_contents)
    except Exception as e:
        print(f"Excel encryption failed: {e}")
        return None

def decrypt_excel_fernet(file_contents, password):
    try:
        cipher = generate_cipher(password)
        return cipher.decrypt(file_contents)
    except Exception as e:
        print(f"Excel decryption failed: {e}")
        return None

# ---------- Routes ----------
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt_file():
    uploaded_file = request.files.get('file')
    password = request.form.get('password')

    if not uploaded_file or not allowed_file(uploaded_file.filename):
        return "Invalid file", 400

    filename = secure_filename(uploaded_file.filename)
    extension = filename.rsplit('.', 1)[1].lower()
    file_contents = uploaded_file.read()

    if extension == 'pdf':
        encrypted_file = encrypt_pdf(io.BytesIO(file_contents), password)
        if encrypted_file:
            return send_file(encrypted_file, as_attachment=True, download_name='encrypted.pdf')
        return "PDF encryption failed", 500

    elif extension == 'json':
        encrypted = encrypt_json(file_contents, password)
        if encrypted:
            return send_file(io.BytesIO(encrypted), as_attachment=True, download_name='encrypted.json')
        return "JSON encryption failed", 500

    elif extension == 'xml':
        encrypted = encrypt_xml(file_contents.decode(), password)
        if encrypted:
            return send_file(io.BytesIO(encrypted), as_attachment=True, download_name='encrypted.xml')
        return "XML encryption failed", 500

    elif extension == 'csv':
        encrypted = encrypt_csv(file_contents.decode(), password)
        if encrypted:
            return send_file(io.BytesIO(encrypted), as_attachment=True, download_name='encrypted.csv')
        return "CSV encryption failed", 500

    elif extension == 'xlsx':
        encrypted = encrypt_excel_fernet(file_contents, password)
        if encrypted:
            return send_file(io.BytesIO(encrypted), as_attachment=True, download_name='encrypted.xlsx')
        return "Excel encryption failed", 500

    elif extension == 'xls':
        encrypted = encrypt_excel_fernet(file_contents, password)
        if encrypted:
            return send_file(io.BytesIO(encrypted), as_attachment=True, download_name='encrypted.xlsx')
        return "Excel encryption failed", 500

    return "Unsupported file type", 400

@app.route('/decrypt', methods=['POST'])
def decrypt_file():
    uploaded_file = request.files.get('file')
    password = request.form.get('password')

    if not uploaded_file or not allowed_file(uploaded_file.filename):
        return "Invalid file", 400

    filename = secure_filename(uploaded_file.filename)
    extension = filename.rsplit('.', 1)[1].lower()
    file_contents = uploaded_file.read()

    if extension == 'json':
        decrypted = decrypt_json(file_contents, password)
        if decrypted:
            return decrypted
        return "Incorrect password or JSON decryption failed", 400

    elif extension == 'xml':
        decrypted = decrypt_xml(file_contents, password)
        if decrypted:
            return decrypted
        return "Incorrect password or XML decryption failed", 400

    elif extension == 'csv':
        decrypted = decrypt_csv(file_contents, password)
        if decrypted:
            return send_file(io.BytesIO(decrypted), as_attachment=True, download_name='decrypted.csv')
        return "Incorrect password or CSV decryption failed", 400

    elif extension == 'xlsx':
        decrypted = decrypt_excel_fernet(file_contents, password)
        if decrypted:
            return send_file(io.BytesIO(decrypted), as_attachment=True, download_name='decrypted.xlsx')
        return "Incorrect password or Excel decryption failed", 400

    elif extension == 'xls':
        decrypted = decrypt_excel_fernet(file_contents, password)
        if decrypted:
            return send_file(io.BytesIO(decrypted), as_attachment=True, download_name='decrypted.xlsx')
        return "Incorrect password or Excel decryption failed", 400

    return "Unsupported file type for decryption", 400

if __name__ == '__main__':
    app.run(debug=True)

















# code is working for pdf, json, xml, csv for ENCRYPT & DECRYPT ...!

# from flask import Flask, request, send_file
# import io
# import os
# import json
# import base64
# from PyPDF2 import PdfReader, PdfWriter
# from cryptography.fernet import Fernet

# app = Flask(__name__)

# # ---------- PDF Handling ----------
# def encrypt_pdf(file_contents, password):
#     input_pdf = io.BytesIO(file_contents)
#     reader = PdfReader(input_pdf)
#     writer = PdfWriter()
#     for page in reader.pages:
#         writer.add_page(page)
#     writer.encrypt(password)
#     output_pdf = io.BytesIO()
#     writer.write(output_pdf)
#     return output_pdf.getvalue()

# def decrypt_pdf(file_contents, password):
#     input_pdf = io.BytesIO(file_contents)
#     reader = PdfReader(input_pdf)
#     if reader.is_encrypted and not reader.decrypt(password):
#         return None
#     writer = PdfWriter()
#     for page in reader.pages:
#         writer.add_page(page)
#     output_pdf = io.BytesIO()
#     writer.write(output_pdf)
#     return output_pdf.getvalue()

# # ---------- Fernet Key Generator ----------
# def generate_cipher(password):
#     key = base64.urlsafe_b64encode(password.encode().ljust(32, b'0'))
#     return Fernet(key)

# # ---------- JSON Handling ----------
# def encrypt_json_fernet(file_contents, password):
#     try:
#         cipher = generate_cipher(password)
#         return cipher.encrypt(file_contents)
#     except Exception as e:
#         print(f"❌ JSON encryption failed: {e}")
#         return None

# def decrypt_json_fernet(file_contents, password):
#     try:
#         cipher = generate_cipher(password)
#         return cipher.decrypt(file_contents)
#     except Exception as e:
#         print(f"❌ JSON decryption failed: {e}")
#         return None

# # ---------- XML Handling ----------
# def encrypt_xml_fernet(file_contents, password):
#     try:
#         cipher = generate_cipher(password)
#         return cipher.encrypt(file_contents)
#     except Exception as e:
#         print(f"❌ XML encryption failed: {e}")
#         return None

# def decrypt_xml_fernet(file_contents, password):
#     try:
#         cipher = generate_cipher(password)
#         return cipher.decrypt(file_contents)
#     except Exception as e:
#         print(f"❌ XML decryption failed: {e}")
#         return None

# # ---------- CSV Handling ----------
# def encrypt_csv_fernet(file_contents, password):
#     try:
#         cipher = generate_cipher(password)
#         return cipher.encrypt(file_contents)
#     except Exception as e:
#         print(f"❌ CSV encryption failed: {e}")
#         return None

# def decrypt_csv_fernet(file_contents, password):
#     try:
#         cipher = generate_cipher(password)
#         return cipher.decrypt(file_contents)
#     except Exception as e:
#         print(f"❌ CSV decryption failed: {e}")
#         return None

# # ---------- Routes ----------
# @app.route('/encrypt', methods=['POST'])
# def encrypt():
#     if 'file' not in request.files:
#         return "No file part", 400

#     file = request.files['file']
#     extension = request.form.get('extension', '').lower()
#     password = request.form.get('password', 'rajesh')
#     file_contents = file.read()

#     if extension == 'pdf':
#         encrypted = encrypt_pdf(file_contents, password)
#         return send_file(io.BytesIO(encrypted), mimetype='application/pdf',
#                          as_attachment=True, download_name='encrypted.pdf')

#     elif extension == 'json':
#         encrypted = encrypt_json_fernet(file_contents, password)
#         if encrypted is None:
#             return "JSON encryption failed", 500
#         return send_file(io.BytesIO(encrypted), mimetype='application/octet-stream',
#                          as_attachment=True, download_name='encrypted.json')

#     elif extension == 'xml':
#         encrypted = encrypt_xml_fernet(file_contents, password)
#         if encrypted is None:
#             return "XML encryption failed", 500
#         return send_file(io.BytesIO(encrypted), mimetype='application/octet-stream',
#                          as_attachment=True, download_name='encrypted.xml')

#     elif extension == 'csv':
#         encrypted = encrypt_csv_fernet(file_contents, password)
#         if encrypted is None:
#             return "CSV encryption failed", 500
#         return send_file(io.BytesIO(encrypted), mimetype='application/octet-stream',
#                          as_attachment=True, download_name='encrypted.csv')

#     return "Unsupported file type", 400

# @app.route('/decrypt', methods=['POST'])
# def decrypt():
#     if 'file' not in request.files:
#         return "No file part", 400

#     file = request.files['file']
#     extension = request.form.get('extension', '').lower()
#     password = request.form.get('password', 'rajesh')
#     file_contents = file.read()

#     if extension == 'pdf':
#         decrypted = decrypt_pdf(file_contents, password)
#         if decrypted is None:
#             return "Incorrect password or PDF decryption failed", 400
#         return send_file(io.BytesIO(decrypted), mimetype='application/pdf',
#                          as_attachment=True, download_name='decrypted.pdf')

#     elif extension == 'json':
#         decrypted = decrypt_json_fernet(file_contents, password)
#         if decrypted is None:
#             return "Incorrect password or JSON decryption failed", 400
#         return send_file(io.BytesIO(decrypted), mimetype='application/json',
#                          as_attachment=True, download_name='decrypted.json')

#     elif extension == 'xml':
#         decrypted = decrypt_xml_fernet(file_contents, password)
#         if decrypted is None:
#             return "Incorrect password or XML decryption failed", 400
#         return send_file(io.BytesIO(decrypted), mimetype='application/xml',
#                          as_attachment=True, download_name='decrypted.xml')

#     elif extension == 'csv':
#         decrypted = decrypt_csv_fernet(file_contents, password)
#         if decrypted is None:
#             return "Incorrect password or CSV decryption failed", 400
#         return send_file(io.BytesIO(decrypted), mimetype='text/csv',
#                          as_attachment=True, download_name='decrypted.csv')

#     return "Unsupported file type", 400

# if __name__ == '__main__':
#     app.run(host='0.0.0.0', port=5000, debug=True)
















# code is working for pdf, json, xml...!

# from flask import Flask, request, send_file
# import io
# import os
# import json
# import base64
# from PyPDF2 import PdfReader, PdfWriter
# from cryptography.fernet import Fernet

# app = Flask(__name__)

# # ---------- PDF Handling ----------
# def encrypt_pdf(file_contents, password):
#     input_pdf = io.BytesIO(file_contents)
#     reader = PdfReader(input_pdf)
#     writer = PdfWriter()
#     for page in reader.pages:
#         writer.add_page(page)
#     writer.encrypt(password)
#     output_pdf = io.BytesIO()
#     writer.write(output_pdf)
#     return output_pdf.getvalue()

# def decrypt_pdf(file_contents, password):
#     input_pdf = io.BytesIO(file_contents)
#     reader = PdfReader(input_pdf)
#     if reader.is_encrypted and not reader.decrypt(password):
#         return None
#     writer = PdfWriter()
#     for page in reader.pages:
#         writer.add_page(page)
#     output_pdf = io.BytesIO()
#     writer.write(output_pdf)
#     return output_pdf.getvalue()

# # ---------- Fernet Key Generator ----------
# def generate_cipher(password):
#     key = base64.urlsafe_b64encode(password.encode().ljust(32, b'0'))
#     return Fernet(key)

# # ---------- JSON Handling ----------
# def encrypt_json_fernet(file_contents, password):
#     try:
#         cipher = generate_cipher(password)
#         return cipher.encrypt(file_contents)
#     except Exception as e:
#         print(f"❌ JSON encryption failed: {e}")
#         return None

# def decrypt_json_fernet(file_contents, password):
#     try:
#         cipher = generate_cipher(password)
#         return cipher.decrypt(file_contents)
#     except Exception as e:
#         print(f"❌ JSON decryption failed: {e}")
#         return None

# # ---------- XML Handling ----------
# def encrypt_xml_fernet(file_contents, password):
#     try:
#         cipher = generate_cipher(password)
#         return cipher.encrypt(file_contents)
#     except Exception as e:
#         print(f"❌ XML encryption failed: {e}")
#         return None

# def decrypt_xml_fernet(file_contents, password):
#     try:
#         cipher = generate_cipher(password)
#         return cipher.decrypt(file_contents)
#     except Exception as e:
#         print(f"❌ XML decryption failed: {e}")
#         return None

# # ---------- Routes ----------
# @app.route('/encrypt', methods=['POST'])
# def encrypt():
#     if 'file' not in request.files:
#         return "No file part", 400

#     file = request.files['file']
#     extension = request.form.get('extension', '').lower()
#     password = request.form.get('password', 'rajesh')
#     file_contents = file.read()

#     if extension == 'pdf':
#         encrypted = encrypt_pdf(file_contents, password)
#         return send_file(io.BytesIO(encrypted), mimetype='application/pdf',
#                          as_attachment=True, download_name='encrypted.pdf')

#     elif extension == 'json':
#         encrypted = encrypt_json_fernet(file_contents, password)
#         if encrypted is None:
#             return "JSON encryption failed", 500
#         return send_file(io.BytesIO(encrypted), mimetype='application/octet-stream',
#                          as_attachment=True, download_name='encrypted.json')

#     elif extension == 'xml':
#         encrypted = encrypt_xml_fernet(file_contents, password)
#         if encrypted is None:
#             return "XML encryption failed", 500
#         return send_file(io.BytesIO(encrypted), mimetype='application/octet-stream',
#                          as_attachment=True, download_name='encrypted.xml')

#     return "Unsupported file type", 400

# @app.route('/decrypt', methods=['POST'])
# def decrypt():
#     if 'file' not in request.files:
#         return "No file part", 400

#     file = request.files['file']
#     filename = file.filename.lower()
#     password = request.form.get('password', 'rajesh')
#     file_contents = file.read()

#     if filename.endswith('.pdf'):
#         decrypted = decrypt_pdf(file_contents, password)
#         if decrypted is None:
#             return "Incorrect password or PDF decryption failed", 400
#         return send_file(io.BytesIO(decrypted), mimetype='application/pdf',
#                          as_attachment=True, download_name='decrypted.pdf')

#     elif filename.endswith('.json'):
#         decrypted = decrypt_json_fernet(file_contents, password)
#         if decrypted is None:
#             return "Incorrect password or JSON decryption failed", 400
#         return send_file(io.BytesIO(decrypted), mimetype='application/json',
#                          as_attachment=True, download_name='decrypted.json')

#     elif filename.endswith('.xml'):
#         decrypted = decrypt_xml_fernet(file_contents, password)
#         if decrypted is None:
#             return "Incorrect password or XML decryption failed", 400
#         return send_file(io.BytesIO(decrypted), mimetype='application/xml',
#                          as_attachment=True, download_name='decrypted.xml')

#     return "Unsupported file type", 400

# if __name__ == '__main__':
#     app.run(host='0.0.0.0', port=5000, debug=True)

















# code with working pdf, json...!

# from flask import Flask, request, send_file
# import io
# import os
# import json
# import base64
# from PyPDF2 import PdfReader, PdfWriter
# from cryptography.fernet import Fernet

# app = Flask(__name__)

# # ---------- PDF Handling ----------
# def encrypt_pdf(file_contents, password):
#     input_pdf = io.BytesIO(file_contents)
#     reader = PdfReader(input_pdf)
#     writer = PdfWriter()
#     for page in reader.pages:
#         writer.add_page(page)
#     writer.encrypt(password)
#     output_pdf = io.BytesIO()
#     writer.write(output_pdf)
#     return output_pdf.getvalue()

# def decrypt_pdf(file_contents, password):
#     input_pdf = io.BytesIO(file_contents)
#     reader = PdfReader(input_pdf)
#     if reader.is_encrypted and not reader.decrypt(password):
#         return None
#     writer = PdfWriter()
#     for page in reader.pages:
#         writer.add_page(page)
#     output_pdf = io.BytesIO()
#     writer.write(output_pdf)
#     return output_pdf.getvalue()

# # ---------- JSON Handling with Fernet ----------
# def generate_cipher(password):
#     key = base64.urlsafe_b64encode(password.encode().ljust(32, b'0'))
#     return Fernet(key)

# def encrypt_json_fernet(file_contents, password):
#     try:
#         cipher = generate_cipher(password)
#         encrypted_data = cipher.encrypt(file_contents)
#         return encrypted_data
#     except Exception as e:
#         print(f"❌ JSON encryption failed: {e}")
#         return None

# def decrypt_json_fernet(file_contents, password):
#     try:
#         cipher = generate_cipher(password)
#         decrypted_data = cipher.decrypt(file_contents)
#         return decrypted_data
#     except Exception as e:
#         print(f"❌ JSON decryption failed: {e}")
#         return None

# # ---------- Routes ----------
# @app.route('/encrypt', methods=['POST'])
# def encrypt():
#     if 'file' not in request.files:
#         return "No file part", 400

#     file = request.files['file']
#     extension = request.form.get('extension', '').lower()
#     password = request.form.get('password', 'rajesh')
#     file_contents = file.read()

#     if extension == 'pdf':
#         encrypted = encrypt_pdf(file_contents, password)
#         return send_file(io.BytesIO(encrypted), mimetype='application/pdf',
#                          as_attachment=True, download_name='encrypted.pdf')

#     elif extension == 'json':
#         encrypted = encrypt_json_fernet(file_contents, password)
#         if encrypted is None:
#             return "JSON encryption failed", 500
#         return send_file(io.BytesIO(encrypted), mimetype='application/octet-stream',
#                          as_attachment=True, download_name='encrypted.json')

#     return "Unsupported file type", 400

# @app.route('/decrypt', methods=['POST'])
# def decrypt():
#     if 'file' not in request.files:
#         return "No file part", 400

#     file = request.files['file']
#     filename = file.filename.lower()
#     password = request.form.get('password', 'rajesh')
#     file_contents = file.read()

#     if filename.endswith('.pdf'):
#         decrypted = decrypt_pdf(file_contents, password)
#         if decrypted is None:
#             return "Incorrect password or PDF decryption failed", 400
#         return send_file(io.BytesIO(decrypted), mimetype='application/pdf',
#                          as_attachment=True, download_name='decrypted.pdf')

#     elif filename.endswith('.json'):
#         decrypted = decrypt_json_fernet(file_contents, password)
#         if decrypted is None:
#             return "Incorrect password or JSON decryption failed", 400
#         return send_file(io.BytesIO(decrypted), mimetype='application/json',
#                          as_attachment=True, download_name='decrypted.json')

#     return "Unsupported file type", 400

# if __name__ == '__main__':
#     app.run(host='0.0.0.0', port=5000, debug=True)























# # working perfectly for PDF, also for json it is working but file is encrypting not adding passcode...!

# # from flask import Flask, request, send_file
# # import io
# # import json
# # from PyPDF2 import PdfReader, PdfWriter
# # from Crypto.Cipher import AES
# # from Crypto.Random import get_random_bytes
# # from Crypto.Protocol.KDF import PBKDF2
# # import base64

# # app = Flask(__name__)

# # # ---------- PDF Handling ----------
# # def encrypt_pdf(file_contents, password):
# #     input_pdf = io.BytesIO(file_contents)
# #     reader = PdfReader(input_pdf)
# #     writer = PdfWriter()
# #     for page in reader.pages:
# #         writer.add_page(page)
# #     writer.encrypt(password)
# #     output_pdf = io.BytesIO()
# #     writer.write(output_pdf)
# #     return output_pdf.getvalue()

# # def decrypt_pdf(file_contents, password):
# #     input_pdf = io.BytesIO(file_contents)
# #     reader = PdfReader(input_pdf)
# #     if reader.is_encrypted and not reader.decrypt(password):
# #         return None
# #     writer = PdfWriter()
# #     for page in reader.pages:
# #         writer.add_page(page)
# #     output_pdf = io.BytesIO()
# #     writer.write(output_pdf)
# #     return output_pdf.getvalue()

# # # ---------- JSON Handling ----------
# # def encrypt_json(file_contents, password):
# #     salt = get_random_bytes(16)
# #     key = PBKDF2(password, salt, dkLen=32, count=100_000)
# #     cipher = AES.new(key, AES.MODE_GCM)
# #     ciphertext, tag = cipher.encrypt_and_digest(file_contents)
# #     payload = {
# #         'salt': base64.b64encode(salt).decode(),
# #         'nonce': base64.b64encode(cipher.nonce).decode(),
# #         'tag': base64.b64encode(tag).decode(),
# #         'ciphertext': base64.b64encode(ciphertext).decode()
# #     }
# #     return json.dumps(payload).encode()

# # def decrypt_json(file_contents, password):
# #     try:
# #         data = json.loads(file_contents.decode())
# #         salt = base64.b64decode(data['salt'])
# #         nonce = base64.b64decode(data['nonce'])
# #         tag = base64.b64decode(data['tag'])
# #         ciphertext = base64.b64decode(data['ciphertext'])

# #         key = PBKDF2(password, salt, dkLen=32, count=100_000)
# #         cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
# #         plaintext = cipher.decrypt_and_verify(ciphertext, tag)
# #         return plaintext
# #     except Exception as e:
# #         return None

# # # ---------- Routes ----------
# # @app.route('/encrypt', methods=['POST'])
# # def encrypt():
# #     if 'file' not in request.files:
# #         return "No file part", 400

# #     file = request.files['file']
# #     extension = request.form.get('extension', '').lower()
# #     password = request.form.get('password', 'rajesh')
# #     file_contents = file.read()

# #     if extension == 'pdf':
# #         encrypted = encrypt_pdf(file_contents, password)
# #         return send_file(io.BytesIO(encrypted), mimetype='application/pdf',
# #                          as_attachment=True, download_name='encrypted.pdf')

# #     elif extension == 'json':
# #         encrypted = encrypt_json(file_contents, password)
# #         return send_file(io.BytesIO(encrypted), mimetype='application/json',
# #                          as_attachment=True, download_name='encrypted.json')

# #     return "Unsupported file type", 400

# # @app.route('/decrypt', methods=['POST'])
# # def decrypt():
# #     if 'file' not in request.files:
# #         return "No file part", 400

# #     file = request.files['file']
# #     filename = file.filename.lower()
# #     password = request.form.get('password', 'rajesh')
# #     file_contents = file.read()

# #     if filename.endswith('.pdf'):
# #         decrypted = decrypt_pdf(file_contents, password)
# #         if decrypted is None:
# #             return "Incorrect password or decryption failed", 400
# #         return send_file(io.BytesIO(decrypted), mimetype='application/pdf',
# #                          as_attachment=True, download_name='decrypted.pdf')

# #     elif filename.endswith('.json'):
# #         decrypted = decrypt_json(file_contents, password)
# #         if decrypted is None:
# #             return "Incorrect password or decryption failed", 400
# #         return send_file(io.BytesIO(decrypted), mimetype='application/json',
# #                          as_attachment=True, download_name='decrypted.json')

# #     return "Unsupported file type", 400

# # if __name__ == '__main__':
# #     app.run(host='0.0.0.0', port=5000, debug=True)


