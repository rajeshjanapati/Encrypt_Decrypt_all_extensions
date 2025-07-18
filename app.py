from flask import Flask, request, send_file
import io
import json
from PyPDF2 import PdfReader, PdfWriter
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import base64

app = Flask(__name__)

# ---------- PDF Handling ----------
def encrypt_pdf(file_contents, password):
    input_pdf = io.BytesIO(file_contents)
    reader = PdfReader(input_pdf)
    writer = PdfWriter()
    for page in reader.pages:
        writer.add_page(page)
    writer.encrypt(password)
    output_pdf = io.BytesIO()
    writer.write(output_pdf)
    return output_pdf.getvalue()

def decrypt_pdf(file_contents, password):
    input_pdf = io.BytesIO(file_contents)
    reader = PdfReader(input_pdf)
    if reader.is_encrypted and not reader.decrypt(password):
        return None
    writer = PdfWriter()
    for page in reader.pages:
        writer.add_page(page)
    output_pdf = io.BytesIO()
    writer.write(output_pdf)
    return output_pdf.getvalue()

# ---------- JSON Handling ----------
def encrypt_json(file_contents, password):
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32, count=100_000)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(file_contents)
    payload = {
        'salt': base64.b64encode(salt).decode(),
        'nonce': base64.b64encode(cipher.nonce).decode(),
        'tag': base64.b64encode(tag).decode(),
        'ciphertext': base64.b64encode(ciphertext).decode()
    }
    return json.dumps(payload).encode()

def decrypt_json(file_contents, password):
    try:
        data = json.loads(file_contents.decode())
        salt = base64.b64decode(data['salt'])
        nonce = base64.b64decode(data['nonce'])
        tag = base64.b64decode(data['tag'])
        ciphertext = base64.b64decode(data['ciphertext'])

        key = PBKDF2(password, salt, dkLen=32, count=100_000)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    except Exception as e:
        return None

# ---------- Routes ----------
@app.route('/encrypt', methods=['POST'])
def encrypt():
    if 'file' not in request.files:
        return "No file part", 400

    file = request.files['file']
    extension = request.form.get('extension', '').lower()
    password = request.form.get('password', 'rajesh')
    file_contents = file.read()

    if extension == 'pdf':
        encrypted = encrypt_pdf(file_contents, password)
        return send_file(io.BytesIO(encrypted), mimetype='application/pdf',
                         as_attachment=True, download_name='encrypted.pdf')

    elif extension == 'json':
        encrypted = encrypt_json(file_contents, password)
        return send_file(io.BytesIO(encrypted), mimetype='application/json',
                         as_attachment=True, download_name='encrypted.json')

    return "Unsupported file type", 400

@app.route('/decrypt', methods=['POST'])
def decrypt():
    if 'file' not in request.files:
        return "No file part", 400

    file = request.files['file']
    filename = file.filename.lower()
    password = request.form.get('password', 'rajesh')
    file_contents = file.read()

    if filename.endswith('.pdf'):
        decrypted = decrypt_pdf(file_contents, password)
        if decrypted is None:
            return "Incorrect password or decryption failed", 400
        return send_file(io.BytesIO(decrypted), mimetype='application/pdf',
                         as_attachment=True, download_name='decrypted.pdf')

    elif filename.endswith('.json'):
        decrypted = decrypt_json(file_contents, password)
        if decrypted is None:
            return "Incorrect password or decryption failed", 400
        return send_file(io.BytesIO(decrypted), mimetype='application/json',
                         as_attachment=True, download_name='decrypted.json')

    return "Unsupported file type", 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)



















# from flask import Flask, request, send_file
# import io
# import os
# import tempfile
# from PyPDF2 import PdfReader, PdfWriter
# import pyminizip

# app = Flask(__name__)

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

#     if reader.is_encrypted:
#         if not reader.decrypt(password):
#             return None

#     writer = PdfWriter()
#     for page in reader.pages:
#         writer.add_page(page)

#     output_pdf = io.BytesIO()
#     writer.write(output_pdf)
#     return output_pdf.getvalue()

# @app.route('/encrypt', methods=['POST'])
# def encrypt():
#     if 'file' not in request.files:
#         return "No file part", 400

#     file = request.files['file']
#     extension = request.form.get('extension', '')
#     password = request.form.get('password', 'rajesh')
#     file_contents = file.read()

#     # Instead of filename.endswith(), use extension directly
#     if extension == 'pdf':
#         encrypted_contents = encrypt_pdf(file_contents, password)
#         return send_file(
#             io.BytesIO(encrypted_contents),
#             mimetype='application/pdf',
#             as_attachment=True,
#             download_name='encrypted.pdf'
#         )
    
#     elif extension == 'xlsx':
#         with tempfile.TemporaryDirectory() as tmpdirname:
#             input_path = os.path.join(tmpdirname, 'temp.xlsx')
#             output_zip = os.path.join(tmpdirname, "encrypted_excel.zip")
            
#             with open(input_path, 'wb') as f:
#                 f.write(file_contents)

#             pyminizip.compress(input_path, None, output_zip, password, 5)

#             return send_file(
#                 output_zip,
#                 mimetype='application/zip',
#                 as_attachment=True,
#                 download_name='encrypted_excel.zip'
#             )
#     else:
#         return "Unsupported file type", 400

# @app.route('/decrypt', methods=['POST'])
# def decrypt():
#     if 'file' not in request.files:
#         return "No file part", 400

#     file = request.files['file']
#     filename = file.filename
#     password = request.form.get('password', 'rajesh')
#     file_contents = file.read()

#     if filename.endswith('.pdf'):
#         decrypted_contents = decrypt_pdf(file_contents, password)
#         if decrypted_contents is None:
#             return "Incorrect password or decryption failed", 400

#         return send_file(
#             io.BytesIO(decrypted_contents),
#             mimetype='application/pdf',
#             as_attachment=True,
#             download_name='decrypted.pdf'
#         )
    
#     elif filename.endswith('.zip'):
#         # Save and unzip with password
#         with tempfile.TemporaryDirectory() as tmpdirname:
#             zip_path = os.path.join(tmpdirname, filename)
#             output_dir = tmpdirname

#             with open(zip_path, 'wb') as f:
#                 f.write(file_contents)

#             try:
#                 os.system(f'unzip -P {password} "{zip_path}" -d "{output_dir}"')
#                 extracted_files = [
#                     f for f in os.listdir(output_dir)
#                     if f != filename
#                 ]
#                 if not extracted_files:
#                     return "Incorrect password or empty archive", 400

#                 extracted_path = os.path.join(output_dir, extracted_files[0])
#                 return send_file(
#                     extracted_path,
#                     mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
#                     as_attachment=True,
#                     download_name='decrypted.xlsx'
#                 )
#             except Exception as e:
#                 return f"Failed to decrypt zip: {str(e)}", 400
#     else:
#         return "Unsupported file type", 400

# if __name__ == '__main__':
#     app.run(host='0.0.0.0', port=5000, debug=True)
