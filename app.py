from flask import Flask, render_template, request
import pandas as pd
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64
import os
from dotenv import load_dotenv

load_dotenv()  # Load biến môi trường từ .env

app = Flask(__name__)

password = os.getenv("APP_PASSWORD").encode()
with open('data/salt.bin', 'rb') as f:
    salt = f.read()

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key = base64.urlsafe_b64encode(kdf.derive(password))
fernet = Fernet(key)

with open('data/SNBo.xlsx.enc', 'rb') as f:
    encrypted_data = f.read()
decrypted_data = fernet.decrypt(encrypted_data)

from io import BytesIO
df = pd.read_excel(BytesIO(decrypted_data), header=None)
df.columns = ['Date', 'SN', 'Verification Code']

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        sn_input = request.form['sn'].strip().upper()
        row = df[df['SN'] == sn_input]
        if not row.empty:
            result = row.iloc[0]['Verification Code']
        else:
            result = '❌ Không tìm thấy SN này.'
    return render_template('index.html', result=result)

if __name__ == '__main__':
    app.run(debug=True)
