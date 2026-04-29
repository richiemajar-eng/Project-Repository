from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from email.message import EmailMessage
import hashlib
import smtplib
import random






class RSAKeyManager:
    def __init__(self):
        self.private_key = None
        self.public_pem = None

    def generate_keys(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        public_key = self.private_key.public_key()

        self.public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return self.public_pem, self.private_key

    def decrypt_shift(self, encrypted_shift: bytes) -> int:

        if not self.private_key:
            raise ValueError("Keys not generated yet")

        shift_bytes = self.private_key.decrypt(
            encrypted_shift,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return int.from_bytes(shift_bytes, "big")



def encrypt(data, shift):
    result = bytearray()
    for b in data:
        result.append((b + shift) % 256)
    return bytes(result)

def decrypt(data, shift):
    result = bytearray()
    for b in data:
        result.append((b - shift) % 256)
    return bytes(result)


def hash_sha(data: bytes):
    return hashlib.sha256(data).hexdigest()




def send_verification_code(receiver_email):
    auth_code = str(random.randint(100000, 999999))

    sender_email = "richimajar@gmail.com"
    app_password = "uibb lnsp tmeu klng"

    msg = EmailMessage()
    msg['Subject'] = "🔑 קוד האימות שלך ל-backupApplication"
    msg['From'] = f"backupApplication <{sender_email}>"
    msg['To'] = receiver_email

    html_content = f"""
    <html>
        <body style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; direction: rtl; text-align: right; background-color: #f4f4f4; padding: 20px;">
            <div style="max-width: 400px; margin: auto; background: white; padding: 30px; border-radius: 15px; border-top: 5px solid #10b981; box-shadow: 0 4px 10px rgba(0,0,0,0.1);">
                <h2 style="color: #1a1a1a; margin-bottom: 10px;">שלום,</h2>
                <p style="color: #4b5563; font-size: 16px;">ביקשת לקבל קוד אימות כדי להיכנס למערכת הגיבוי שלנו.</p>

                <div style="background: #f0fdf4; border: 2px dashed #10b981; border-radius: 10px; padding: 20px; text-align: center; margin: 25px 0;">
                    <span style="font-size: 32px; font-weight: bold; letter-spacing: 5px; color: #059669;">{auth_code}</span>
                </div>

                <p style="color: #6b7280; font-size: 14px;">הקוד תקף ל-5 דקות הקרובות. אם לא ביקשת את הקוד הזה, אפשר פשוט להתעלם מהמייל.</p>

                <hr style="border: 0; border-top: 1px solid #e5e7eb; margin: 20px 0;">
                <p style="color: #9ca3af; font-size: 12px; text-align: center;">נשלח על ידי backupApplication Security System</p>
            </div>
        </body>
    </html>
    """

    # הוספת ה-HTML להודעה
    msg.add_alternative(html_content, subtype='html')

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(sender_email, app_password)
            server.send_message(msg)
        print(f"Success! email sent to {receiver_email}")
        return auth_code
    except Exception as e:
        print(f"Error: {e}")
        return None