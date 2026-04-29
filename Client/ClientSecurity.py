from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from validate_email import validate_email as check_online
import hashlib
import random





class AsymmetricEncryptor:
    def __init__(self, public_key_pem: bytes):
        self.public_key = self._load_public_key(public_key_pem)

    def _load_public_key(self, pem: bytes):
        return serialization.load_pem_public_key(pem)

    def generate_encrypted_shift(self):
        """
        Generates a random shift and encrypts it using RSA
        """
        shift = random.randint(1, 255)
        shift_bytes = shift.to_bytes(2, "big")

        encrypted_shift = self.public_key.encrypt(
            shift_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return shift, encrypted_shift



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


def password_requirement(pwd):

    if pwd is None or pwd == "":
        return False, "Password cannot be empty"

    # Length
    if len(pwd) < 8 or len(pwd) > 20:
        return False, "Password length must be between 8 and 20 characters"

    # Space
    if " " in pwd:
        return False, "Password cannot contain spaces"

    # Letter
    if not any(c.isalpha() for c in pwd):
        return False, "Password must contain at least one letter"

    # Number
    if not any(c.isdigit() for c in pwd):
        return False ,"Password must contain at least one number"



    return True, "Account Successfully Created"





def validate_email_address(email):
    try:
        is_valid = check_online(
            email_address=email,
            check_format=True,
            check_blacklist=True,
            check_dns=True,
            check_smtp=True,
            smtp_from_address='my-app-verifier@example.com'
        )
        return is_valid
    except Exception as e:
        print(f"Error validating email: {e}")
        return False
