import hashlib
import os
import base64
import random

def encrypt_field(field_value):
    salt = os.urandom(32)
    hashed_value = hashlib.sha256(salt + field_value.encode()).hexdigest()
    return salt.hex() + hashed_value

def decrypt_field(encrypted_field, key):
    salt = bytes.fromhex(encrypted_field[:64])
    encrypted_data = encrypted_field[64:]
    decrypted_value = hashlib.pbkdf2_hmac('sha256', encrypted_data.encode(), salt, 100000)
    return base64.b64decode(decrypted_value).decode('utf-8')

def generate_otp():
    return str(random.randint(100000, 999999))
