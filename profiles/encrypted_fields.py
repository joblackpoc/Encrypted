from django.db import models
from cryptography.fernet import Fernet
import base64

class EncryptedCharField(models.CharField):
    def __init__(self, *args, **kwargs):
        self.key = kwargs.pop('encryption_key', None)
        super().__init__(*args, **kwargs)

    def from_db_value(self, value, expression, connection):
        if value is None:
            return value
        f = Fernet(self.key)
        decrypted_value = f.decrypt(base64.b64decode(value))
        return decrypted_value.decode()

    def get_prep_value(self, value):
        if value is None:
            return value
        f = Fernet(self.key)
        encrypted_value = f.encrypt(value.encode())
        return base64.b64encode(encrypted_value).decode()
