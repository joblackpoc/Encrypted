from django.db import models
from django.contrib.auth.models import User
from .encrypted_fields import EncryptedCharField
from django.conf import settings

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    first_name = EncryptedCharField(max_length=255, encryption_key=settings.ENCRYPTION_KEY)
    last_name = EncryptedCharField(max_length=255, encryption_key=settings.ENCRYPTION_KEY)
    phone_number = EncryptedCharField(max_length=255, encryption_key=settings.ENCRYPTION_KEY)

    def __str__(self):
        return self.user.username
