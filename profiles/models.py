from django.db import models
from django.contrib.auth.models import AbstractUser
from .encrypted_fields import EncryptedCharField
from django.conf import settings

class UserProfileBase(models.Model):
    phone_number = EncryptedCharField(max_length=20,encryption_key=settings.ENCRYPTION_KEY)
    
    class Meta:
        abstract = True

class UserProfile(models.Model):
    user = models.OneToOneField(AbstractUser, on_delete=models.CASCADE, related_name='profile')
