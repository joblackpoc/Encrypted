from django.db import models
from django.contrib.auth.models import User
from hashlib import sha256

class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    CID = models.IntegerField(max_length=13)
    Phone_number = models.CharField(max_length=10)

    def save(self, *args, **kwargs):
        # Encrypt fields before saving
        self.first_name = sha256(self.first_name.encode()).hexdigest()
        self.last_name = sha256(self.last_name.encode()).hexdigest()
        self.CID = sha256(str(self.CID).encode()).hexdigest()
        self.Phone_number = sha256(self.Phone_number.encode()).hexdigest()
        super().save(*args, **kwargs)

    def __str__(self):
        return self.user.username


class Salary(models.Model):
    CID = models.ForeignKey(UserProfile, on_delete=models.CASCADE)
    first_name = models.ForeignKey(UserProfile, on_delete=models.CASCADE)
    last_name = models.ForeignKey(UserProfile, on_delete=models.CASCADE)
    bank_account = models.IntegerField()
    salary = models.CharField(max_length=10)
    total = models.CharField(max_length=10)
    date_input = models.DateField()

    def __str__(self):
        return f"{self.CID} {self.first_name} {self.last_name} ({self.date_input})"
