from django import forms
from .models import Profiles
from captcha.fields import ReCaptchaField

class ProfileForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput)

    class Meta:
        model = Profiles
        fields = ['username', 'password', 'first_name', 'last_name', 'phone_number', 'gmail']

class UpdateProfileForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput)

    class Meta:
        model = Profiles
        fields = ['password', 'first_name', 'last_name', 'phone_number', 'gmail']

class LoginForm(forms.Form):
    username = forms.CharField()
    password = forms.CharField(widget=forms.PasswordInput)
    captcha = ReCaptchaField()
    
class OTPForm(forms.Form):
    otp = forms.CharField(label='One-Time Password')
