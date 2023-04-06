from django.shortcuts import render, redirect, get_object_or_404
from .models import Profiles
from .forms import ProfileForm, UpdateProfileForm, LoginForm, OTPForm
from .utils import encrypt_field, decrypt_field
from django_ratelimit.decorators import ratelimit
from django.conf import settings
from django.http import HttpResponseForbidden
from django.contrib.auth import authenticate, get_user_model, login
from django.core.mail import send_mail
import pyotp
from django.contrib.auth.decorators import login_required

def send_otp_email(user, otp):
    subject = 'Your One-Time Password for Login'
    message = f'Your One-Time Password for login is: {otp}\n\nPlease use this OTP to complete the login process.'
    from_email = 'your_email@example.com'  # Replace with your email
    to_email = [user.email]

    send_mail(subject, message, from_email, to_email)
    
def verify_otp(request):
    if request.method == 'POST':
        form = OTPForm(request.POST)
        if form.is_valid():
            submitted_otp = form.cleaned_data['otp']
            stored_otp = request.session.get('otp')
            user_id = request.session.get('user_id')

            if submitted_otp == stored_otp:
                User = get_user_model()
                user = User.objects.get(id=user_id)
                login(request, user)

                del request.session['otp']
                del request.session['user_id']

                return redirect('profile_list')  # Redirect to your desired page after a successful login
            else:
                return HttpResponseForbidden("Invalid OTP.")
    else:
        form = OTPForm()
    return render(request, 'verify_otp.html', {'form': form})
    
def login_view(request):
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user = authenticate(request, username=username, password=password)
            if user is not None:
                # Generate OTP
                otp = pyotp.random_base32()
                request.session['otp'] = otp
                request.session['user_id'] = user.id

                # Send OTP email
                send_otp_email(user, otp)

                return redirect('verify_otp')
            else:
                return HttpResponseForbidden("Invalid login credentials.")
    else:
        form = LoginForm()
    return render(request, 'login.html', {'form': form})

@login_required
#Use their IP addres as the key. If a user exceeds the limit, their request will be blocked and custom rate-limit view will be displayed.
@ratelimit(key='ip', rate='3/m', method='GET', block=True)
def create_profile(request):
    if request.method == 'POST':
        form = ProfileForm(request.POST)
        if form.is_valid():
            profile = form.save(commit=False)
            profile.password = encrypt_field(profile.password)
            profile.first_name = encrypt_field(profile.first_name)
            profile.last_name = encrypt_field(profile.last_name)
            profile.phone_number = encrypt_field(profile.phone_number)
            profile.gmail = encrypt_field(profile.gmail)
            profile.save()
            return redirect('profile_list')
    else:
        form = ProfileForm()
    return render(request, 'create_profile.html', {'form': form})

from django.shortcuts import render, get_object_or_404
from .models import Profiles
from .utils import decrypt_field

def profile_detail(request, pk):
    profile = get_object_or_404(Profiles, pk=pk)

    decrypted_profile = {
        'username': profile.username,
        'password': decrypt_field(profile.password, 'your_key'),
        'first_name': decrypt_field(profile.first_name, 'your_key'),
        'last_name': decrypt_field(profile.last_name, 'your_key'),
        'phone_number': decrypt_field(profile.phone_number, 'your_key'),
        'gmail': decrypt_field(profile.gmail, 'your_key'),
    }

    return render(request, 'profile_detail.html', {'profile': decrypted_profile})


def update_profile(request, pk):
    profile = get_object_or_404(Profiles, pk=pk)
    if request.method == 'POST':
        form = UpdateProfileForm(request.POST, instance=profile)
        if form.is_valid():
            updated_profile = form.save(commit=False)
            updated_profile.password = encrypt_field(updated_profile.password)
            updated_profile.first_name = encrypt_field(updated_profile.first_name)
            updated_profile.last_name = encrypt_field(updated_profile.last_name)
            updated_profile.phone_number = encrypt_field(updated_profile.phone_number)
            updated_profile.gmail = encrypt_field(updated_profile.gmail)
            updated_profile.save()
            return redirect('profile_list')
    else:
        form = UpdateProfileForm(instance=profile)
    return render(request, 'update_profile.html', {'form': form})

@login_required
def delete_profile(request, pk):
    profile = get_object_or_404(Profiles, pk=pk)

    # Ensure that only the owner of the profile or an admin can delete the profile
    if request.user == profile.user or request.user.is_staff:
        profile.delete()
        return redirect('login_app:profile_list')  # Redirect to the profile list view after deletion
    else:
        return HttpResponseForbidden("You don't have permission to delete this profile.")

def custom_ratelimit_view(request, exception):
    return HttpResponseForbidden("You have exceeded the allowed number of requests.")
