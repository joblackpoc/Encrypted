import base64
import hashlib
import pyotp
from hashlib import sha256
from django.contrib.auth import logout
from django.contrib.auth.models import User
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django_ratelimit.decorators import ratelimit
from django_ratelimit.exceptions import Ratelimited
from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.utils.timezone import now
from .forms import  OTPForm, LoginForm
from .utils import generate_otp
from .forms import UserRegisterForm, UserProfileForm, ProfileUpdateForm, UserProfileDeleteForm, ProfileDeleteForm
from .models import Profile
from django.core.paginator import Paginator
from django.views.generic import ListView

RATELIMIT_ENABLE = getattr(settings, 'RATELIMIT_ENABLE', True)
LOGIN_RATELIMIT_FAILURE = getattr(settings, 'LOGIN_RATELIMIT_FAILURE', 10)
LOGIN_RATELIMIT_PERIOD = getattr(settings, 'LOGIN_RATELIMIT_PERIOD', 60)

def welcome(request):
    return render(request, 'profiles/welcome.html')

def send_otp_email(user, otp):
    subject = 'Your One-Time Password for Login'
    message = f'Your One-Time Password for login is: {otp}\n\nPlease use this OTP to complete the login process.'
    from_email = 'your_email@example.com'  # Replace with your email
    to_email = [user.email]

    send_mail(subject, message, from_email, to_email)
    
    
@login_required
def verify_otp(request):
    user = request.user
    if not user.profile.is_2fa_enabled:
        return redirect('home')
    totp = pyotp.TOTP(user.profile.otp_secret)
    otp = totp.now()
    request.session['otp'] = otp
    if request.method == 'POST':
        form = OTPForm(request.POST)
        if form.is_valid():
            if form.cleaned_data['otp'] == otp:
                request.session['is_verified'] = True
                return redirect('home')
            else:
                form.add_error('otp', 'Invalid OTP. Please try again.')
    else:
        form = OTPForm()
    return render(request, 'verify_otp.html', {'form': form})


@ratelimit(key='ip', rate='10/m', block=True, method=['POST'])
def login_view(request):
    if request.user.is_authenticated:
        return redirect('profile_detail')
    if request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            # Verify reCAPTCHA
            captcha = form.cleaned_data.get('captcha')
            recaptcha_secret_key = settings.RECAPTCHA_PRIVATE_KEY
            recaptcha_response = request.POST.get('g-recaptcha-response')
            data = {
                'secret': recaptcha_secret_key,
                'response': recaptcha_response
            }
            response = request.post('https://www.google.com/recaptcha/api/siteverify', data=data)
            result = response.json()
            if not result['success']:
                messages.error(request, 'Invalid reCAPTCHA. Please try again.')
                return redirect('login')
                
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            user = authenticate(request, username=username, password=password)
            if user is not None:
                # Check if the user has two-factor authentication enabled
                profile = Profile.objects.get(user=user)
                if profile.two_factor_enabled:
                    # If two-factor authentication is enabled, generate and send an OTP
                    otp = generate_otp()
                    request.session['otp'] = otp
                    request.session['otp_time'] = now().timestamp()
                    subject = 'Login OTP'
                    html_message = render_to_string('email_otp.html', {'otp': otp})
                    plain_message = strip_tags(html_message)
                    from_email = settings.EMAIL_HOST_USER
                    to_email = profile.user.email
                    send_mail(subject, plain_message, from_email, [to_email], html_message=html_message)
                    # Render the OTP verification form to the user
                    return redirect('verify_otp')
                else:
                    # If two-factor authentication is not enabled, log in the user
                    login(request, user)
                    return redirect('profile_detail')
            else:
                # If authentication fails, display an error message
                if RATELIMIT_ENABLE:
                    raise Ratelimited(login_view)
                else:
                    messages.error(request, 'Invalid username or password.')
    else:
        form = LoginForm()
    return render(request, 'login.html', {'form': form})

def register(request):
    if request.method == 'POST':
        user_form = UserRegisterForm(request.POST)
        profile_form = UserProfileForm(request.POST)
        if user_form.is_valid() and profile_form.is_valid():
            # Create new user and user profile objects
            user = user_form.save(commit=False)
            user.set_password(user_form.cleaned_data['password1','password2'])
            user.save()
            profile = profile_form.save(commit=False)
            profile.user = user
            # Encrypt necessary fields
            profile.CID = sha256(str(profile.CID).encode()).hexdigest()
            profile.Phone_number = sha256(profile.Phone_number.encode()).hexdigest()
            profile.save()
            # Log user in and redirect to profile detail view
            login(request, user)
            return redirect('profile_detail')
    else:
        user_form = UserRegisterForm()
        profile_form = UserProfileForm()
    return render(request, 'profiles/register.html', {'user_form': user_form, 'profile_form': profile_form})


@login_required
#Use their IP addres as the key. If a user exceeds the limit, their request will be blocked and custom rate-limit view will be displayed.
@ratelimit(key='ip', rate='3/m', method='GET', block=True)
def profile_detail(request):
    user = request.user
    profile = Profile.objects.get(user=user)
    # Decrypt necessary fields
    CID = profile.CID
    Phone_number = profile.Phone_number
    context = {'user': user, 'CID': CID, 'Phone_number': Phone_number}
    return render(request, 'profile_detail.html', context)


@login_required
#Use their IP addres as the key. If a user exceeds the limit, their request will be blocked and custom rate-limit view will be displayed.
@ratelimit(key='ip', rate='3/m', method='GET', block=True)
def profile_update(request):
    user = request.user
    profile = Profile.objects.get(user=user)
    if request.method == 'POST':
        form = ProfileUpdateForm(request.POST, instance=profile)
        if form.is_valid():
            # Update the user profile object
            profile = form.save(commit=False)
            # Encrypt necessary fields
            profile.CID = sha256(str(profile.CID).encode()).hexdigest()
            profile.Phone_number = sha256(profile.Phone_number.encode()).hexdigest()
            profile.save()
            messages.success(request, 'Profile updated successfully.')
            # Redirect to profile detail view
            return redirect('profile_detail')
    else:
        form = ProfileUpdateForm(instance=profile)
    return render(request, 'profile_update.html', {'form': form})

@login_required
#Use their IP addres as the key. If a user exceeds the limit, their request will be blocked and custom rate-limit view will be displayed.
@ratelimit(key='ip', rate='3/m', method='GET', block=True)
def profile_delete(request):
    user = request.user
    profile = Profile.objects.get(user=user)
    if request.method == 'POST':
        form = UserProfileDeleteForm(request.POST)
        if form.is_valid() and form.cleaned_data['confirm']:
            # Delete the user profile object
            profile.delete()
            # Log out the user
            logout(request)
            messages.success(request, 'Profile deleted successfully.')
            # Redirect to home page
            return redirect('home')
    else:
        form = UserProfileDeleteForm()
    return render(request, 'profile_confirm_delete.html', {'form': form})

@login_required
def profile_confirm_delete(request, pk):
    profile = get_object_or_404(Profile, pk=pk)
    
    if request.method == 'POST':
        form = ProfileDeleteForm(request.POST)
        if form.is_valid():
            if form.cleaned_data['confirm']:
                profile.delete()
                messages.success(request, 'Profile has been deleted successfully.')
                return redirect('profile_list')
            else:
                messages.error(request, 'Please confirm the deletion by checking the box.')
    else:
        form = ProfileDeleteForm()
    
    context = {'profile': profile, 'form': form}
    return render(request, 'profile_confirm_delete.html', context)

class UserProfileListView(ListView):
    model = Profile
    template_name = 'profile_list.html'
    context_object_name = 'profiles'
    paginate_by = 10  # Change this to set the number of profiles per page

def profile_list(request):
    profiles = Profile.objects.all()
    paginator = Paginator(profiles, 10)  # Change this to set the number of profiles per page
    page = request.GET.get('page')
    profiles = paginator.get_page(page)
    return render(request, 'profile_list.html', {'profiles': profiles})

def encrypt_salary_fields(salary):
    fields_to_encrypt = ['CID', 'first_name', 'last_name', 'bank_account', 'salary', 'total']
    for field_name in fields_to_encrypt:
        # Skip the date_input field
        if field_name == 'date_input':
            continue
        # Get the value of the field
        field_value = getattr(salary, field_name)
        # Encode the value with utf-8 and hash it with SHA256
        hashed_value = hashlib.sha256(field_value.encode('utf-8')).digest()
        # Encode the hashed value with base64
        encoded_value = base64.b64encode(hashed_value).decode('utf-8')
        # Set the encrypted value back to the model instance
        setattr(salary, field_name, encoded_value)
    # Save the encrypted model instance
    salary.save()