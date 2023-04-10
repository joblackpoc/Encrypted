import random
import string
from django.shortcuts import render, redirect
from .models import UserProfile
from django.contrib.auth.models import User
from django.contrib.auth.forms import AuthenticationForm, UserChangeForm
from .forms import UserForm, UserProfileForm, OTPForm
from django_ratelimit.decorators import ratelimit
from django.core.paginator import Paginator
from django.http import HttpResponseForbidden, FileResponse
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import login as auth_login, get_user_model
from django.core.mail import send_mail
from django.contrib.auth.decorators import login_required
from captcha.fields import ReCaptchaField
from xhtml2pdf import pisa
from io import BytesIO

def welcome(request):
    return render(request, 'profiles/welcome.html')

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
            otp = form.cleaned_data.get('otp')
            stored_otp = request.session.get('otp')
            if otp == stored_otp:
                user_id = request.session.get('user_id')
                user = User.objects.get(id=user_id)
                login(request, user)
                messages.success(request, 'You have successfully logged in.')
                return redirect('home')
            else:
                messages.error(request, 'Invalid OTP. Please try again.')
    else:
        form = OTPForm()

    return render(request, 'verify_otp.html', {'form': form})

def login(request):
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        captcha = ReCaptchaField()

        # Check reCAPTCHA
        if not captcha.clean(request):
            messages.error(request, 'Invalid reCAPTCHA')
            return render(request, 'login.html', {'form': form})

        if form.is_valid():
            user = form.get_user()
            otp = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
            request.session['otp'] = otp
            request.session['user_id'] = user.id

            send_mail(
                'Two-Factor Authentication',
                f'Your One Time Password (OTP) is {otp}',
                settings.EMAIL_HOST_USER,
                [user.email],
                fail_silently=False,
            )

            return redirect('login_app:verify_otp')

        messages.error(request, 'Invalid username or password')
    else:
        form = AuthenticationForm()

    return render(request, 'login.html', {'form': form})


def register(request):
    if request.method == 'POST':
        form = UserForm(request.POST)
        profile_form = UserProfileForm(request.POST)
        if form.is_valid() and profile_form.is_valid():
            user = form.save()
            user_profile = profile_form.save(commit=False)
            #user_profile.user = user
            user_profile.save()

            # ... (send email with OTP and save OTP in the session)

            return redirect('profiles:verify_otp')
    else:
        form = UserForm()
        profile_form = UserProfileForm()
    return render(request, 'register.html', {'form': form, 'profile_form': profile_form})


@login_required
#Use their IP addres as the key. If a user exceeds the limit, their request will be blocked and custom rate-limit view will be displayed.
@ratelimit(key='ip', rate='3/m', method='GET', block=True)
def profile_detail(request):
    user = request.user
    user_profile = UserProfile.objects.get(user=user)
    return render(request, 'profile_detail.html', {'user': user, 'user_profile': user_profile})


@login_required
#Use their IP addres as the key. If a user exceeds the limit, their request will be blocked and custom rate-limit view will be displayed.
@ratelimit(key='ip', rate='3/m', method='GET', block=True)
def update_profile(request):
    user = request.user
    user_profile = UserProfile.objects.get(user=user)

    if request.method == 'POST':
        form = UserChangeForm(request.POST, instance=user)
        profile_form = UserProfileForm(request.POST, instance=user_profile)
        if form.is_valid() and profile_form.is_valid():
            form.save()
            profile_form.save()
            return redirect('login_app:profile_detail')
    else:
        form = UserChangeForm(instance=user)
        profile_form = UserProfileForm(instance=user_profile)
    return render(request, 'update_profile.html', {'form': form, 'profile_form': profile_form})

@login_required
#Use their IP addres as the key. If a user exceeds the limit, their request will be blocked and custom rate-limit view will be displayed.
@ratelimit(key='ip', rate='3/m', method='GET', block=True)
def profile_list(request):
    users = User.objects.all()

    user_profiles = []
    for user in users:
        user_profile = UserProfile.objects.get(user=user)
        user_profiles.append({
            'user': user,
            'user_profile': user_profile,
        })

    paginator = Paginator(user_profiles, 5)  # Show 5 profiles per page
    page = request.GET.get('page')
    profiles_page = paginator.get_page(page)

    return render(request, 'profile_list.html', {'profiles': profiles_page})

@login_required
#Use their IP addres as the key. If a user exceeds the limit, their request will be blocked and custom rate-limit view will be displayed.
@ratelimit(key='ip', rate='3/m', method='GET', block=True)
def delete_profile(request):
    user = request.user
    if request.method == 'POST':
        user.delete()
        messages.success(request, 'Your profile has been deleted.')
        return redirect('login_app:login')

    return render(request, 'delete_profile.html', {'user': user})

@login_required
def profile_detail_pdf(request):
    user = request.user
    user_profile = UserProfile.objects.get(user=user)

    # Render the profile detail to a string
    html_content = render_to_string('profile_detail_pdf.html', {
        'user': user,
        'user_profile': user_profile
    })

    # Convert the HTML content to a PDF file
    pdf_buffer = BytesIO()
    pisa.CreatePDF(BytesIO(html_content.encode()), pdf_buffer)

    # Serve the generated PDF as a response
    pdf_buffer.seek(0)
    response = FileResponse(pdf_buffer, content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="{user.username}_profile_detail.pdf"'

    return response

def custom_ratelimit_view(request, exception):
    return HttpResponseForbidden("You have exceeded the allowed number of requests.")
