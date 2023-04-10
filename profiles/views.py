from django.contrib.auth import logout
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django_ratelimit.decorators import ratelimit
from django_ratelimit.exceptions import Ratelimited
from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.utils.timezone import now
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from django.views.generic.edit import FormView
from django.views.generic.base import TemplateView
from .forms import LoginForm, VerifyOTPForm
from .models import UserProfile
from .utils import generate_otp
from .forms import RegistrationForm, UserProfileForm, UserProfileUpdateForm, UserProfileDeleteForm
from .models import UserProfile
from hashlib import sha256

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
    
@ratelimit(key='ip', rate='10/m', block=True, method=['POST'], 
    use_request_method=True, group=None, condition=None)
def verify_otp(request):
    if request.user.is_authenticated:
        return redirect('profile_detail')
    otp = request.session.get('otp')
    otp_time = request.session.get('otp_time')
    if not otp or not otp_time:
        messages.error(request, 'OTP session expired. Please log in again.')
        return redirect('login')
    if (now().timestamp() - otp_time) > settings.SESSION_COOKIE_AGE:
        messages.error(request, 'OTP session expired. Please log in again.')
        return redirect('login')
    if request.method == 'POST':
        form = VerifyOTPForm(request.POST)
        if form.is_valid():
            if form.cleaned_data['otp'] == otp:
                # If the OTP is valid, log in the user
                del request.session['otp']
                del request.session['otp_time']
                user = authenticate(request, username=form.cleaned_data['username'], password=form.cleaned_data['password'])
                if user is not None:
                    login(request, user)
                    return redirect('profile_detail')
                else:
                    messages.error(request, 'Invalid username or password.')
            else:
                # If the OTP is invalid, display an error message
                messages.error(request, 'Invalid OTP.')
    else:
        form = VerifyOTPForm()
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
        user_form = RegistrationForm(request.POST)
        profile_form = UserProfileForm(request.POST)
        if user_form.is_valid() and profile_form.is_valid():
            # Create new user and user profile objects
            user = user_form.save(commit=False)
            user.set_password(user_form.cleaned_data['password'])
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
        user_form = RegistrationForm()
        profile_form = UserProfileForm()
    return render(request, 'registration/register.html', {'user_form': user_form, 'profile_form': profile_form})


@login_required
#Use their IP addres as the key. If a user exceeds the limit, their request will be blocked and custom rate-limit view will be displayed.
@ratelimit(key='ip', rate='3/m', method='GET', block=True)
def profile_detail(request):
    user = request.user
    profile = UserProfile.objects.get(user=user)
    # Decrypt necessary fields
    CID = profile.CID
    Phone_number = profile.Phone_number
    context = {'user': user, 'CID': CID, 'Phone_number': Phone_number}
    return render(request, 'profile_detail.html', context)


@login_required
#Use their IP addres as the key. If a user exceeds the limit, their request will be blocked and custom rate-limit view will be displayed.
@ratelimit(key='ip', rate='3/m', method='GET', block=True)
def update_profile(request):
    user = request.user
    profile = UserProfile.objects.get(user=user)
    if request.method == 'POST':
        form = UserProfileUpdateForm(request.POST, instance=profile)
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
        form = UserProfileUpdateForm(instance=profile)
    return render(request, 'profile_update.html', {'form': form})

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

def profile_delete(request):
    user = request.user
    profile = UserProfile.objects.get(user=user)
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
