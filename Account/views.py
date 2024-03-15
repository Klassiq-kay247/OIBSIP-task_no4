from django.shortcuts import redirect, render
from Account.forms import  UserRegisterForm
from django.contrib.auth import login, authenticate, logout
from django.contrib import messages
from django.conf import settings
from Account.models import Account
from django.urls import reverse
from django.template.loader import render_to_string
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes, force_str
from django.contrib.sessions.models import Session
import random
import smtplib
import pyotp
from django.core.mail import send_mail



def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp_email(email, otp):
    subject = 'OTP Verification'
    message = f'Your OTP for email verification is: {otp}'
    from_email = settings.EMAIL_HOST_USER
    recipient_list = [email]
    send_mail(subject, message, from_email, recipient_list)


def index(request):
    return render(request, "Account/index.html")

def register_view(request):

    if request.method == "POST":
        form = UserRegisterForm(request.POST or None)
        if form.is_valid():
            new_user = form.save()
            username = form.cleaned_data.get("username")
            otp = generate_otp()
            request.session['email_verification_otp'] = otp  # Store OTP in session
            send_otp_email(new_user.email, otp)
            messages.success(request, f"Hey Enter Your Email OTP to verify your account!")
            new_user = authenticate(username=form.cleaned_data['email'], 
                                    password=form.cleaned_data['password1']
            )
            login(request, new_user)
            return redirect("Account:otp-verification")

     
    else:
        print("User can not be register")
        form = UserRegisterForm()
    
    context = {
        'form': form,
    }
    
    
    return render(request, "Account/sign-up.html", context)


def otp_verification_view(request):
    if request.method == "POST":
        entered_otp = request.POST.get('entered_otp')
        stored_otp = request.session.get('email_verification_otp')

        if entered_otp == stored_otp:
            del request.session['email_verification_otp']  # Remove OTP from session
            messages.success(request, "Email verified successfully!")
            return redirect("Account:login-in")  # Redirect to login page
        else:
            messages.error(request, "Invalid OTP. Please try again.")

    return render(request, 'Account/otp-verification.html')

def login_view(request):
    if request.user.is_authenticated:
        messages.warning(request, "fHey you are already Logged In.")
        return redirect('Account:index')
    
    if request.method == "POST":
        email = request.POST.get('email')
        password = request.POST.get('password')

        try:
            user = Account.objects.get(email=email)
            user = authenticate(request, email=email, password=password)

            if user is not None:
                login(request, user)
                messages.success(request, "You are Logged in successfully")
                return redirect('Account:index')
            else:
                messages.warning(request, "User Does Not Exist, Create an Account 🛑!!")
        except: #User.DoesNotExist:
            messages.warning(request, f"User with {email} does not exist")

   
        
    return render(request, "Account/login-in.html")

def logout_view(request):
    logout(request)
    messages.success(request, "You logged out 🚗")
    return redirect("Account:login-in")

def forgot_password(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        try:
            user = Account.objects.get(email=email)
        except Account.DoesNotExist:
            user = None

        if user:
            # Generate and send OTP to the user's email
            otp = generate_otp()
            request.session['password_reset_otp'] = otp  # Store OTP in session
            send_otp_email(user.email, otp)

            # Redirect to password reset confirmation page
            return redirect("Account:password-reset-confirm", uidb64=urlsafe_base64_encode(force_bytes(user.pk)))

        else:
            messages.error(request, 'User with this email does not exist.')

    return render(request, 'Account/forgot-password.html')

def password_reset_confirm(request, uidb64):
    user = None
    otp = request.session.get('password_reset_otp')

    if otp:
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = Account.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, Account.DoesNotExist):
            user = None

        if user:
            if request.method == 'POST':
                entered_otp = request.POST.get('otp')

                if entered_otp == otp:
                    # OTP is correct, proceed with password reset
                    del request.session['password_reset_otp']  # Remove OTP from session
                    return redirect("Account:password-reset", uidb64=uidb64)  # Redirect to password reset form

            context = {
                'uidb64': uidb64,
            }
            return render(request, 'Account/otp-entry.html', context)

    messages.error(request, 'Invalid OTP or user.')
    return redirect("Account:login-in")


def password_reset(request, uidb64):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = Account.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, Account.DoesNotExist):
        user = None

    if user:
        if request.method == 'POST':
            new_password = request.POST.get('new_password')
            user.set_password(new_password)
            user.save()
            messages.success(request, 'Your password has been reset successfully. You can now log in with your new password.')
            return redirect("Account:login-in")

        context = {
            'uidb64': uidb64,
        }
        return render(request, 'Account/password-reset.html', context)

    messages.error(request, 'Invalid user.')
    return redirect("Account:login-in")