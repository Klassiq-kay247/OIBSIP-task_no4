Project Structure:
Account: Django app containing user authentication-related views, forms, models, and templates.
templates: HTML templates for user authentication pages.
static: Static files such as CSS, JavaScript, and images.
Usage:
User Registration: Users can create new accounts by providing their email address and password.
Email Verification: After registration, users receive an OTP (One-Time Password) via email for email verification.
Login: Registered users can log in using their email and password.
Logout: Users can log out of their accounts.
Forgot Password: Users can reset their passwords by providing their email address and verifying the OTP sent to their email.
Password Reset: After verifying the OTP, users can reset their passwords.
Environment Variables:
To run the application, you need to set the following environment variables:

EMAIL_HOST_USER: Email address for sending verification emails.
EMAIL_HOST_PASSWORD: Password for the email account.
You can set these variables in your environment or use a .env file in the project root directory.
