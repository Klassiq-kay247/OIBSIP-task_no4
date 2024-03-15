from django.urls import path
from Account import views



app_name = "Account"

urlpatterns = [
    path("", views.register_view, name="sign-up"),
    path("index/", views.index, name="index"),
    path("login-in/", views.login_view, name="login-in"),
    path("sign-out/", views.logout_view, name="sign-out"),
    path("otp-verification/", views.otp_verification_view, name="otp-verification"),
    path('forgot-password/', views.forgot_password, name='forgot_password'),

    path("forgot-password/", views.forgot_password, name="forgot-password"),
    path("password-reset-confirm/<str:uidb64>/", views.password_reset_confirm, name="password-reset-confirm"),
    path("password-reset/<str:uidb64>/", views.password_reset, name="password-reset"),  # Add this URL
]