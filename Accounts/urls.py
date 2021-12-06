from django.urls import path
from .views import GoogleLoginView, GoogleSocialAuthView, Login, SignUp, VerifyEmail
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path('signup/', SignUp.as_view(), name="SignUp"),
    path('email-verify/<str:pk>/', VerifyEmail.as_view(), name="EmailVerification"),
    path('login/', Login.as_view(), name="Login"),
    path('token-refresh/',TokenRefreshView.as_view(),name="RefreshToken"),
    path('google/', GoogleSocialAuthView.as_view()),
    path('googlelogin/', GoogleLoginView),
]