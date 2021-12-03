from django.urls import path
from .views import Login, SignUp, VerifyEmail
from rest_framework_simplejwt.views import TokenRefreshView

urlpatterns = [
    path('signup/', SignUp.as_view(), name="SignUp"),
    path('email-verify/', VerifyEmail.as_view(), name="EmailVerification"),
    path('login/', Login.as_view(), name="Login"),
    path('token-refresh/',TokenRefreshView.as_view(),name="RefreshToken")
]