from django.conf import settings
from django.contrib.auth import get_user_model
from drf_yasg import openapi
from rest_framework import (mixins, generics, status)
from rest_framework.authtoken.models import Token
from rest_framework.authtoken.views import ObtainAuthToken
from django.http.response import Http404, HttpResponse, JsonResponse
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from django.core.mail import send_mail
from .utils import Util
from django.contrib.sites.shortcuts import get_current_site
from django.urls import reverse
import jwt
from drf_yasg.utils import swagger_auto_schema

from Accounts.serializers import GoogleSocialAuthSerializer, UserSerializer, EmailVerificationSerializer, LoginSerializer
from .models import User
from rest_framework import status
from rest_framework.response import Response
from rest_framework.generics import GenericAPIView

from django.shortcuts import render


# Create your views here.


class SignUp(mixins.ListModelMixin, mixins.CreateModelMixin, generics.GenericAPIView):
    
    serializer_class = UserSerializer

    def post(self, request, *args, **kwargs):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user_data = serializer.save_user(serializer.data)
            # user = User.objects.get(email=user_data['id'])

            token = RefreshToken.for_user(user_data).access_token
            # token = Token.objects.get_or_create(user=user)
            abs_url = settings.FRONT_END_HOST + "verify/token=" + str(token)
            email_body = "Hiii! Use link below to verify your email \n"+ abs_url
            data ={'email_body': email_body, 'email_subject': "Verify your Email",'to_email':user_data.email}


            Util.send_email(data)
            # send_mail(subject="Verify your Email",message=email_body,from_email=settings.EMAIL_HOST_USER, recipient_list=[user.email],fail_silently=False)
            return JsonResponse({'status': 'created', 'token': str(token)}, status=status.HTTP_201_CREATED)
        return JsonResponse(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyEmail(APIView):

    serializer_class = EmailVerificationSerializer

    token_param_config = openapi.Parameter('token',in_=openapi.IN_QUERY, type=openapi.TYPE_STRING, description="Enter token here")

    @swagger_auto_schema(manual_parameters=[token_param_config])
    def get(self, request, *args, **kwargs):
        token = self.kwargs['pk']

        try:
            payload = jwt.decode(token,settings.SECRET_KEY, algorithms=['HS256'])
            user = User.objects.get(id=payload['user_id'])
            if not user.verified:
                user.verified = True
                user.active = True
                user.save()
            return JsonResponse({'status': 'Email Successfully Verified'}, status=status.HTTP_200_OK)
        except jwt.ExpiredSignatureError as identifier:
            return JsonResponse({'error':"Activation Link has expired"}, status=status.HTTP_400_BAD_REQUEST)
        except jwt.exceptions.DecodeError as identifier:
            return JsonResponse({'error':"Invalid Token"}, status=status.HTTP_400_BAD_REQUEST)

class Login(generics.GenericAPIView):

    serializer_class = LoginSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data, context={'request':request})
        serializer.is_valid(raise_exception=True)
        return JsonResponse(serializer.validated_data, status=status.HTTP_200_OK)



class GoogleSocialAuthView(GenericAPIView):

    serializer_class = GoogleSocialAuthSerializer

    def post(self, request):
        """
        POST with "auth_token"
        Send an idtoken as from google to get user information
        """

        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = ((serializer.validated_data)['auth_token'])
        return Response(data, status=status.HTTP_200_OK)
