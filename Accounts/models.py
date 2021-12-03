from django.db import models

from django.contrib.auth.models import (AbstractBaseUser, BaseUserManager)
import rest_framework
from rest_framework_simplejwt.tokens import RefreshToken

# Create your models here.


class UserManager(BaseUserManager):
    def create_superuser(self, email, password=None ,is_active=True, is_staff=True, is_admin=True, is_verified=True):
        if not email:
            raise ValueError("User must have an email address")
        if not password:
            raise ValueError("User must have an password")
        user_obj = self.model(
            email = self.normalize_email(email)
        )
        user_obj.set_password(password)
        user_obj.staff = is_staff
        user_obj.admin = is_admin
        user_obj.active = is_active
        user_obj.verified = is_verified
        user_obj.save(using=self._db)
        return user_obj

    def create_staffuser(self, email, password=None):
        user = self.create_superuser(
            email,
            password=password,
            is_admin=False
        )
        return user
    
    def create_user(self, email, password=None):
        user = self.create_superuser(
            email,
            password=password,
            is_admin=False,
            is_staff=False,
            is_active=True,
            is_verified=False
        )
        return user

    
AUTH_PROVIDERS = {
    'facebook': 'facebook',
    'google': 'google',
    'twitter': 'twitter',
    'email': 'email'
}


class User(AbstractBaseUser):

    email     = models.EmailField(max_length=255, unique=True)
    active    = models.BooleanField(default=False)
    staff     = models.BooleanField(default=False)
    admin     = models.BooleanField(default=False)
    verified  = models.BooleanField(default=False)
    auth_provider = models.CharField(
        max_length=255, blank=False,
        null=False, default=AUTH_PROVIDERS.get('email'))

    USERNAME_FIELD = 'email'

    objects = UserManager()

    def __str__(self):
        return self.email

    def has_module_perms(self, app_label):
        return True

    def has_perm(self, app_label):
        return True

    @property
    def is_admin(self):
        return self.admin

    @property
    def is_staff(self):
        return self.staff

    @property
    def is_active(self):
        return self.active

    @property
    def is_verified(self):
        return self.verified
