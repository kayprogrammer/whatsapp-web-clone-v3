from django.http import HttpRequest
from django.utils import timezone

from ninja.security import HttpBearer

from typing import Any, Optional

from apps.accounts.models import User

class CustomUserAuth(HttpBearer):
    def authenticate(self, request, token):
        from apps.accounts.views import decodeJWT
        user = decodeJWT(token)
        
        if not user:
            return False
        request.user = user
        if request.user and request.user.is_authenticated:
            User.objects.filter(id=request.user.id).update(is_online=timezone.now())
            return True

        return False

    # class Config:
    #     arbitrary_types_allowed = True

class CustomAdminUserAuth(HttpBearer):
    def authenticate(self, request, token):
        from accounts.views import decodeJWT
        user = decodeJWT(token)
        if not (user and user.is_staff):
            return False
        request.user = user
        if request.user and request.user.is_authenticated and request.user.is_staff:
            User.objects.filter(id=request.user.id).update(
                is_online=timezone.now())
            return True
        return False