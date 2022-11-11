from django.conf import settings
from ninja.security import HttpBearer
from datetime import datetime
from django.contrib.auth import get_user_model

import jwt

User = get_user_model()

class Authentication(HttpBearer):

    @staticmethod
    def verify_token(token):
        # decode the token
        try:
            decoded_data = jwt.decode(
                token, settings.SECRET_KEY, algorithms=["HS256"])
        except Exception:
            return None

        # check if token as exipired
        exp = decoded_data["exp"]

        if datetime.now().timestamp() > exp:
            return None

        return decoded_data