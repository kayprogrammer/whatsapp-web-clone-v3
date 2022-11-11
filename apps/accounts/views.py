from django.utils.encoding import force_str
from django.utils.http import urlsafe_base64_decode
from django.contrib.auth import authenticate
from django.conf import settings
from django.contrib.auth import get_user_model

from ninja import Router

from datetime import datetime, timedelta
import jwt
import random
import string
import json

from . schemas import (
    RegisterSchema, LoginSchema, SuccessMessageSchema, ErrorMessageSchema, 
    TokenReceiveSchema, VerifyPhoneSchema, ResendPhoneOTPSchema, ResendActivationEmailSchema,
    TokenRefreshSchema,  ResetPasswordEmailRequestSchema, SetNewPasswordSchema
)

from . models import Jwt, Timezone
from . senders import Util, email_verification_generate_token, password_reset_generate_token
from . authentication import Authentication

router = Router()

User = get_user_model()

#-------------------------------------------------------------------------------------------------
#----------------JWT AUTH AND TOKENS CREATION----------------------------------------------------------
#-------------------------------------------------------------------------------------------------------

def get_random(length):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))


def get_access_token(payload):
    return jwt.encode(
        {"exp": datetime.utcnow() + timedelta(minutes=5), **payload},
        settings.SECRET_KEY,
        algorithm="HS256"
    )


def get_refresh_token():
    return jwt.encode(
        {"exp": datetime.utcnow() + timedelta(hours=24), "data": get_random(10)},
        settings.SECRET_KEY,
        algorithm="HS256"
    )


def decodeJWT(token):
    if not token:
        return None

    try:
        decoded = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
    except:
        return None

    print(decoded)
    if decoded:
        try:
            return User.objects.get(id=decoded["user_id"])
        except Exception:
            return None
#-------------------------------------------------------------------------------------------------
#-------------------------------------------------------------------------------------------------------

#-----------------------------------------------------------------------------------------------
#----------------REGISTER LOGIN LOGOUT----------------------------------------------------------
#-----------------------------------------------------------------------------------------------
def convert_to_dict(value):
    value = value.decode('utf-8')
    return json.loads(value)

@router.post('/register', response={201: SuccessMessageSchema})
def register(request, data: RegisterSchema):
    response_data = request.body
    response_data = convert_to_dict(response_data)
    tz = response_data['tz'] 
    del response_data['tz']
    user = User.objects.create_user(tz=Timezone.objects.get(name=tz), **response_data)
    Util.send_verification_email(user)
    return 201, {'success': 'Account created'}

@router.post('/login', response={201: TokenReceiveSchema, 400: ErrorMessageSchema, 401: ErrorMessageSchema})
def login(request, data: LoginSchema):
    user = authenticate(
        username=data.email_or_phone,
        password=data.password
    )

    if not user:
        return 400, {'error': {
            'invalid_credentials': 'Invalid credentials'
        }}

    if not user.is_email_verified:
        return 401, {'error': {
            'email_not_verified': 'You must verify your email first'
        }}
        
    if not user.is_phone_verified:
        return 401, {'error': {
            'phone_not_verified': 'You must verify your phone number first'
        }}
        
    Jwt.objects.filter(user=user).delete()

    access = get_access_token({
        "user_id": str(user.id), "name":user.name, "email":user.email,
        "phone":user.phone, 'avatar': user.avatarURL, 'timezone': user.tz.name 
    })

    refresh = get_refresh_token()

    Jwt.objects.create(
        user=user, access=access, refresh=refresh
    )
    return 201, {'access': access, 'refresh': refresh}

@router.post('/token/refresh', response={201: TokenReceiveSchema, 422: ErrorMessageSchema})
def refresh_token(request, data: TokenRefreshSchema):
    try:
        active_jwt = Jwt.objects.get(
            refresh=data.refresh)
    except Jwt.DoesNotExist:
        return 422, {'error': {
            'not_found': 'refresh token not found'
            }    
        }
    if not Authentication.verify_token(data.refresh):
        return 422, {'error': {
            'invalid_token': 'Token is invalid or has expired'
            }    
        }

    access = get_access_token({
        "user_id": str(active_jwt.user.id), "name":active_jwt.user.name, 
        "email": active_jwt.user.email, 'phone': active_jwt.user.phone, 
        'avatar': active_jwt.user.avatarURL, 'timezone': active_jwt.user.tz.name 
    })

    refresh = get_refresh_token()


    active_jwt.access = access
    active_jwt.refresh = refresh
    active_jwt.save()

    return 201, {'access': access, 'refresh': refresh}


@router.post('/logout', response={200: SuccessMessageSchema})
def logout(request):
    user_id = request.user.id

    Jwt.objects.filter(user_id=user_id).delete()

    return 200, {'success': 'Logged out successfully'}
#-------------------------------------------------------------------------------------------------
#-------------------------------------------------------------------------------------------------------

#-------------------------------------------------------------------------------------------------
#----------------ACCOUNT VERIFICATION ----------------------------------------------------------
#-------------------------------------------------------------------------------------------------------

@router.get('/verify-email/{uidb64}/{token}', response={200: SuccessMessageSchema, 400: ErrorMessageSchema})
def verify_email(request, uidb64: str, token: str):
    try:
        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(id=uid)

    except Exception as e:
        user = None

    if user and email_verification_generate_token.check_token(user, token):
        user.is_email_verified = True
        user.save()
        Util.send_sms_otp(user)
        return 200, {'success': 'Email verified'}

    return 400, {'error': 'Link is broken, expired or has already been used'}

@router.post('/verify-phone', response={422: ErrorMessageSchema, 200: SuccessMessageSchema})
def verify_phone(request, data: VerifyPhoneSchema):

    phone = data.phone
    otp = data.otp
 
    user_obj = User.objects.filter(phone=phone)
    if not user_obj.exists():
        return 422, {'error': {
            'phone': 'Phone number not registered'
        }}
    user = user_obj.first()
    if user.otp != otp:
        return 422, {'error': {
            'otp': 'Invalid otp'
        }}
    if user.is_phone_verified:
        return 422, {'error': {
            'phone_already_verified': 'Phone Number already verified. Proceed to login!'
        }}

    user.is_phone_verified = True
    user.otp = None
    user.save()
    Util.send_welcome_email(user)
    return 200, {'success': 'Phone number verified'}

@router.post('/resend-phone-otp', response={422: ErrorMessageSchema, 200: SuccessMessageSchema})
def resend_phone_otp(request, data: ResendPhoneOTPSchema):
    phone = data.phone
    user = User.objects.filter(phone=phone)
    if not user.exists():
        return 422, {'error': {
            'phone': 'Phone number not registered'
        }}
    if user[0].is_phone_verified == True:
        return 422, {'error': {
            'phone_already_verified': 'Phone Number already verified. Proceed to login!'
        }}
    user = user.get()
    Util.send_sms_otp(user)
    return 200, {'success': 'New Otp sent!'}

@router.post('/resend-activation-email', response={422: ErrorMessageSchema, 200: SuccessMessageSchema})
def resend_activation_email(request, data: ResendActivationEmailSchema):
    email = data.email
    user = User.objects.filter(email=email)
    if not user.exists():
        return 422, {'error': {
            'email': 'Email address not registered'
        }}
    if user[0].is_email_verified == True:
        return 422, {'error': {
            'email_already_verified': 'Email address already verified. Proceed to login!'
        }}
    user = user.get()
    Util.send_verification_email(user)
    return 200, {'success': 'Activation link sent to email!'}

#-------------------------------------------------------------------------------------------------
#-------------------------------------------------------------------------------------------------------

#-------------------------------------------------------------------------------------------------
#----------------PASSWORD RESET----------------------------------------------------------
#-------------------------------------------------------------------------------------------------------

@router.post('/request-password-reset', response={422: ErrorMessageSchema, 200: SuccessMessageSchema})
def request_password_reset_email(request, data: ResetPasswordEmailRequestSchema):
    email = data.email
    user = User.objects.filter(email=email)
    if not user.exists():
        return 422, {'error': {
            'email': 'Email address not registered'
        }}
    user = user.get()
    Util.send_password_reset_email(user)
    return 200, {'success': 'Password email sent!'}

@router.post('/set-new-password', response={422: ErrorMessageSchema, 200: SuccessMessageSchema})
def set_new_password(request, data: SetNewPasswordSchema):
    try:
        uid = force_str(urlsafe_base64_decode(data.uid))
        user = User.objects.get(id=uid)

    except Exception as e:
        user = None

    if not user or not password_reset_generate_token.check_token(user, data.token):
        return 422, {'error': {
            'token_error': 'Link is broken, expired or has already been used'
        }}

    user.set_password(data.new_password)
    user.save()
    return 200, {'success': 'Password reset success!'}

#-------------------------------------------------------------------------------------------------
#-------------------------------------------------------------------------------------------------------
