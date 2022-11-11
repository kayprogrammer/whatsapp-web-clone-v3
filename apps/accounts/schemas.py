from ninja import Schema
from pydantic import validator
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.contrib.auth.password_validation import validate_password
from django.utils.translation import gettext as _
from django.contrib.auth import get_user_model

from datetime import date, datetime, time, timedelta
from . models import Timezone
from . validators import phoneValidator

User = get_user_model()

class ErrorMessageSchema(Schema):
    error: dict

class SuccessMessageSchema(Schema):
    success: str
  
#------------------------------------------------------------------------------------------
#--------------------------------REGISTER LOGIN AUTH SCHEMAS-------------------------------
#------------------------------------------------------------------------------------------
class RegisterSchema(Schema):
    name: str 
    email : str
    phone: str
    tz: str
    password: str
    terms_agreement: bool

    # FIELD VALIDATIONS

    @validator('name')
    def name_validator(cls, v):
        # This can be done in validators, like wise some others. Just showing different ways of implementation
        if len(v) > 50:
            raise ValueError('50 chars max')
        if len(v) < 5:
            raise ValueError('5 chars min')

        return v

    @validator('email')
    def email_validator(cls, v):
        try:
            validate_email(v)
        except:
            raise ValueError('Invalid email')
        else:
            if User.objects.filter(email=v).exists():
                raise ValueError('Email address already registered')
        return v

    @validator('phone')
    def phone_validator(cls, v):
        val = phoneValidator(v)
        if User.objects.filter(phone=val).exists():
            raise ValueError('Phone number already registered')
        return val
    
    @validator('tz')
    def timezone_validator(cls, v):
        if not Timezone.objects.filter(name=v).exists():
            raise ValueError('Invalid Timezone')
        return v

    @validator('password')
    def password_validator(cls, v):
        try:
            validate_password(v)
        except ValidationError as e:
            errmessage = list(e)[0]
            raise ValueError(errmessage)
        return v
    
    @validator('terms_agreement')
    def terms_validator(cls, v):
        if v == False:
            raise ValueError('You must agree to terms and condition')
        return v
    
class LoginSchema(Schema):
    email_or_phone: str
    password : str

class TokenReceiveSchema(Schema):
    access: str
    refresh: str

class TokenRefreshSchema(Schema):
    refresh: str

#-----------------------------------------------------------------------------------------
#-----------------------------------------------------------------------------------------
        
#------------------------------------------------------------------------------------------
#---------------------------EMAIL AND PHONE VERIFICATION SCHEMAS---------------------------
#------------------------------------------------------------------------------------------

class VerifyPhoneSchema(Schema):
    phone: str
    otp: int

class ResendPhoneOTPSchema(Schema):
    phone: str

    @validator('phone')
    def phone_validator(cls, v):
        return phoneValidator(v)

class ResendActivationEmailSchema(Schema):
    email: str

    @validator('email')
    def email_validator(cls, v):
        try:
            validate_email(v)
        except:
            raise ValueError('Invalid email')
        return v

#-----------------------------------------------------------------------------------------
#-----------------------------------------------------------------------------------------

#------------------------------------------------------------------------------------------
#----------------------------------PASSWORD RESET SCHEMAS----------------------------------
#------------------------------------------------------------------------------------------

class ResetPasswordEmailRequestSchema(Schema):
    email: str

    @validator('email')
    def email_validator(cls, v):
        try:
            validate_email(v)
        except:
            raise ValueError('Invalid email')
        return v

class SetNewPasswordSchema(Schema):
    uid: str
    token: str
    new_password: str

    @validator('new_password')
    def password_validator(cls, v):
        try:
            validate_password(v)
        except ValidationError as e:
            errmessage = list(e)[0]
            raise ValueError(errmessage)
        return v

#-----------------------------------------------------------------------------------------
#-----------------------------------------------------------------------------------------
