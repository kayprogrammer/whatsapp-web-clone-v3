from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.mail import EmailMessage
from django.template.loader import render_to_string 
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.conf import settings

from sms import Message
import six
import threading
import random

class EmailVerificationTokenGenerator(PasswordResetTokenGenerator):
    def _make_hash_value(self, user, timestamp):
        return (six.text_type(user.id)+six.text_type(timestamp)+six.text_type(user.is_email_verified))

email_verification_generate_token = EmailVerificationTokenGenerator()
password_reset_generate_token = PasswordResetTokenGenerator()

class MessageThread(threading.Thread):

    def __init__(self, email):
        self.email = email
        threading.Thread.__init__(self)

    def run(self):
        self.email.send()

class Util:
    @staticmethod
    def send_verification_email(user):
        subject = 'Activate your account'
        message = render_to_string('accounts/email-activation-message.html', {
            'name':user.name, 
            'FRONTEND_URL':settings.FRONTEND_URL, 
            'site_name': settings.SITE_NAME,
            'uid': urlsafe_base64_encode(force_bytes(user.id)),
            'token': email_verification_generate_token.make_token(user)
        })

        email_message = EmailMessage(subject=subject, body=message, to=[user.email])
        email_message.content_subtype = "html"
        
        MessageThread(email_message).start()
    
    @staticmethod
    def send_sms_otp(user):
        otp = random.randint(100000, 999999) 
        user.otp = otp
        user.save()
        message = Message(
            f'Hello {user.name}! \nYour Phone Verification OTP from {settings.SITE_NAME} is {otp}',
            settings.DEFAULT_FROM_PHONE,
            [user.phone]
        )

        MessageThread(message).start()

    @staticmethod
    def send_welcome_email(user):
        subject = 'Account Verified'
        message = render_to_string('accounts/welcomemessage.html', {
            'FRONTEND_URL':settings.FRONTEND_URL,
            'name':user.name, 
            'site_name': settings.SITE_NAME,
        })

        email_message = EmailMessage(subject=subject, body=message, to=[user.email])
        email_message.content_subtype = "html"
        
        MessageThread(email_message).start()

    @staticmethod
    def send_password_reset_email(user):
        subject = 'Reset your password'
        message = render_to_string('accounts/reset-password-email.html', {
            'name':user.name, 
            'FRONTEND_URL':settings.FRONTEND_URL, 
            'site_name': settings.SITE_NAME,
            'uid': urlsafe_base64_encode(force_bytes(user.id)),
            'token': password_reset_generate_token.make_token(user)
        })

        email_message = EmailMessage(subject=subject, body=message, to=[user.email])
        email_message.content_subtype = "html"
        
        MessageThread(email_message).start()