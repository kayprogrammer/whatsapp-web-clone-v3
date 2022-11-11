from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _

import re

class CustomPasswordValidator():

    def validate(self, password, user=None):
        special_characters = "[~\!@#\$%\^&\*\(\)_\+{}\":;'\[\]]"
        if not any(char.isdigit() for char in password) or not any(char.isalpha() for char in password) or not any(char in special_characters for char in password):
            raise ValidationError(_('Passwords must contain letters, numbers and special characters.'))
        if len(password) < 8:
            raise ValidationError(_('Password must contain at least 8 characters'), code="password_too_short")
    def get_help_text(self):
        return _("Passwords must contain letters, numbers and special characters. It must also contain at least 8 characters")

def phoneValidator(value):
    regex = r'^\+[0-9]*$'
    match = re.match(regex, value)
    if not match:
        raise ValueError('Phone number must be in this format: +1234567890')
    if len(value) < 10:
        raise ValueError('Phone number must be at least 10 chars')
    if len(value) > 15:
        raise ValueError('Phone number must be at most 15 chars')
    return value

# class CustomPasswordValidator():

#     def __init__(self, min_length=1):
#         self.min_length = min_length

#     def validate(self, password, user=None):
#         special_characters = "[~\!@#\$%\^&\*\(\)_\+{}\":;'\[\]]"
#         if not any(char.isdigit() for char in password):
#             raise ValidationError(_('Password must contain at least %(min_length)d digit.') % {'min_length': self.min_length})
#         if not any(char.isalpha() for char in password):
#             raise ValidationError(_('Password must contain at least %(min_length)d letter.') % {'min_length': self.min_length})
#         if not any(char in special_characters for char in password):
#             raise ValidationError(_('Password must contain at least %(min_length)d special character.') % {'min_length': self.min_length})
#         if len(password) < 8:
#             raise ValidationError(_('Password must contain at least characters'), code="password_too_short")

#     def get_help_text(self):
#         return ""
