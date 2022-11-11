from django import forms
from django.contrib.auth.forms import UserChangeForm, UserCreationForm, AuthenticationForm
from django.utils.translation import gettext_lazy as _
from . models import Timezone, User

#-----ADMIN USER CREATION AND AUTHENTICATION------------#
class CustomAdminUserCreationForm(UserCreationForm):
    class Meta(UserCreationForm):
        model = User
        fields = ["email", "name", "phone"]
        error_class = "error"


class CustomAdminUserChangeForm(UserChangeForm):
    class Meta:
        model = User
        fields = ["email", "name", "phone"]
        error_class = "error"

class MyAuthForm(AuthenticationForm):
    error_messages = {
        'invalid_login': _(
            "Invalid credentials. "
            "Fields may be case-sensitive."
        ),
        'inactive': _("This account is inactive."),
    }
    class Meta:
        model = User
        fields = ['username', 'password']
    def __init__(self, *args, **kwargs):
        super(MyAuthForm, self).__init__(*args, **kwargs)
        self.fields['username'].label = 'Email or Phone number'
        self.fields['password'].label = 'Password'

#----------------------------------------------------------#
