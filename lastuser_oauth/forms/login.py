# -*- coding: utf-8 -*-

from flask import Markup, url_for, current_app, escape
import flask.ext.wtf as wtf
from coaster.utils import valid_username
from baseframe import _, __
import baseframe.forms as forms

from lastuser_core.models import User, UserEmail, getuser


class LoginPasswordResetException(Exception):
    pass


class LoginForm(forms.Form):
    username = forms.StringField(__("Username or Email"), validators=[forms.validators.DataRequired()])
    password = forms.PasswordField(__("Password"), validators=[forms.validators.DataRequired()])

    def validate_username(self, field):
        existing = getuser(field.data)
        if existing is None:
            raise forms.ValidationError(_("User does not exist"))

    def validate_password(self, field):
        user = getuser(self.username.data)
        if user and not user.pw_hash:
            raise LoginPasswordResetException()
        if user is None or not user.password_is(field.data):
            if not self.username.errors:
                raise forms.ValidationError(_("Incorrect password"))
        self.user = user


class RegisterForm(forms.Form):
    fullname = forms.StringField(__("Full name"), validators=[forms.validators.DataRequired()])
    email = forms.EmailField(__("Email address"), validators=[forms.validators.DataRequired(), forms.validators.ValidEmail()])
    username = forms.StringField(__("Username"), validators=[forms.validators.DataRequired()],
        description=__("Single word that can contain letters, numbers and dashes"))
    password = forms.PasswordField(__("Password"), validators=[forms.validators.DataRequired()])
    confirm_password = forms.PasswordField(__("Confirm password"),
        validators=[forms.validators.DataRequired(), forms.validators.EqualTo('password')])
    recaptcha = wtf.RecaptchaField(__("Are you human?"),
        description=__("Type both words into the text box to prove that you are a human and not a computer program"))

    def validate_username(self, field):
        if field.data in current_app.config['RESERVED_USERNAMES']:
            raise forms.ValidationError, _("This name is reserved")
        if not valid_username(field.data):
            raise forms.ValidationError(_(u"Invalid characters in name. Names must be made of ‘a-z’, ‘0-9’ and ‘-’, without trailing dashes"))
        existing = User.get(username=field.data)
        if existing is not None:
            raise forms.ValidationError(_("This username is taken"))

    def validate_email(self, field):
        field.data = field.data.lower()  # Convert to lowercase
        existing = UserEmail.get(email=field.data)
        if existing is not None:
            raise forms.ValidationError(Markup(
                _(u"This email address is already registered. Do you want to <a href=\"{loginurl}\">login</a> instead?").format(
                    loginurl=escape(url_for('.login')))))
