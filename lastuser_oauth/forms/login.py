# -*- coding: utf-8 -*-

from flask import Markup, url_for, current_app
import wtforms
import wtforms.fields.html5
import flask.ext.wtf as wtf
from coaster import valid_username
from baseframe.forms import Form

from lastuser_core.models import User, UserEmail, getuser


class LoginForm(Form):
    username = wtforms.TextField('Username or Email', validators=[wtforms.validators.Required()])
    password = wtforms.PasswordField('Password', validators=[wtforms.validators.Required()])

    def validate_username(self, field):
        existing = getuser(field.data)
        if existing is None:
            raise wtforms.ValidationError("User does not exist")

    def validate_password(self, field):
        user = getuser(self.username.data)
        if user is None or not user.password_is(field.data):
            raise wtforms.ValidationError("Incorrect password")
        self.user = user


class RegisterForm(Form):
    fullname = wtforms.TextField('Full name', validators=[wtforms.validators.Required()])
    email = wtforms.fields.html5.EmailField('Email address', validators=[wtforms.validators.Required(), wtforms.validators.Email()])
    username = wtforms.TextField('Username', validators=[wtforms.validators.Required()],
        description="Single word that can contain letters, numbers and dashes")
    password = wtforms.PasswordField('Password', validators=[wtforms.validators.Required()])
    confirm_password = wtforms.PasswordField('Confirm password',
                          validators=[wtforms.validators.Required(), wtforms.validators.EqualTo('password')])
    recaptcha = wtf.RecaptchaField('Are you human?',
        description="Type both words into the text box to prove that you are a human and not a computer program")

    def validate_username(self, field):
        if field.data in current_app.config['RESERVED_USERNAMES']:
            raise wtforms.ValidationError, "That name is reserved"
        if not valid_username(field.data):
            raise wtforms.ValidationError(u"Invalid characters in name. Names must be made of ‘a-z’, ‘0-9’ and ‘-’, without trailing dashes")
        existing = User.query.filter_by(username=field.data).first()
        if existing is not None:
            raise wtforms.ValidationError("That username is taken")

    def validate_email(self, field):
        field.data = field.data.lower()  # Convert to lowercase
        existing = UserEmail.query.filter_by(email=field.data).first()
        if existing is not None:
            raise wtforms.ValidationError(Markup(
                u'This email address is already registered. Do you want to <a href="{}">login</a> instead?'.format(
                    url_for('.login'))))
