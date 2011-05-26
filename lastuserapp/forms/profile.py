# -*- coding: utf-8 -*-

import re

from flask import g
import flaskext.wtf as wtf

from lastuserapp.utils import valid_username
from lastuserapp.models import User, UserEmail, UserEmailClaim, getuser


class PasswordResetRequestForm(wtf.Form):
    username = wtf.TextField('Username or Email', validators=[wtf.Required()])

    def validate_username(self, field):
        user = getuser(field.data)
        if user is None:
            raise wtf.ValidationError, "Could not find a user with that id"
        self.user = user


class PasswordResetForm(wtf.Form):
    password = wtf.PasswordField('New password', validators=[wtf.Required()])
    confirm_password = wtf.PasswordField('Confirm password',
                          validators=[wtf.Required(), wtf.EqualTo('password')])


class PasswordChangeForm(wtf.Form):
    old_password = wtf.PasswordField('Current password', validators=[wtf.Required()])
    password = wtf.PasswordField('New password', validators=[wtf.Required()])
    confirm_password = wtf.PasswordField('Confirm password',
                          validators=[wtf.Required(), wtf.EqualTo('password')])

    def validate_old_password(self, field):
        if g.user is None:
            raise wtf.ValidationError, "Not logged in"
        if not g.user.password_is(field.data):
            raise wtf.ValidationError, "Incorrect password"


class ProfileForm(wtf.Form):
    fullname = wtf.TextField('Full name', validators=[wtf.Required()])
    username = wtf.TextField('Username (optional)', validators=[wtf.Optional()])
    description = wtf.TextAreaField('Bio')

    def validate_username(self, field):
        if not valid_username(field.data):
            raise wtf.ValidationError, "Invalid characters in username"
        if field.data == g.user.username:
            return
        existing = User.query.filter_by(username=field.data).first()
        if existing is not None:
            raise wtf.ValidationError, "That username is taken"


class NewEmailAddressForm(wtf.Form):
    email = wtf.html5.EmailField('Email address', validators=[wtf.Required(), wtf.Email()])

    def validate_email(self, field):
        existing = UserEmail.query.filter_by(email=field.data).first()
        if existing is not None:
            if existing.user == g.user:
                raise wtf.ValidationError, "You have already registered this email address."
            else:
                raise wtf.ValidationError, "That email address has already been claimed."
        existing = UserEmailClaim.query.filter_by(email=field.data, user=g.user).first()
        if existing is not None:
            raise wtf.ValidationError, "That email address is pending verification."
