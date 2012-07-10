# -*- coding: utf-8 -*-

from flask import g
import flask.ext.wtf as wtf
from coaster import valid_username

from lastuserapp import RESERVED_USERNAMES
from lastuserapp.utils import strip_phone, valid_phone
from lastuserapp.models import User, UserEmail, UserEmailClaim, UserPhone, UserPhoneClaim, Organization, getuser


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
        if field.data in RESERVED_USERNAMES:
            raise wtf.ValidationError, "That name is reserved"
        existing = User.query.filter_by(username=field.data).first()
        if existing is not None and existing.id != self.edit_obj.id:
            raise wtf.ValidationError, "That username is taken"
        existing = Organization.query.filter_by(name=field.data).first()
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


class NewPhoneForm(wtf.Form):
    phone = wtf.TextField('Phone number', default='+91', validators=[wtf.Required()],
        description="Indian mobile numbers only")

    def validate_phone(self, field):
        existing = UserPhone.query.filter_by(phone=field.data).first()
        if existing is not None:
            if existing.user == g.user:
                raise wtf.ValidationError, "You have already registered this phone number."
            else:
                raise wtf.ValidationError, "That phone number has already been claimed."
        existing = UserPhoneClaim.query.filter_by(phone=field.data, user=g.user).first()
        if existing is not None:
            raise wtf.ValidationError, "That phone number is pending verification."
        # Step 1: Remove punctuation in number
        field.data = strip_phone(field.data)
        # Step 2: Validate number format
        if not valid_phone(field.data):
            raise wtf.ValidationError, "Invalid phone number (must be in international format with a leading + symbol)"
        # Step 3: Check if Indian number (startswith('+91'))
        if not field.data.startswith('+91') or len(field.data) != 13:
            raise wtf.ValidationError, "Only Indian mobile numbers are allowed at this time"


class VerifyPhoneForm(wtf.Form):
    verification_code = wtf.TextField('Verification code', validators=[wtf.Required()])

    def validate_verification_code(self, field):
        if self.phoneclaim.verification_code != field.data:
            raise wtf.ValidationError, "Verification code does not match."
