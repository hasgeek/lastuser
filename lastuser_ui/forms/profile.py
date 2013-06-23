# -*- coding: utf-8 -*-

from flask import g
import flask.ext.wtf as wtf
from baseframe.forms import Form, ValidEmailDomain

from lastuser_core.utils import strip_phone, valid_phone
from lastuser_core.models import UserEmail, UserEmailClaim, UserPhone, UserPhoneClaim


class NewEmailAddressForm(Form):
    email = wtf.html5.EmailField('Email address', validators=[wtf.Required(), wtf.Email(), ValidEmailDomain()])

    # TODO: Move to function and place before ValidEmailDomain()
    def validate_email(self, field):
        field.data = field.data.lower()  # Convert to lowercase
        existing = UserEmail.query.filter_by(email=field.data).first()
        if existing is not None:
            if existing.user == g.user:
                raise wtf.ValidationError("You have already registered this email address.")
            else:
                raise wtf.ValidationError("This email address has already been claimed.")
        existing = UserEmailClaim.query.filter_by(email=field.data, user=g.user).first()
        if existing is not None:
            raise wtf.ValidationError("This email address is pending verification.")


class NewPhoneForm(Form):
    phone = wtf.TextField('Phone number', default='+91', validators=[wtf.Required()],
        description="Indian mobile numbers only")

    def validate_phone(self, field):
        existing = UserPhone.query.filter_by(phone=field.data).first()
        if existing is not None:
            if existing.user == g.user:
                raise wtf.ValidationError("You have already registered this phone number.")
            else:
                raise wtf.ValidationError("That phone number has already been claimed.")
        existing = UserPhoneClaim.query.filter_by(phone=field.data, user=g.user).first()
        if existing is not None:
            raise wtf.ValidationError("That phone number is pending verification.")
        # Step 1: Remove punctuation in number
        field.data = strip_phone(field.data)
        # Step 2: Validate number format
        if not valid_phone(field.data):
            raise wtf.ValidationError("Invalid phone number (must be in international format with a leading + symbol)")
        # Step 3: Check if Indian number (startswith('+91'))
        if not field.data.startswith('+91') or len(field.data) != 13:
            raise wtf.ValidationError("Only Indian mobile numbers are allowed at this time")


class VerifyPhoneForm(Form):
    verification_code = wtf.TextField('Verification code', validators=[wtf.Required()])

    def validate_verification_code(self, field):
        if self.phoneclaim.verification_code != field.data:
            raise wtf.ValidationError("Verification code does not match.")
