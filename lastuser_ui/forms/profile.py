# -*- coding: utf-8 -*-

import wtforms
import wtforms.fields.html5
from baseframe.forms import Form, ValidEmailDomain

from lastuser_core.utils import strip_phone, valid_phone
from lastuser_core.models import UserEmail, UserEmailClaim, UserPhone, UserPhoneClaim


class NewEmailAddressForm(Form):
    email = wtforms.fields.html5.EmailField('Email address', validators=[wtforms.validators.Required(), wtforms.validators.Email(), ValidEmailDomain()])

    # TODO: Move to function and place before ValidEmailDomain()
    def validate_email(self, field):
        field.data = field.data.lower()  # Convert to lowercase
        existing = UserEmail.get(email=field.data)
        if existing is not None:
            if existing.user == g.user:
                raise wtforms.ValidationError("You have already registered this email address.")
            else:
                raise wtforms.ValidationError("This email address has already been claimed.")
        existing = UserEmailClaim.get(email=field.data, user=g.user)
        if existing is not None:
            raise wtforms.ValidationError("This email address is pending verification.")


class NewPhoneForm(Form):
    phone = wtforms.TextField('Phone number', default='+91', validators=[wtforms.validators.Required()],
        description="Indian mobile numbers only")

    def validate_phone(self, field):
        existing = UserPhone.get(phone=field.data)
        if existing is not None:
            if existing.user == g.user:
                raise wtforms.ValidationError("You have already registered this phone number.")
            else:
                raise wtforms.ValidationError("That phone number has already been claimed.")
        existing = UserPhoneClaim.get(phone=field.data, user=g.user)
        if existing is not None:
            raise wtforms.ValidationError("That phone number is pending verification.")
        # Step 1: Remove punctuation in number
        field.data = strip_phone(field.data)
        # Step 2: Validate number format
        if not valid_phone(field.data):
            raise wtforms.ValidationError("Invalid phone number (must be in international format with a leading + symbol)")
        # Step 3: Check if Indian number (startswith('+91'))
        if not field.data.startswith('+91') or len(field.data) != 13:
            raise wtforms.ValidationError("Only Indian mobile numbers are allowed at this time")


class VerifyPhoneForm(Form):
    verification_code = wtforms.TextField('Verification code', validators=[wtforms.validators.Required()])

    def validate_verification_code(self, field):
        if self.phoneclaim.verification_code != field.data:
            raise wtforms.ValidationError("Verification code does not match.")
