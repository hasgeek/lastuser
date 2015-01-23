# -*- coding: utf-8 -*-

from flask import g
import wtforms
import wtforms.fields.html5
from coaster.utils import nullunicode
from baseframe import _, __
from baseframe.forms import Form, ValidEmail

from lastuser_core.utils import strip_phone, valid_phone
from lastuser_core.models import UserEmail, UserEmailClaim, UserPhone, UserPhoneClaim

__all__ = ['NewEmailAddressForm', 'NewPhoneForm', 'VerifyPhoneForm']


class NewEmailAddressForm(Form):
    email = wtforms.fields.html5.EmailField(__("Email address"), validators=[wtforms.validators.Required(), ValidEmail()])
    type = wtforms.RadioField(__("Type"), coerce=nullunicode, validators=[wtforms.validators.Optional()], choices=[
        (__(u"Home"), __(u"Home")),
        (__(u"Work"), __(u"Work")),
        (__(u"Other"), __(u"Other"))])

    # TODO: Move to function and place before ValidEmail()
    def validate_email(self, field):
        field.data = field.data.lower()  # Convert to lowercase
        existing = UserEmail.get(email=field.data)
        if existing is not None:
            if existing.user == g.user:
                raise wtforms.ValidationError(_("You have already registered this email address"))
            else:
                raise wtforms.ValidationError(_("This email address has already been claimed"))
        existing = UserEmailClaim.get(email=field.data, user=g.user)
        if existing is not None:
            raise wtforms.ValidationError(_("This email address is pending verification"))


class NewPhoneForm(Form):
    phone = wtforms.TextField(__("Phone number"), default='+91',
        validators=[
            wtforms.validators.Required(),
            wtforms.validators.Length(min=1, max=16, message=__("This is too long to be a valid phone number"))],
        description=__("Indian mobile numbers only"))
    type = wtforms.RadioField(__("Type"), coerce=nullunicode, validators=[wtforms.validators.Optional()], choices=[
        (__(u"Mobile"), __(u"Mobile")),
        (__(u"Home"), __(u"Home")),
        (__(u"Work"), __(u"Work")),
        (__(u"Other"), __(u"Other"))])

    def validate_phone(self, field):
        existing = UserPhone.get(phone=field.data)
        if existing is not None:
            if existing.user == g.user:
                raise wtforms.ValidationError(_("You have already registered this phone number"))
            else:
                raise wtforms.ValidationError(_("This phone number has already been claimed"))
        existing = UserPhoneClaim.get(phone=field.data, user=g.user)
        if existing is not None:
            raise wtforms.ValidationError(_("This phone number is pending verification"))
        # Step 1: Remove punctuation in number
        field.data = strip_phone(field.data)
        # Step 2: Validate number format
        if not valid_phone(field.data):
            raise wtforms.ValidationError(_("Invalid phone number (must be in international format with a leading + symbol)"))
        # Step 3: Check if Indian number (startswith('+91'))
        if not field.data.startswith('+91') or len(field.data) != 13:
            raise wtforms.ValidationError(_("Only Indian mobile numbers are allowed at this time"))


class VerifyPhoneForm(Form):
    verification_code = wtforms.TextField(__("Verification code"), validators=[wtforms.validators.Required()])

    def validate_verification_code(self, field):
        if self.phoneclaim.verification_code != field.data:
            raise wtforms.ValidationError(_("Verification code does not match"))
