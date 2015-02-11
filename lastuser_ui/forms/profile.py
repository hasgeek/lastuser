# -*- coding: utf-8 -*-

from flask import g
import wtforms
import wtforms.fields.html5
from coaster.utils import nullunicode
from baseframe import _, __
import baseframe.forms as forms

from lastuser_core.utils import strip_phone, valid_phone
from lastuser_core.models import UserEmail, UserEmailClaim, UserPhone, UserPhoneClaim

__all__ = ['NewEmailAddressForm', 'NewPhoneForm', 'VerifyPhoneForm']


class NewEmailAddressForm(forms.Form):
    email = forms.EmailField(__("Email address"), validators=[wtforms.validators.DataRequired(), forms.ValidEmail()])
    type = forms.RadioField(__("Type"), coerce=nullunicode, validators=[wtforms.validators.Optional()], choices=[
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


class NewPhoneForm(forms.Form):
    phone = forms.StringField(__("Phone number"), default='+91',
        validators=[wtforms.validators.DataRequired()],
        description=__("In international calling format starting with '+' and country code. Mobile numbers only at this time"))
    type = forms.RadioField(__("Type"), coerce=nullunicode, validators=[wtforms.validators.Optional()], choices=[
        (__(u"Mobile"), __(u"Mobile")),
        # (__(u"Home"), __(u"Home")),
        # (__(u"Work"), __(u"Work")),
        (__(u"Other"), __(u"Other"))])

    def validate_phone(self, field):
        # Step 1: Remove punctuation in number
        number = strip_phone(field.data)
        # Step 2: Check length
        if len(number) > 16:
            raise wtforms.ValidationError(_("This is too long to be a valid phone number"))
        # Step 3: Validate number format
        if not valid_phone(number):
            raise wtforms.ValidationError(_("Invalid phone number (must be in international format with a leading + symbol)"))
        # Step 4: Check if Indian number (startswith('+91'))
        if number.startswith('+91') and len(number) != 13:
            raise wtforms.ValidationError(_("This does not appear to be a valid Indian mobile number"))
        # Step 5: Check if number has already been claimed
        existing = UserPhone.get(phone=number)
        if existing is not None:
            if existing.user == g.user:
                raise wtforms.ValidationError(_("You have already registered this phone number"))
            else:
                raise wtforms.ValidationError(_("This phone number has already been claimed"))
        existing = UserPhoneClaim.get(phone=number, user=g.user)
        if existing is not None:
            raise wtforms.ValidationError(_("This phone number is pending verification"))
        field.data = number  # Save stripped number


class VerifyPhoneForm(forms.Form):
    verification_code = forms.StringField(__("Verification code"), validators=[wtforms.validators.DataRequired()])

    def validate_verification_code(self, field):
        # self.phoneclaim is set by the view before calling form.validate()
        if self.phoneclaim.verification_code != field.data:
            raise wtforms.ValidationError(_("Verification code does not match"))
