# -*- coding: utf-8 -*-

from baseframe import _, __
from coaster.auth import current_auth
from coaster.utils import nullstr
from lastuser_core.models import UserEmail, UserEmailClaim, UserPhone, UserPhoneClaim
from lastuser_core.utils import strip_phone, valid_phone
import baseframe.forms as forms

__all__ = [
    'EmailPrimaryForm',
    'NewEmailAddressForm',
    'NewPhoneForm',
    'PhonePrimaryForm',
    'VerifyEmailForm',
    'VerifyPhoneForm',
]


class NewEmailAddressForm(forms.RecaptchaForm):
    email = forms.EmailField(
        __("Email address"),
        validators=[forms.validators.DataRequired(), forms.ValidEmail()],
        widget_attrs={'autocorrect': 'none', 'autocapitalize': 'none'},
    )
    type = forms.RadioField(  # NOQA: A003
        __("Type"),
        coerce=nullstr,
        validators=[forms.validators.Optional()],
        choices=[
            (__(u"Home"), __(u"Home")),
            (__(u"Work"), __(u"Work")),
            (__(u"Other"), __(u"Other")),
        ],
    )

    # TODO: Move to function and place before ValidEmail()
    def validate_email(self, field):
        field.data = field.data.lower()  # Convert to lowercase
        existing = UserEmail.get(email=field.data)
        if existing is not None:
            if existing.user == current_auth.user:
                raise forms.ValidationError(
                    _("You have already registered this email address")
                )
            else:
                raise forms.ValidationError(
                    _("This email address has already been claimed")
                )
        existing = UserEmailClaim.get(email=field.data, user=current_auth.user)
        if existing is not None:
            raise forms.ValidationError(_("This email address is pending verification"))


class EmailPrimaryForm(forms.Form):
    email = forms.EmailField(
        __("Email address"),
        validators=[forms.validators.DataRequired(), forms.ValidEmail()],
        widget_attrs={'autocorrect': 'none', 'autocapitalize': 'none'},
    )


class VerifyEmailForm(forms.Form):
    pass


class NewPhoneForm(forms.RecaptchaForm):
    phone = forms.TelField(
        __("Phone number"),
        default='+91',
        validators=[forms.validators.DataRequired()],
        description=__(
            "Mobile numbers only at this time. Please prefix with '+' and country code."
        ),
    )

    # Temporarily removed since we only support mobile numbers at this time. When phone call validation is added,
    # we can ask for other types of numbers:

    # type = forms.RadioField(__("Type"), coerce=nullstr, validators=[forms.validators.Optional()], choices=[
    #     (__(u"Mobile"), __(u"Mobile")),
    #     (__(u"Home"), __(u"Home")),
    #     (__(u"Work"), __(u"Work")),
    #     (__(u"Other"), __(u"Other"))])

    def validate_phone(self, field):
        # TODO: Use the phonenumbers library to validate this

        # Step 1: Remove punctuation in number
        number = strip_phone(field.data)
        # Step 2: Check length
        if len(number) > 16:
            raise forms.ValidationError(
                _("This is too long to be a valid phone number")
            )
        # Step 3: Validate number format
        if not valid_phone(number):
            raise forms.ValidationError(
                _(
                    "Invalid phone number (must be in international format with a leading + symbol)"
                )
            )
        # Step 4: Check if Indian number (startswith('+91'))
        if number.startswith('+91') and len(number) != 13:
            raise forms.ValidationError(
                _("This does not appear to be a valid Indian mobile number")
            )
        # Step 5: Check if number has already been claimed
        existing = UserPhone.get(phone=number)
        if existing is not None:
            if existing.user == current_auth.user:
                raise forms.ValidationError(
                    _("You have already registered this phone number")
                )
            else:
                raise forms.ValidationError(
                    _("This phone number has already been claimed")
                )
        existing = UserPhoneClaim.get(phone=number, user=current_auth.user)
        if existing is not None:
            raise forms.ValidationError(_("This phone number is pending verification"))
        field.data = number  # Save stripped number


class PhonePrimaryForm(forms.Form):
    phone = forms.StringField(
        __("Phone number"),
        validators=[forms.validators.DataRequired()],
        widget_attrs={'autocorrect': 'none', 'autocapitalize': 'none'},
    )


class VerifyPhoneForm(forms.Form):
    verification_code = forms.StringField(
        __("Verification code"),
        validators=[forms.validators.DataRequired()],
        widget_attrs={'pattern': '[0-9]*', 'autocomplete': 'off'},
    )

    def validate_verification_code(self, field):
        # self.phoneclaim is set by the view before calling form.validate()
        if self.phoneclaim.verification_code != field.data:
            raise forms.ValidationError(_("Verification code does not match"))
