# -*- coding: utf-8 -*-

from flask import current_app
from coaster.utils import sorted_timezones
from baseframe import _, __
import baseframe.forms as forms

from lastuser_core.models import Name, User, UserEmail, getuser

timezones = sorted_timezones()


class PasswordResetRequestForm(forms.RecaptchaForm):
    username = forms.StringField(__("Username or Email"), validators=[forms.validators.DataRequired()],
        widget_attrs={'autocorrect': 'none', 'autocapitalize': 'none'})

    def validate_username(self, field):
        user = getuser(field.data)
        if user is None:
            raise forms.ValidationError(_("Could not find a user with that id"))
        self.user = user


class PasswordResetForm(forms.RecaptchaForm):
    username = forms.StringField(__("Username or Email"), validators=[forms.validators.DataRequired()],
        description=__("Please reconfirm your username or email address"),
        widget_attrs={'autocorrect': 'none', 'autocapitalize': 'none'})
    password = forms.PasswordField(__("New password"), validators=[forms.validators.DataRequired()])
    confirm_password = forms.PasswordField(__("Confirm password"),
        validators=[forms.validators.DataRequired(), forms.validators.EqualTo('password')])

    def validate_username(self, field):
        user = getuser(field.data)
        if user is None or user != self.edit_user:
            raise forms.ValidationError(
                _("This username or email does not match the user the reset code is for"))


class PasswordChangeForm(forms.Form):
    old_password = forms.PasswordField(__("Current password"), validators=[forms.validators.DataRequired()])
    password = forms.PasswordField(__("New password"), validators=[forms.validators.DataRequired()])
    confirm_password = forms.PasswordField(__("Confirm password"),
        validators=[forms.validators.DataRequired(), forms.validators.EqualTo('password')])

    def validate_old_password(self, field):
        if self.edit_user is None:
            raise forms.ValidationError(_("Not logged in"))
        if not self.edit_user.password_is(field.data):
            raise forms.ValidationError(_("Incorrect password"))


class ProfileForm(forms.Form):
    fullname = forms.StringField(__("Full name"),
        validators=[forms.validators.DataRequired(), forms.validators.Length(max=User.__title_length__)])
    email = forms.EmailField(__("Email address"),
        validators=[forms.validators.DataRequired(), forms.ValidEmail()],
        widget_attrs={'autocorrect': 'none', 'autocapitalize': 'none'})
    username = forms.AnnotatedTextField(__("Username"),
        validators=[forms.validators.DataRequired(), forms.validators.Length(max=Name.__name_length__)],
        filters=[forms.filters.none_if_empty()],
        prefix=u"https://hasgeek.com/",
        widget_attrs={'autocorrect': 'none', 'autocapitalize': 'none'})
    timezone = forms.SelectField(__("Timezone"), validators=[forms.validators.DataRequired()], choices=timezones)

    def validate_username(self, field):
        if field.data.lower() in current_app.config['RESERVED_USERNAMES']:
            raise forms.ValidationError(_("This name is reserved"))  # To be deprecated in favour of one below

        reason = self.edit_obj.validate_name_candidate(field.data)
        if not reason:
            return  # Username is available
        if reason == 'invalid':
            raise forms.ValidationError(_("Usernames can only have alphabets, numbers and dashes (except at the ends)"))
        elif reason == 'reserved':
            raise forms.ValidationError(_("This username is reserved"))
        elif reason in ('user', 'org'):
            raise forms.ValidationError(_("This username has been taken"))
        else:
            raise forms.ValidationError(_("This username is not available"))

    # TODO: Move to function and place before ValidEmail()
    def validate_email(self, field):
        existing = UserEmail.get(email=field.data)
        if existing is not None and existing.user != self.edit_obj:
            raise forms.ValidationError(_("This email address has been claimed by another user"))


class ProfileMergeForm(forms.Form):
    pass
