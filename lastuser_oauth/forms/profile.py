# -*- coding: utf-8 -*-

from flask import current_app
import wtforms
import wtforms.fields.html5
from coaster import valid_username, sorted_timezones
from baseframe.forms import Form, ValidEmail, AnnotatedNullTextField

from lastuser_core.models import UserEmail, getuser

timezones = sorted_timezones()


class PasswordResetRequestForm(Form):
    username = wtforms.TextField('Username or Email', validators=[wtforms.validators.Required()])

    def validate_username(self, field):
        user = getuser(field.data)
        if user is None:
            raise wtforms.ValidationError("Could not find a user with that id")
        self.user = user


class PasswordResetForm(Form):
    username = wtforms.TextField('Username or Email', validators=[wtforms.validators.Required()],
        description="Please reconfirm your username or email address")
    password = wtforms.PasswordField('New password', validators=[wtforms.validators.Required()])
    confirm_password = wtforms.PasswordField('Confirm password',
        validators=[wtforms.validators.Required(), wtforms.validators.EqualTo('password')])

    def validate_username(self, field):
        user = getuser(field.data)
        if user is None or user != self.edit_user:
            raise wtforms.ValidationError(
                "This username or email does not match the user the reset code is for")


class PasswordChangeForm(Form):
    old_password = wtforms.PasswordField('Current password', validators=[wtforms.validators.Required()])
    password = wtforms.PasswordField('New password', validators=[wtforms.validators.Required()])
    confirm_password = wtforms.PasswordField('Confirm password',
        validators=[wtforms.validators.Required(), wtforms.validators.EqualTo('password')])

    def validate_old_password(self, field):
        if self.edit_user is None:
            raise wtforms.ValidationError("Not logged in")
        if not self.edit_user.password_is(field.data):
            raise wtforms.ValidationError("Incorrect password")


class ProfileForm(Form):
    fullname = wtforms.TextField('Full name', validators=[wtforms.validators.Required()])
    email = wtforms.fields.html5.EmailField('Email address',
        validators=[wtforms.validators.Required(), ValidEmail()])
    username = AnnotatedNullTextField('Username', validators=[wtforms.validators.Required()],
        prefix=u"https://hasgeek.com/…")
    timezone = wtforms.SelectField('Timezone', validators=[wtforms.validators.Required()], choices=timezones)

    def validate_username(self, field):
        # # Usernames are now mandatory. This should be commented out:
        # if not field.data:
        #     field.data = None
        #     return
        field.data = field.data.lower()  # Usernames can only be lowercase
        if not valid_username(field.data):
            raise wtforms.ValidationError("Usernames can only have alphabets, numbers and dashes (except at the ends)")
        if field.data in current_app.config.get('RESERVED_USERNAMES', []):
            raise wtforms.ValidationError("This name is reserved")
        if not self.edit_user.is_valid_username(field.data):
            raise wtforms.ValidationError("This username is taken")

    # TODO: Move to function and place before ValidEmail()
    def validate_email(self, field):
        field.data = field.data.lower()  # Convert to lowercase
        existing = UserEmail.get(email=field.data)
        if existing is not None and existing.user != self.edit_obj:
            raise wtforms.ValidationError("This email address has been claimed by another user")


class ProfileMergeForm(Form):
    pass
