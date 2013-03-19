# -*- coding: utf-8 -*-

from pytz import common_timezones
from flask import g, current_app
import flask.ext.wtf as wtf
from coaster import valid_username
from baseframe.forms import Form

from lastuser_core.models import User, UserEmail, Organization, getuser

timezones = [(tz, tz) for tz in common_timezones]


class PasswordResetRequestForm(Form):
    username = wtf.TextField('Username or Email', validators=[wtf.Required()])

    def validate_username(self, field):
        user = getuser(field.data)
        if user is None:
            raise wtf.ValidationError("Could not find a user with that id")
        self.user = user


class PasswordResetForm(Form):
    username = wtf.TextField('Username or Email', validators=[wtf.Required()],
        description="Please reconfirm your username or email address")
    password = wtf.PasswordField('New password', validators=[wtf.Required()])
    confirm_password = wtf.PasswordField('Confirm password',
                          validators=[wtf.Required(), wtf.EqualTo('password')])

    def validate_username(self, field):
        user = getuser(field.data)
        if user is None or user != self.user:
            raise wtf.ValidationError(
                "This username or email does not match the user the reset code is for")


class PasswordChangeForm(Form):
    old_password = wtf.PasswordField('Current password', validators=[wtf.Required()])
    password = wtf.PasswordField('New password', validators=[wtf.Required()])
    confirm_password = wtf.PasswordField('Confirm password',
                          validators=[wtf.Required(), wtf.EqualTo('password')])

    def validate_old_password(self, field):
        if g.user is None:
            raise wtf.ValidationError, "Not logged in"
        if not g.user.password_is(field.data):
            raise wtf.ValidationError, "Incorrect password"


class ProfileForm(Form):
    fullname = wtf.TextField('Full name', validators=[wtf.Required()])
    email = wtf.html5.EmailField('Email address', validators=[wtf.Required(), wtf.Email()])
    username = wtf.TextField('Username', validators=[wtf.Required()])
    description = wtf.TextAreaField('Bio')
    timezone = wtf.SelectField('Timezone', validators=[wtf.Required()], choices=timezones)

    def __init__(self, *args, **kwargs):
        super(ProfileForm, self).__init__(*args, **kwargs)
        self.existing_email = None

    def validate_username(self, field):
        ## Usernames are now mandatory. This should be commented out:
        # if not field.data:
        #     field.data = None
        #     return
        field.data = field.data.lower()  # Usernames can only be lowercase
        if not valid_username(field.data):
            raise wtf.ValidationError("Usernames can only have alphabets, numbers and dashes (except at the ends)")
        if field.data in current_app.config['RESERVED_USERNAMES']:
            raise wtf.ValidationError("This name is reserved")
        existing = User.query.filter_by(username=field.data).first()
        if existing is not None and existing.id != self.edit_id:
            raise wtf.ValidationError("This username is taken")
        existing = Organization.query.filter_by(name=field.data).first()
        if existing is not None:
            raise wtf.ValidationError("This username is taken")

    def validate_email(self, field):
        field.data = field.data.lower()  # Convert to lowercase
        existing = UserEmail.query.filter_by(email=field.data).first()
        if existing is not None and existing.user != self.edit_obj:
            raise wtf.ValidationError("This email address has been claimed by another user.")


class ProfileMergeForm(Form):
    pass
