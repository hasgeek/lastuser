# -*- coding: utf-8 -*-

from flask import g, current_app
import wtforms
import wtforms.fields.html5
from coaster import valid_username, sorted_timezones
from baseframe.forms import Form, ValidEmailDomain

from lastuser_core.models import User, UserEmail, Organization, getuser

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
        if user is None or user != self.user:
            raise wtforms.ValidationError(
                "This username or email does not match the user the reset code is for")


class PasswordChangeForm(Form):
    old_password = wtforms.PasswordField('Current password', validators=[wtforms.validators.Required()])
    password = wtforms.PasswordField('New password', validators=[wtforms.validators.Required()])
    confirm_password = wtforms.PasswordField('Confirm password',
                          validators=[wtforms.validators.Required(), wtforms.validators.EqualTo('password')])

    def validate_old_password(self, field):
        if g.user is None:
            raise wtforms.ValidationError, "Not logged in"
        if not g.user.password_is(field.data):
            raise wtforms.ValidationError, "Incorrect password"


class ProfileForm(Form):
    fullname = wtforms.TextField('Full name', validators=[wtforms.validators.Required()])
    email = wtforms.fields.html5.EmailField('Email address',
        validators=[wtforms.validators.Required(), wtforms.validators.Email(), ValidEmailDomain()])
    username = wtforms.TextField('Username', validators=[wtforms.validators.Required()])
    description = wtforms.TextAreaField('Bio')
    timezone = wtforms.SelectField('Timezone', validators=[wtforms.validators.Required()], choices=timezones)

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
            raise wtforms.ValidationError("Usernames can only have alphabets, numbers and dashes (except at the ends)")
        if field.data in current_app.config['RESERVED_USERNAMES']:
            raise wtforms.ValidationError("That name is reserved")
        existing = User.query.filter_by(username=field.data).first()
        if existing is not None and existing.id != self.edit_id:
            raise wtforms.ValidationError("That username is taken by {}".format(existing.fullname))
        existing = Organization.query.filter_by(name=field.data).first()
        if existing is not None:
            raise wtforms.ValidationError("That username is taken by {}".format(existing.title))

    # TODO: Move to function and place before ValidEmailDomain()
    def validate_email(self, field):
        field.data = field.data.lower()  # Convert to lowercase
        existing = UserEmail.query.filter_by(email=field.data).first()
        if existing is not None and existing.user != self.edit_obj:
            raise wtforms.ValidationError("That email address has been claimed by another user.")


class ProfileMergeForm(Form):
    pass
