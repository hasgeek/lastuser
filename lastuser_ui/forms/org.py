# -*- coding: utf-8 -*-

from flask import current_app
import wtforms
from coaster import valid_username
from baseframe.forms import Form, HiddenMultiField

from lastuser_core.models import User, Organization


class OrganizationForm(Form):
    title = wtforms.TextField('Organization name', validators=[wtforms.validators.Required()])
    name = wtforms.TextField('Username', validators=[wtforms.validators.Required()])

    def validate_name(self, field):
        if not valid_username(field.data):
            raise wtforms.ValidationError("Invalid characters in name")
        if field.data in current_app.config['RESERVED_USERNAMES']:
            raise wtforms.ValidationError("That name is reserved")
        existing = User.get(username=field.data)
        if existing is not None:
            raise wtforms.ValidationError("That name is taken")
        existing = Organization.get(name=field.data)
        if existing is not None and existing.id != self.edit_id:
            raise wtforms.ValidationError("That name is taken")


class TeamForm(Form):
    title = wtforms.TextField('Team name', validators=[wtforms.validators.Required()])
    users = HiddenMultiField('Users', validators=[wtforms.validators.Required()])
