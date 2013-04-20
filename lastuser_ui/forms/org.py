# -*- coding: utf-8 -*-

from flask import current_app
import flask.ext.wtf as wtf
from coaster import valid_username
from baseframe.forms import Form

from lastuser_core.models import User, Organization, USER_STATUS


class OrganizationForm(Form):
    title = wtf.TextField('Organization name', validators=[wtf.Required()])
    name = wtf.TextField('URL name', validators=[wtf.Required()])
    description = wtf.TextAreaField('Description')

    def validate_name(self, field):
        if not valid_username(field.data):
            raise wtf.ValidationError("Invalid characters in name")
        if field.data in current_app.config['RESERVED_USERNAMES']:
            raise wtf.ValidationError("That name is reserved")
        existing = User.query.filter_by(username=field.data).first()
        if existing is not None:
            raise wtf.ValidationError("That name is taken")
        existing = Organization.query.filter_by(name=field.data).first()
        if existing is not None and existing.id != self.edit_id:
            raise wtf.ValidationError("That name is taken")


# FIXME: This will have too many users in production. Use some form of lookup instead
def sorted_users():
    return User.query.filter_by(status=USER_STATUS.ACTIVE).order_by('fullname')


class TeamForm(Form):
    title = wtf.TextField('Team name', validators=[wtf.Required()])
    users = wtf.QuerySelectMultipleField('Users', validators=[wtf.Required()],
        query_factory=sorted_users, get_label='pickername',
        description=u"Select users who are part of this team")
