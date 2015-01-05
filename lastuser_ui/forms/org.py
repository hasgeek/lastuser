# -*- coding: utf-8 -*-

from flask import g, current_app, Markup, url_for
import wtforms
from coaster.utils import valid_username
from baseframe import _
from baseframe.forms import Form, HiddenMultiField, AnnotatedTextField

from lastuser_core.models import User, Organization


class OrganizationForm(Form):
    title = wtforms.TextField("Organization name", validators=[wtforms.validators.Required()])
    name = AnnotatedTextField("Username", validators=[wtforms.validators.Required()],
        prefix=u"https://hasgeek.com/…")

    def validate_name(self, field):
        if not valid_username(field.data):
            raise wtforms.ValidationError("Invalid characters in name")
        if field.data in current_app.config['RESERVED_USERNAMES']:
            raise wtforms.ValidationError("This name is reserved")
        existing = User.get(username=field.data)
        if existing is not None:
            if existing == g.user:
                raise wtforms.ValidationError(Markup(_(u"This is <em>your</em> current username. "
                    u'You must change it first from <a href="{profile}">your profile</a> '
                    u"before you can assign it to an organization").format(
                        profile=url_for('profile'))))
            else:
                raise wtforms.ValidationError("This name is taken")
        existing = Organization.get(name=field.data)
        if existing is not None and existing.id != self.edit_id:
            raise wtforms.ValidationError("This name is taken")


class TeamForm(Form):
    title = wtforms.TextField("Team name", validators=[wtforms.validators.Required()])
    users = HiddenMultiField("Users", validators=[wtforms.validators.Required()])
