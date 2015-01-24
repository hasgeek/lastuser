# -*- coding: utf-8 -*-

from flask import g, current_app, Markup, url_for
import wtforms
from coaster.utils import valid_username
from baseframe import _, __
from baseframe.forms import Form, HiddenMultiField, AnnotatedTextField

from lastuser_core.models import User, Organization

__all__ = ['OrganizationForm', 'TeamForm']


class OrganizationForm(Form):
    title = wtforms.TextField(__("Organization name"), validators=[wtforms.validators.Required()])
    name = AnnotatedTextField(__("Username"), validators=[wtforms.validators.Required()],
        prefix=u"https://hasgeek.com/…")
    domain = wtforms.RadioField(__("Domain"),
        description=__(u"Users with an email address at this domain will automatically become members of this organization"),
        validators=[wtforms.validators.Optional()])

    def validate_name(self, field):
        if not valid_username(field.data):
            raise wtforms.ValidationError(_("Invalid characters in name"))
        if field.data in current_app.config['RESERVED_USERNAMES']:
            raise wtforms.ValidationError(_("This name is reserved"))
        existing = User.get(username=field.data)
        if existing is not None:
            if existing == g.user:
                raise wtforms.ValidationError(Markup(_(u"This is <em>your</em> current username. "
                    u'You must change it first from <a href="{profile}">your profile</a> '
                    u"before you can assign it to an organization").format(
                        profile=url_for('profile'))))
            else:
                raise wtforms.ValidationError(_("This name is taken"))
        existing = Organization.get(name=field.data)
        if existing is not None and existing.id != self.edit_id:
            raise wtforms.ValidationError(_("This name is taken"))


class TeamForm(Form):
    title = wtforms.TextField(__("Team name"), validators=[wtforms.validators.Required()])
    users = HiddenMultiField(__("Users"), validators=[wtforms.validators.Required()])
