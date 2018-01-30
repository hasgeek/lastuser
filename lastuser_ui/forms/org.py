# -*- coding: utf-8 -*-

from flask import current_app, Markup, url_for
from coaster.utils import valid_username
from coaster.auth import current_auth
from baseframe import _, __
import baseframe.forms as forms

from lastuser_core.models import User, Organization

__all__ = ['OrganizationForm', 'TeamForm']


class OrganizationForm(forms.Form):
    title = forms.StringField(__("Organization name"), validators=[forms.validators.DataRequired()])
    name = forms.AnnotatedTextField(__("Username"), validators=[forms.validators.DataRequired()],
        prefix=u"https://hasgeek.com/…",
        widget_attrs={'autocorrect': 'none', 'autocapitalize': 'none'})

    def validate_name(self, field):
        if not valid_username(field.data):
            raise forms.ValidationError(_("Invalid characters in name"))
        if field.data in current_app.config['RESERVED_USERNAMES']:
            raise forms.ValidationError(_("This name is reserved"))
        existing = User.get(username=field.data)
        if existing is not None:
            if existing == current_auth.user:
                raise forms.ValidationError(Markup(_(u"This is <em>your</em> current username. "
                    u'You must change it first from <a href="{profile}">your profile</a> '
                    u"before you can assign it to an organization").format(
                        profile=url_for('profile'))))
            else:
                raise forms.ValidationError(_("This name is taken"))
        existing = Organization.get(name=field.data)
        if existing is not None and existing.id != self.edit_id:
            raise forms.ValidationError(_("This name is taken"))


class TeamForm(forms.Form):
    title = forms.StringField(__("Team name"), validators=[forms.validators.DataRequired()])
    users = forms.UserSelectMultiField(__("Users"), validators=[forms.validators.DataRequired()],
        description=__("Lookup a user by their username or email address"),
        lastuser=None, usermodel=User,
        autocomplete_endpoint=lambda: url_for('lastuser_oauth.user_autocomplete'),
        getuser_endpoint=lambda: url_for('lastuser_oauth.user_get_by_userids'))
