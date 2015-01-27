# -*- coding: utf-8 -*-

from urlparse import urlparse

from flask import Markup, url_for
import wtforms
import wtforms.fields.html5
from baseframe import _, __
from baseframe.forms import Form, NullTextField, UserSelectField
from coaster.utils import valid_username, domain_namespace_match

from lastuser_core.models import Permission, Resource, getuser, Organization, User
from lastuser_core import resource_registry

__all__ = ['ConfirmDeleteForm', 'RegisterClientForm', 'ClientCredentialForm', 'PermissionForm',
    'UserPermissionAssignForm', 'TeamPermissionAssignForm', 'PermissionEditForm', 'ResourceForm',
    'ResourceActionForm', 'ClientTeamAccessForm']


class ConfirmDeleteForm(Form):
    """
    Confirm a delete operation
    """
    delete = wtforms.SubmitField(__("Delete"))
    cancel = wtforms.SubmitField(__("Cancel"))


class RegisterClientForm(Form):
    """
    Register a new OAuth client application
    """
    title = wtforms.TextField(__("Application title"),
        validators=[wtforms.validators.Required()],
        description=__("The name of your application"))
    description = wtforms.TextAreaField(__("Description"),
        validators=[wtforms.validators.Required()],
        description=__("A description to help users recognize your application"))
    client_owner = wtforms.RadioField(__("Owner"),
        validators=[wtforms.validators.Required()],
        description=__("User or organization that owns this application. Changing the owner "
        "will revoke all currently assigned permissions for this app"))
    website = wtforms.fields.html5.URLField(__("Application website"),
        validators=[wtforms.validators.Required(), wtforms.validators.URL()],
        description=__("Website where users may access this application"))
    namespace = NullTextField(__("Client namespace"),
        validators=[wtforms.validators.Optional()],
        description=Markup(__(u"A dot-based namespace that uniquely identifies your client application. "
            u"For example, if your client website is <code>https://auth.hasgeek.com</code>, "
            u"use <code>com.hasgeek.auth</code>. Only required if your client app provides resources")))
    redirect_uri = wtforms.fields.html5.URLField(__("Redirect URL"),
        validators=[wtforms.validators.Optional(), wtforms.validators.URL()],
        description=__("OAuth2 Redirect URL"))
    notification_uri = wtforms.fields.html5.URLField(__("Notification URL"),
        validators=[wtforms.validators.Optional(), wtforms.validators.URL()],
        description=__("When the user's data changes, Lastuser will POST a notice to this URL. "
        "Other notices may be posted too"))
    iframe_uri = wtforms.fields.html5.URLField(__("IFrame URL"),
        validators=[wtforms.validators.Optional(), wtforms.validators.URL()],
        description=__("Front-end notifications URL. This is loaded in a hidden iframe to notify the app that the "
        "user updated their profile in some way (not yet implemented)"))
    allow_any_login = wtforms.BooleanField(__("Allow anyone to login"),
        default=True,
        description=__("If your application requires access to be restricted to specific users, uncheck this, "
        "and only users who have been assigned a permission to the app will be able to login"))
    team_access = wtforms.BooleanField(__("Requires access to teams"),
        default=False,
        description=__("If your application is capable of assigning access permissions to teams, check this. "
        "Organization owners will then able to grant access to teams in their organizations"))

    def validate_client_owner(self, field):
        if field.data == self.edit_user.userid:
            self.user = self.edit_user
            self.org = None
        else:
            orgs = [org for org in self.edit_user.organizations_owned() if org.userid == field.data]
            if len(orgs) != 1:
                raise wtforms.ValidationError(_("Invalid owner"))
            self.user = None
            self.org = orgs[0]

    def _urls_match(self, url1, url2):
        p1 = urlparse(url1)
        p2 = urlparse(url2)
        return (p1.netloc == p2.netloc) and (p1.scheme == p2.scheme) and (
            p1.username == p2.username) and (p1.password == p2.password)

    def validate_redirect_uri(self, field):
        if not self._urls_match(self.website.data, field.data):
            raise wtforms.ValidationError(_("The scheme, domain and port must match that of the website URL"))

    def validate_notification_uri(self, field):
        if not self._urls_match(self.website.data, field.data):
            raise wtforms.ValidationError(_("The scheme, domain and port must match that of the website URL"))

    def validate_resource_uri(self, field):
        if not self._urls_match(self.website.data, field.data):
            raise wtforms.ValidationError(_("The scheme, domain and port must match that of the website URL"))

    def validate_namespace(self, field):
        if field.data:
            if not domain_namespace_match(self.website.data, field.data):
                raise wtforms.ValidationError(_(u"The namespace should be derived from your application’s website domain"))
            client = self.edit_model.get(namespace=field.data)
            if client:
                if client == self.edit_obj:
                    return
                raise wtforms.ValidationError(_("This namespace has been claimed by another client app"))


class ClientCredentialForm(Form):
    """
    Generate new client credentials
    """
    title = wtforms.TextField(__(u"What’s this for?"),
        validators=[wtforms.validators.Required(), wtforms.validators.Length(max=250)],
        description=__("Add a description to help yourself remember why this was generated"))


class PermissionForm(Form):
    """
    Create or edit a permission
    """
    name = wtforms.TextField(__("Permission name"), validators=[wtforms.validators.Required()],
        description=__("Name of the permission as a single word in lower case. "
        "This is passed to the application when a user logs in. "
        "Changing the name will not automatically update it everywhere. "
        "You must reassign the permission to users who had it with the old name"))
    title = wtforms.TextField(__("Title"), validators=[wtforms.validators.Required()],
        description=__("Permission title that is displayed to users"))
    description = wtforms.TextAreaField(__("Description"),
        description=__("An optional description of what the permission is for"))
    context = wtforms.RadioField(__("Context"), validators=[wtforms.validators.Required()],
        description=__("Context where this permission is available"))

    def validate(self):
        rv = super(PermissionForm, self).validate()
        if not rv:
            return False

        if not valid_username(self.name.data):
            self.name.errors.append(_("Name contains invalid characters"))
            return False

        existing = Permission.get(name=self.name.data, allusers=True)
        if existing and existing.id != self.edit_id:
            self.name.errors.append(_("A global permission with that name already exists"))
            return False

        if self.context.data == self.edit_user.userid:
            existing = Permission.get(name=self.name.data, user=self.edit_user)
        else:
            org = Organization.get(userid=self.context.data)
            if org:
                existing = Permission.get(name=self.name.data, org=org)
            else:
                existing = None
        if existing and existing.id != self.edit_id:
            self.name.errors.append(_("You have another permission with the same name"))
            return False

        return True

    def validate_context(self, field):
        if field.data == self.edit_user.userid:
            self.user = self.edit_user
            self.org = None
        else:
            orgs = [org for org in self.edit_user.organizations_owned() if org.userid == field.data]
            if len(orgs) != 1:
                raise wtforms.ValidationError(_("Invalid context"))
            self.user = None
            self.org = orgs[0]


class UserPermissionAssignForm(Form):
    """
    Assign permissions to a user
    """
    user = UserSelectField(__("User"), validators=[wtforms.validators.Required()],
        description=__("Lookup a user by their username or email address"),
        lastuser=None, usermodel=User,
        autocomplete_endpoint=lambda: url_for('lastuser_oauth.user_autocomplete'),
        getuser_endpoint=lambda: url_for('lastuser_oauth.user_get_by_userids'))
    perms = wtforms.SelectMultipleField(__("Permissions"), validators=[wtforms.validators.Required()])


class TeamPermissionAssignForm(Form):
    """
    Assign permissions to a team
    """
    team_id = wtforms.RadioField(__("Team"), validators=[wtforms.validators.Required()],
        description=__("Select a team to assign permissions to"))
    perms = wtforms.SelectMultipleField(__("Permissions"), validators=[wtforms.validators.Required()])

    def validate_team_id(self, field):
        teams = [team for team in self.org.teams if team.userid == field.data]
        if len(teams) != 1:
            raise wtforms.ValidationError(_("Unknown team"))
        self.team = teams[0]


class PermissionEditForm(Form):
    """
    Edit a user or team's permissions
    """
    perms = wtforms.SelectMultipleField(__("Permissions"), validators=[wtforms.validators.Required()])


class ResourceForm(Form):
    """
    Edit a resource provided by an application
    """
    name = wtforms.TextField(__("Resource name"), validators=[wtforms.validators.Required()],
        description=__("Name of the resource as a single word in lower case. "
        "This is provided by applications as part of the scope "
        "when requesting access to a user's resources"))
    title = wtforms.TextField(__("Title"), validators=[wtforms.validators.Required()],
        description=__("Resource title that is displayed to users"))
    description = wtforms.TextAreaField(__("Description"),
        description=__("An optional description of what the resource is"))
    siteresource = wtforms.BooleanField(__("Site resource"),
        description=__("Enable if this resource is generic to the site and not owned by specific users"))
    restricted = wtforms.BooleanField(__("Restrict access to your apps"),
        description=__("Enable if access to the resource should be restricted to client apps "
            "that share the same owner. You may want to do this for sensitive resources "
            "that should only be available to your own apps"))

    def validate_name(self, field):
        if not valid_username(field.data):
            raise wtforms.ValidationError(_("Name contains invalid characters"))

        if field.data in resource_registry:
            raise wtforms.ValidationError(_("This name is reserved for internal use"))

        existing = Resource.get(name=field.data, client=self.client)
        if existing and existing.id != self.edit_id:
            raise wtforms.ValidationError(_("A resource with that name already exists"))


class ResourceActionForm(Form):
    """
    Edit an action associated with a resource
    """
    name = wtforms.TextField(__("Action name"), validators=[wtforms.validators.Required()],
        description=__("Name of the action as a single word in lower case. "
        "This is provided by applications as part of the scope in the form "
        "'resource/action' when requesting access to a user's resources. "
        "Read actions are implicit when applications request just 'resource' "
        "in the scope and do not need to be specified as an explicit action"))
    title = wtforms.TextField(__("Title"), validators=[wtforms.validators.Required()],
        description=__("Action title that is displayed to users"))
    description = wtforms.TextAreaField(__("Description"),
        description=__("An optional description of what the action is"))

    def validate_name(self, field):
        if not valid_username(field.data):
            raise wtforms.ValidationError(_("Name contains invalid characters"))

        existing = self.edit_resource.get_action(field.data)
        if existing and existing.id != self.edit_id:
            raise wtforms.ValidationError(_("An action with that name already exists for this resource"))


class ClientTeamAccessForm(Form):
    """
    Select organizations that the client has access to the teams of
    """
    organizations = wtforms.SelectMultipleField(__("Organizations"))
