# -*- coding: utf-8 -*-

from urlparse import urlparse

import wtforms
import wtforms.fields.html5
from baseframe.forms import Form
from coaster import valid_username

from lastuser_core.models import Permission, Resource, getuser, Organization
from lastuser_core import resource_registry


class ConfirmDeleteForm(Form):
    """
    Confirm a delete operation
    """
    delete = wtforms.SubmitField('Delete')
    cancel = wtforms.SubmitField('Cancel')


class RegisterClientForm(Form):
    """
    Register a new OAuth client application
    """
    title = wtforms.TextField('Application title', validators=[wtforms.validators.Required()],
        description="The name of your application")
    description = wtforms.TextAreaField('Description', validators=[wtforms.validators.Required()],
        description="A description to help users recognize your application")
    client_owner = wtforms.RadioField('Owner', validators=[wtforms.validators.Required()],
        description="User or organization that owns this application. Changing the owner "
            "will revoke all currently assigned permissions for this app")
    website = wtforms.fields.html5.URLField('Application website', validators=[wtforms.validators.Required(), wtforms.validators.URL()],
        description="Website where users may access this application")
    redirect_uri = wtforms.fields.html5.URLField('Redirect URL', validators=[wtforms.validators.Optional(), wtforms.validators.URL()],
        description="OAuth2 Redirect URL")
    notification_uri = wtforms.fields.html5.URLField('Notification URL', validators=[wtforms.validators.Optional(), wtforms.validators.URL()],
        description="When the user's data changes, Lastuser will POST a notice to this URL. "
            "Other notices may be posted too")
    iframe_uri = wtforms.fields.html5.URLField('IFrame URL', validators=[wtforms.validators.Optional(), wtforms.validators.URL()],
        description="Front-end notifications URL. This is loaded in a hidden iframe to notify the app that the "
            "user updated their profile in some way (not yet implemented)")
    resource_uri = wtforms.fields.html5.URLField('Resource URL', validators=[wtforms.validators.Optional(), wtforms.validators.URL()],
        description="URL at which this application provides resources as per the Lastuser Resource API "
            "(not yet implemented)")
    allow_any_login = wtforms.BooleanField('Allow anyone to login', default=True,
        description="If your application requires access to be restricted to specific users, uncheck this, "
            "and only users who have been assigned a permission to the app will be able to login")
    team_access = wtforms.BooleanField('Requires access to teams', default=False,
        description="If your application is capable of assigning access permissions to teams, check this. "
            "Organization owners will then able to grant access to teams in their organizations")

    def validate_client_owner(self, field):
        if field.data == self.edit_user.userid:
            self.user = self.edit_user
            self.org = None
        else:
            orgs = [org for org in self.edit_user.organizations_owned() if org.userid == field.data]
            if len(orgs) != 1:
                raise wtforms.ValidationError("Invalid owner")
            self.user = None
            self.org = orgs[0]

    def _urls_match(self, url1, url2):
        p1 = urlparse(url1)
        p2 = urlparse(url2)
        return (p1.netloc == p2.netloc) and (p1.scheme == p2.scheme) and (
            p1.username == p2.username) and (p1.password == p2.password)

    def validate_redirect_uri(self, field):
        if not self._urls_match(self.website.data, field.data):
            raise wtforms.ValidationError("The scheme, domain and port must match that of the website URL")

    def validate_notification_uri(self, field):
        if not self._urls_match(self.website.data, field.data):
            raise wtforms.ValidationError("The scheme, domain and port must match that of the website URL")

    def validate_resource_uri(self, field):
        if not self._urls_match(self.website.data, field.data):
            raise wtforms.ValidationError("The scheme, domain and port must match that of the website URL")


class PermissionForm(Form):
    """
    Create or edit a permission
    """
    name = wtforms.TextField('Permission name', validators=[wtforms.validators.Required()],
        description='Name of the permission as a single word in lower case. '
            'This is passed to the application when a user logs in. '
            'Changing the name will not automatically update it everywhere. '
            'You must reassign the permission to users who had it with the old name')
    title = wtforms.TextField('Title', validators=[wtforms.validators.Required()],
        description='Permission title that is displayed to users')
    description = wtforms.TextAreaField('Description',
        description='An optional description of what the permission is for')
    context = wtforms.RadioField('Context', validators=[wtforms.validators.Required()],
        description='Context where this permission is available')

    def validate(self):
        rv = super(PermissionForm, self).validate()
        if not rv:
            return False

        if not valid_username(self.name.data):
            self.name.errors.append("Name contains invalid characters")
            return False

        existing = Permission.get(name=self.name.data, allusers=True)
        if existing and existing.id != self.edit_id:
            self.name.errors.append("A global permission with that name already exists")
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
            self.name.errors.append("You have another permission with the same name")
            return False

        return True

    def validate_context(self, field):
        if field.data == self.edit_user.userid:
            self.user = self.edit_user
            self.org = None
        else:
            orgs = [org for org in self.edit_user.organizations_owned() if org.userid == field.data]
            if len(orgs) != 1:
                raise wtforms.ValidationError("Invalid context")
            self.user = None
            self.org = orgs[0]


class UserPermissionAssignForm(Form):
    """
    Assign permissions to a user
    """
    username = wtforms.TextField("User", validators=[wtforms.validators.Required()],
        description='Lookup a user by their username or email address')
    perms = wtforms.SelectMultipleField("Permissions", validators=[wtforms.validators.Required()])

    def validate_username(self, field):
        existing = getuser(field.data)
        if existing is None:
            raise wtforms.ValidationError("User does not exist")
        self.user = existing


class TeamPermissionAssignForm(Form):
    """
    Assign permissions to a team
    """
    team_id = wtforms.RadioField("Team", validators=[wtforms.validators.Required()],
        description='Select a team to assign permissions to')
    perms = wtforms.SelectMultipleField("Permissions", validators=[wtforms.validators.Required()])

    def validate_team_id(self, field):
        teams = [team for team in self.org.teams if team.userid == field.data]
        if len(teams) != 1:
            raise wtforms.ValidationError("Unknown team")
        self.team = teams[0]


class PermissionEditForm(Form):
    """
    Edit a user or team's permissions
    """
    perms = wtforms.SelectMultipleField("Permissions", validators=[wtforms.validators.Required()])


class ResourceForm(Form):
    """
    Edit a resource provided by an application
    """
    name = wtforms.TextField('Resource name', validators=[wtforms.validators.Required()],
        description="Name of the resource as a single word in lower case. "
            "This is provided by applications as part of the scope "
            "when requesting access to a user's resources.")
    title = wtforms.TextField('Title', validators=[wtforms.validators.Required()],
        description='Resource title that is displayed to users')
    description = wtforms.TextAreaField('Description',
        description='An optional description of what the resource is')
    siteresource = wtforms.BooleanField('Site resource',
        description='Enable if this resource is generic to the site and not owned by specific users')
    trusted = wtforms.BooleanField('Trusted applications only',
        description='Enable if access to the resource should be restricted to trusted '
            'applications. You may want to do this for sensitive information like billing data')

    def validate_name(self, field):
        if not valid_username(field.data):
            raise wtforms.ValidationError("Name contains invalid characters.")

        if field.data in resource_registry:
            raise wtforms.ValidationError("This name is reserved for internal use")

        existing = Resource.get(name=field.data)
        if existing and existing.id != self.edit_id:
            raise wtforms.ValidationError("A resource with that name already exists")


class ResourceActionForm(Form):
    """
    Edit an action associated with a resource
    """
    name = wtforms.TextField('Action name', validators=[wtforms.validators.Required()],
        description="Name of the action as a single word in lower case. "
            "This is provided by applications as part of the scope in the form "
            "'resource/action' when requesting access to a user's resources. "
            "Read actions are implicit when applications request just 'resource' "
            "in the scope and do not need to be specified as an explicit action.")
    title = wtforms.TextField('Title', validators=[wtforms.validators.Required()],
        description='Action title that is displayed to users')
    description = wtforms.TextAreaField('Description',
        description='An optional description of what the action is')

    def validate_name(self, field):
        if not valid_username(field.data):
            raise wtforms.ValidationError("Name contains invalid characters.")

        existing = self.edit_resource.get_action(field.data)
        if existing and existing.id != self.edit_id:
            raise wtforms.ValidationError("An action with that name already exists for this resource")


class ClientTeamAccessForm(Form):
    """
    Select organizations that the client has access to the teams of
    """
    organizations = wtforms.SelectMultipleField('Organizations')
