# -*- coding: utf-8 -*-
from flask import g
import flask.ext.wtf as wtf
from baseframe.forms import Form
from coaster import valid_username

from lastuserapp.models import Permission, Resource, ResourceAction, getuser, Organization
from lastuserapp.registry import resource_registry


class AuthorizeForm(Form):
    """
    OAuth authorization form. Has no fields and is only used for CSRF protection.
    """
    pass


class ConfirmDeleteForm(Form):
    """
    Confirm a delete operation
    """
    delete = wtf.SubmitField('Delete')
    cancel = wtf.SubmitField('Cancel')


class RegisterClientForm(Form):
    """
    Register a new OAuth client application
    """
    title = wtf.TextField('Application title', validators=[wtf.Required()],
        description="The name of your application")
    description = wtf.TextAreaField('Description', validators=[wtf.Required()],
        description="A description to help users recognize your application")
    client_owner = wtf.RadioField('Owner', validators=[wtf.Required()],
        description="User or organization that owns this application. Changing the owner "
            "will revoke all currently assigned permissions for this app")
    website = wtf.html5.URLField('Application website', validators=[wtf.Required(), wtf.URL()],
        description="Website where users may access this application")
    redirect_uri = wtf.html5.URLField('Redirect URI', validators=[wtf.Optional(), wtf.URL()],
        description="OAuth2 Redirect URI")
    notification_uri = wtf.html5.URLField('Notification URI', validators=[wtf.Optional(), wtf.URL()],
        description="Lastuser resource provider Notification URI. When another application requests access to "
            "resources provided by this app, Lastuser will post a notice to this URI with a copy of the access "
            "token that was provided to the other application. Other notices may be posted too "
            "(not yet implemented)")
    iframe_uri = wtf.html5.URLField('IFrame URI', validators=[wtf.Optional(), wtf.URL()],
        description="Front-end notifications URL. This is loaded in a hidden iframe to notify the app that the "
            "user updated their profile in some way (not yet implemented)")
    resource_uri = wtf.html5.URLField('Resource URI', validators=[wtf.Optional(), wtf.URL()],
        description="URI at which this application provides resources as per the Lastuser Resource API "
            "(not yet implemented)")
    allow_any_login = wtf.BooleanField('Allow anyone to login', default=True,
        description="If your application requires access to be restricted to specific users, uncheck this, "
            "and only users who have been assigned a permission to the app will be able to login")
    team_access = wtf.BooleanField('Requires access to teams', default=False,
        description="If your application is capable of assigning access permissions to teams, check this. "
            "Organization owners will then able to grant access to teams in their organizations")

    def validate_client_owner(self, field):
        if field.data == g.user.userid:
            self.user = g.user
            self.org = None
        else:
            orgs = [org for org in g.user.organizations_owned() if org.userid == field.data]
            if len(orgs) != 1:
                raise wtf.ValidationError("Invalid owner")
            self.user = None
            self.org = orgs[0]


class PermissionForm(Form):
    """
    Create or edit a permission
    """
    name = wtf.TextField('Permission name', validators=[wtf.Required()],
        description='Name of the permission as a single word in lower case. '
            'This is passed to the application when a user logs in. '
            'Changing the name will not automatically update it everywhere. '
            'You must reassign the permission to users who had it with the old name')
    title = wtf.TextField('Title', validators=[wtf.Required()],
        description='Permission title that is displayed to users')
    description = wtf.TextAreaField('Description',
        description='An optional description of what the permission is for')
    context = wtf.RadioField('Context', validators=[wtf.Required()],
        description='Context where this permission is available')

    def validate(self):
        rv = super(PermissionForm, self).validate()
        if not rv:
            return False

        if not valid_username(self.name.data):
            self.name.errors.append("Name contains invalid characters")
            return False

        existing = Permission.query.filter_by(name=self.name.data, allusers=True).first()
        if existing and existing.id != self.edit_id:
            self.name.errors.append("A global permission with that name already exists")
            return False

        if self.context.data == g.user.userid:
            existing = Permission.query.filter_by(name=self.name.data, user=g.user).first()
        else:
            org = Organization.query.filter_by(userid=self.context.data).first()
            if org:
                existing = Permission.query.filter_by(name=self.name.data, org=org).first()
            else:
                existing = None
        if existing and existing.id != self.edit_id:
            self.name.errors.append("You have another permission with the same name")
            return False

        return True

    def validate_context(self, field):
        if field.data == g.user.userid:
            self.user = g.user
            self.org = None
        else:
            orgs = [org for org in g.user.organizations_owned() if org.userid == field.data]
            if len(orgs) != 1:
                raise wtf.ValidationError("Invalid context")
            self.user = None
            self.org = orgs[0]


class UserPermissionAssignForm(Form):
    """
    Assign permissions to a user
    """
    username = wtf.TextField("User", validators=[wtf.Required()],
        description='Lookup a user by their username or email address')
    perms = wtf.SelectMultipleField("Permissions", validators=[wtf.Required()])

    def validate_username(self, field):
        existing = getuser(field.data)
        if existing is None:
            raise wtf.ValidationError("User does not exist")
        self.user = existing


class TeamPermissionAssignForm(Form):
    """
    Assign permissions to a team
    """
    team_id = wtf.RadioField("Team", validators=[wtf.Required()],
        description='Select a team to assign permissions to')
    perms = wtf.SelectMultipleField("Permissions", validators=[wtf.Required()])

    def validate_team_id(self, field):
        teams = [team for team in self.org.teams if team.userid == field.data]
        if len(teams) != 1:
            raise wtf.ValidationError("Unknown team")
        self.team = teams[0]


class PermissionEditForm(Form):
    """
    Edit a user or team's permissions
    """
    perms = wtf.SelectMultipleField("Permissions", validators=[wtf.Required()])


class ResourceForm(Form):
    """
    Edit a resource provided by an application
    """
    name = wtf.TextField('Resource name', validators=[wtf.Required()],
        description="Name of the resource as a single word in lower case. "
            "This is provided by applications as part of the scope "
            "when requesting access to a user's resources.")
    title = wtf.TextField('Title', validators=[wtf.Required()],
        description='Resource title that is displayed to users')
    description = wtf.TextAreaField('Description',
        description='An optional description of what the resource is')
    siteresource = wtf.BooleanField('Site resource',
        description='Enable if this resource is generic to the site and not owned by specific users')
    trusted = wtf.BooleanField('Trusted applications only',
        description='Enable if access to the resource should be restricted to trusted '
            'applications. You may want to do this for sensitive information like billing data')

    def validate_name(self, field):
        if not valid_username(field.data):
            raise wtf.ValidationError("Name contains invalid characters.")

        if field.data in resource_registry:
            raise wtf.ValidationError("This name is reserved for internal use")

        existing = Resource.query.filter_by(name=field.data).first()
        if existing and existing.id != self.edit_id:
            raise wtf.ValidationError("A resource with that name already exists")


class ResourceActionForm(Form):
    """
    Edit an action associated with a resource
    """
    name = wtf.TextField('Action name', validators=[wtf.Required()],
        description="Name of the action as a single word in lower case. "
            "This is provided by applications as part of the scope in the form "
            "'resource/action' when requesting access to a user's resources. "
            "Read actions are implicit when applications request just 'resource' "
            "in the scope and do not need to be specified as an explicit action.")
    title = wtf.TextField('Title', validators=[wtf.Required()],
        description='Action title that is displayed to users')
    description = wtf.TextAreaField('Description',
        description='An optional description of what the action is')

    def validate_name(self, field):
        if not valid_username(field.data):
            raise wtf.ValidationError("Name contains invalid characters.")

        existing = ResourceAction.query.filter_by(name=field.data, resource=self.edit_resource).first()
        if existing and existing.id != self.edit_id:
            raise wtf.ValidationError("An action with that name already exists for this resource")


class ClientTeamAccessForm(Form):
    """
    Select organizations that the client has access to the teams of
    """
    organizations = wtf.SelectMultipleField('Organizations')
