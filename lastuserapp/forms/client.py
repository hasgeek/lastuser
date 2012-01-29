# -*- coding: utf-8 -*-
from flask import g
import flask.ext.wtf as wtf

from lastuserapp.models import Permission, Resource, ResourceAction, getuser
from lastuserapp.utils import valid_username


class AuthorizeForm(wtf.Form):
    """
    OAuth authorization form. Has no fields and is only used for CSRF protection.
    """
    pass


class ConfirmDeleteForm(wtf.Form):
    """
    Confirm a delete operation
    """
    delete = wtf.SubmitField('Delete')
    cancel = wtf.SubmitField('Cancel')


class RegisterClientForm(wtf.Form):
    """
    Register a new OAuth client application
    """
    title = wtf.TextField('Application title', validators=[wtf.Required()],
        description="The name of your application")
    description = wtf.TextAreaField('Description', validators=[wtf.Required()],
        description="A description to help users recognize your application")
    owner = wtf.TextField('Organization name', validators=[wtf.Required()],
        description="Name of the organization or individual who owns this application")
    website = wtf.html5.URLField('Application website', validators=[wtf.Required(), wtf.URL()],
        description="Website where users may access this application")
    redirect_uri = wtf.html5.URLField('Redirect URI', validators=[wtf.Optional(), wtf.URL()],
        description="OAuth2 Redirect URI")
    notification_uri = wtf.html5.URLField('Notification URI', validators=[wtf.Optional(), wtf.URL()],
        description="LastUser resource provider Notification URI. When another application requests access to "
            "resources provided by this app, LastUser will post a notice to this URI with a copy of the access "
            "token that was provided to the other application. Other notices may be posted too.")
    resource_uri = wtf.html5.URLField('Resource URI', validators=[wtf.Optional(), wtf.URL()],
        description="URI at which this application provides resources as per the LastUser Resource API")
    allow_any_login = wtf.BooleanField('Allow anyone to login', default=True,
        description="If your application requires access to be restricted to specific users, uncheck this")


class PermissionForm(wtf.Form):
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

    def validate_name(self, field):
        if not valid_username(field.data):
            raise wtf.ValidationError("Name contains invalid characters.")

        edit_id = getattr(self, 'edit_id', None)

        existing = Permission.query.filter_by(name=field.data, allusers=True).first()
        if existing and existing.id != edit_id:
            raise wtf.ValidationError("A global permission with that name already exists")

        existing = Permission.query.filter_by(name=field.data, user=g.user).first()
        if existing and existing.id != edit_id:
            raise wtf.ValidationError("You have another permission with the same name")


class UserPermissionAssignForm(wtf.Form):
    """
    Assign permissions to a user
    """
    username = wtf.TextField("User", validators=[wtf.Required()],
        description = 'Lookup a user by their username or email address')
    perms = wtf.SelectMultipleField("Permissions", validators=[wtf.Required()])

    def validate_username(self, field):
        existing = getuser(field.data)
        if existing is None:
            raise wtf.ValidationError, "User does not exist"
        self.user = existing


class UserPermissionEditForm(wtf.Form):
    """
    Edit a user's permissions
    """
    perms = wtf.SelectMultipleField("Permissions", validators=[wtf.Required()])


class ResourceForm(wtf.Form):
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

        existing = Resource.query.filter_by(name=field.data).first()
        if existing and existing.id != self.edit_id:
            raise wtf.ValidationError("A resource with that name already exists")

class ResourceActionForm(wtf.Form):
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
