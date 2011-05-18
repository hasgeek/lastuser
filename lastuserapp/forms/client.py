# -*- coding: utf-8 -*-
import flaskext.wtf as wtf


class AuthorizeForm(wtf.Form):
    """
    OAuth authorization form. Has no fields and is only used for CSRF protection.
    """
    pass


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
    redirect_uri = wtf.html5.URLField('Redirect URI', validators=[wtf.Required(), wtf.URL()],
        description="OAuth2 Redirect URI")
    service_uri = wtf.html5.URLField('Service URI (optional)', validators=[wtf.Optional(), wtf.URL()],
        description="LastUser resource provider Service URI")
    allow_any_login = wtf.BooleanField('Allow anyone to login', default=True,
        description="If your application requires access to be restricted to specific users, uncheck this")
