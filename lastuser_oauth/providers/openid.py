# -*- coding: utf-8 -*-

from __future__ import absolute_import

from flask import Markup, session
import wtforms
import wtforms.fields.html5
from baseframe.forms import Form
from lastuser_core.registry import LoginProvider
from ..views.login import oid
from ..views.account import login_service_postcallback

__all__ = ['OpenIdProvider']


class OpenIdForm(Form):
    openid = wtforms.fields.html5.URLField('Login with OpenID', validators=[wtforms.validators.Required()], default='http://',
        description=Markup("Don't forget the <code>http://</code> or <code>https://</code> prefix"))


class OpenIdProvider(LoginProvider):
    form = OpenIdForm

    def __init__(self, name, title, key=None, secret=None, at_login=True, priority=False):
        self.name = name
        self.title = title
        self.at_login = at_login
        self.priority = priority

    def get_form(self):
        return {
            'error': oid.fetch_error(),
            'next': oid.get_next_url(),
            'form': self.form() if self.form else None
            }

    def do(self, callback_url=None, form=None):
        if form and form.validate_on_submit():
            session['openid_service'] = self.name
            return oid.try_login(form.openid.data,
                ask_for=['email', 'fullname', 'nickname'])


@oid.after_login
def login_openid_success(resp):
    """
    Called when OpenID login succeeds
    """
    openid = resp.identity_url
    if (openid.startswith('https://profiles.google.com/') or
            openid.startswith('https://www.google.com/accounts/o8/id?id=')):
        service = 'google'
    else:
        service = 'openid'

    response = {
        'userid': openid,
        'username': None,
        'fullname': getattr(resp, 'fullname', None),
        'oauth_token': None,
        'oauth_token_secret': None,
        'oauth_token_type': None,
    }
    if resp.email:
        if service == 'google':
            # Google id. Trust the email address.
            response['email'] = resp.email
        else:
            # Not Google. Treat it as a claim.
            response['emailclaim'] = resp.email
    # Set username for Google ids
    if openid.startswith('https://profiles.google.com/'):
        # Use profile name as username
        parts = openid.split('/')
        while not parts[-1]:
            parts.pop(-1)
        response['username'] = parts[-1]
    elif openid.startswith('https://www.google.com/accounts/o8/id?id='):
        # Use email address as username
        response['username'] = resp.email

    return login_service_postcallback(session.pop('openid_service', service), response)
