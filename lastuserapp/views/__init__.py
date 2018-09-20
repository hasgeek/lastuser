# -*- coding: utf-8 -*-

# Handle top-level views for url routing

from flask import url_for
from .. import app
from lastuser_core.models import User
import lastuser_oauth.views
import lastuser_ui.views


# These endpoints are replicated here so that Baseframe's routing does not choke

# Monkeypatch these methods into the User model
def profile_url(self):
    """
    Link to the user's profile.
    """
    return url_for('lastuser_ui.account')


def organization_links(self):
    """
    Links to organizations owned by this user.
    """
    return []
    return [{
        'link': url_for('lastuser_ui.org_info', name=org.name),
        'title': org.title} for org in self.organizations_owned()]


User.profile_url = property(profile_url)
User.organization_links = organization_links


@app.route('/profile')
def profile():
    return lastuser_ui.views.profile.profile()


@app.route('/account')
def account():
    return lastuser_ui.views.profile.account()


@app.route('/login')
def login():
    return lastuser_oauth.views.login.login()


@app.route('/logout')
def logout():
    return lastuser_oauth.views.login.logout()


@app.route('/')
def index():
    return lastuser_ui.views.index.index()
