# -*- coding: utf-8 -*-

# Handle top-level views for url routing

from lastuserapp import app
import lastuser_oauth.views
import lastuser_ui.views


# These endpoints are replicated here so that Baseframe's routing does not choke

@app.route('/profile')
def profile():
    return lastuser_ui.views.profile.profile()


@app.route('/login')
def login():
    return lastuser_oauth.views.login.login()


@app.route('/logout')
def logout():
    return lastuser_oauth.views.login.logout()


@app.route('/')
def index():
    return lastuser_ui.views.index.index()
