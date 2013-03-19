# -*- coding: utf-8 -*-

__version__ = '0.1'

from flask import Flask
from flask.ext.assets import Environment, Bundle
from coaster.app import init_app
from baseframe import baseframe, baseframe_js, baseframe_css, cookie_js, timezone_js

import lastuser_core, lastuser_oauth, lastuser_ui
from lastuser_core import login_registry
from lastuser_oauth import providers

app = Flask(__name__, instance_relative_config=True)

app.register_blueprint(baseframe)
app.register_blueprint(lastuser_core.lastuser_core)
app.register_blueprint(lastuser_oauth.lastuser_oauth)
app.register_blueprint(lastuser_ui.lastuser_ui)

import lastuserapp.views

assets = Environment(app)

# FIXME: app.js has moved to lastuser_oauth
js = Bundle(baseframe_js, cookie_js, timezone_js, lastuser_oauth.lastuser_oauth_js,
    filters='jsmin', output='js/packed.js')

# FIXME: CSS has moved to lastuser_oauth
css = Bundle(baseframe_css, lastuser_oauth.lastuser_oauth_css,
    filters='cssmin', output='css/packed.css')

assets.register('js_all', js)
assets.register('css_all', css)


def init_for(env):
    init_app(app, env)
    lastuser_core.models.db.init_app(app)
    lastuser_core.models.db.app = app  # To make it work without an app context
    lastuser_oauth.mailclient.mail.init_app(app)
    lastuser_oauth.views.login.oid.init_app(app)

    # Register some login providers
    if app.config.get('OAUTH_TWITTER_KEY') and app.config.get('OAUTH_TWITTER_SECRET'):
        login_registry['twitter'] = providers.TwitterProvider('twitter', 'Twitter',
            at_login=True, priority=True,
            key=app.config['OAUTH_TWITTER_KEY'],
            secret=app.config['OAUTH_TWITTER_SECRET'])
    login_registry['google'] = providers.GoogleProvider('google', 'Google',
        at_login=True, priority=True)
    if app.config.get('OAUTH_GITHUB_KEY') and app.config.get('OAUTH_GITHUB_SECRET'):
        login_registry['github'] = providers.GitHubProvider('github', 'GitHub',
            at_login=True, priority=False,
            key=app.config['OAUTH_GITHUB_KEY'],
            secret=app.config['OAUTH_GITHUB_SECRET'])
    login_registry['openid'] = providers.OpenIdProvider('openid', 'OpenID',
        at_login=True, priority=False)
