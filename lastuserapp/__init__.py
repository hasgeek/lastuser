# -*- coding: utf-8 -*-

from flask import Flask
from flask_migrate import Migrate

from baseframe import Version, assets, baseframe
import coaster.app

from ._version import __version__

import lastuser_core  # isort:skip
import lastuser_oauth  # isort:skip
import lastuser_ui  # isort:skip
from lastuser_core import login_registry  # isort:skip
from lastuser_core.models import db  # isort:skip
from lastuser_oauth import providers, rq  # isort:skip

version = Version(__version__)
app = Flask(__name__, instance_relative_config=True)

app.register_blueprint(lastuser_core.lastuser_core)
app.register_blueprint(lastuser_oauth.lastuser_oauth)
app.register_blueprint(lastuser_ui.lastuser_ui)

from . import views  # NOQA  # isort:skip

assets['lastuser-oauth.js'][version] = (lastuser_oauth.lastuser_oauth_js,)
assets['lastuser-oauth.css'][version] = lastuser_oauth.lastuser_oauth_css

# Configure the app
coaster.app.init_app(app)
db.init_app(app)
db.app = app  # To make it work without an app context
migrate = Migrate(app, db)
rq.init_app(app)  # Pick up RQ configuration from the app
baseframe.init_app(
    app,
    requires=['lastuser-oauth'],
    ext_requires=['baseframe-mui', 'jquery.cookie', 'timezone'],
    theme='mui',
)

lastuser_oauth.lastuser_oauth.init_app(app)
lastuser_oauth.mailclient.mail.init_app(app)
lastuser_oauth.views.login.oid.init_app(app)

# Register some login providers
if app.config.get('OAUTH_TWITTER_KEY') and app.config.get('OAUTH_TWITTER_SECRET'):
    login_registry['twitter'] = providers.TwitterProvider(
        'twitter',
        'Twitter',
        at_login=True,
        priority=True,
        icon='twitter',
        key=app.config['OAUTH_TWITTER_KEY'],
        secret=app.config['OAUTH_TWITTER_SECRET'],
        access_key=app.config.get('OAUTH_TWITTER_ACCESS_KEY'),
        access_secret=app.config.get('OAUTH_TWITTER_ACCESS_SECRET'),
    )
if app.config.get('OAUTH_GOOGLE_KEY') and app.config.get('OAUTH_GOOGLE_SECRET'):
    login_registry['google'] = providers.GoogleProvider(
        'google',
        'Google',
        client_id=app.config['OAUTH_GOOGLE_KEY'],
        secret=app.config['OAUTH_GOOGLE_SECRET'],
        scope=app.config.get('OAUTH_GOOGLE_SCOPE', ['email', 'profile']),
        at_login=True,
        priority=True,
        icon='google',
    )
if app.config.get('OAUTH_LINKEDIN_KEY') and app.config.get('OAUTH_LINKEDIN_SECRET'):
    login_registry['linkedin'] = providers.LinkedInProvider(
        'linkedin',
        'LinkedIn',
        at_login=True,
        priority=False,
        icon='linkedin',
        key=app.config['OAUTH_LINKEDIN_KEY'],
        secret=app.config['OAUTH_LINKEDIN_SECRET'],
    )
if app.config.get('OAUTH_GITHUB_KEY') and app.config.get('OAUTH_GITHUB_SECRET'):
    login_registry['github'] = providers.GitHubProvider(
        'github',
        'GitHub',
        at_login=True,
        priority=False,
        icon='github',
        key=app.config['OAUTH_GITHUB_KEY'],
        secret=app.config['OAUTH_GITHUB_SECRET'],
    )
