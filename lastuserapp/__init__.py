# -*- coding: utf-8 -*-

__version__ = '0.1'

from os import environ
from flask import Flask, Markup
from flask.ext.assets import Environment, Bundle
from markdown import markdown
from coaster import configureapp
from baseframe import baseframe, networkbar_js, networkbar_css


__MESSAGES = ['MESSAGE_FOOTER']

# These names are unavailable for use as usernames
RESERVED_USERNAMES = set([
    'app',
    'apps',
    'auth',
    'client',
    'confirm',
    'login',
    'logout',
    'new',
    'profile',
    'reset',
    'register',
    'token',
    'organizations',
    ])

app = Flask(__name__, instance_relative_config=True)
configureapp(app, 'LASTUSER_ENV')
app.register_blueprint(baseframe)
assets = Environment(app)

js = Bundle('js/libs/jquery-1.5.1.min.js',
            'js/libs/jquery.form.js',
            'js/scripts.js',
            filters='jsmin', output='js/packed.js')

assets.register('js_all', js)

for msg in __MESSAGES:
    app.config[msg] = Markup(markdown(app.config.get(msg, '')))


import lastuserapp.mailclient
import lastuserapp.models
import lastuserapp.forms
import lastuserapp.views
if environ['LASTUSER_ENV'] == 'production':
    import lastuserapp.loghandler
