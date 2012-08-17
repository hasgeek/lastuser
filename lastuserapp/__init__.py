# -*- coding: utf-8 -*-

__version__ = '0.1'

from flask import Flask, Markup
from flask.ext.assets import Environment, Bundle
from markdown import markdown
from coaster.app import configure
from baseframe import baseframe, baseframe_js, baseframe_css


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
configure(app, 'LASTUSER_ENV')
app.register_blueprint(baseframe)
assets = Environment(app)

js = Bundle(baseframe_js, 'js/app.js',
    filters='jsmin', output='js/packed.js')

css = Bundle(baseframe_css, 'css/app.css',
    filters='cssmin', output='css/packed.css')

assets.register('js_all', js)
assets.register('css_all', css)

for msg in __MESSAGES:
    app.config[msg] = Markup(markdown(app.config.get(msg, '')))


import lastuserapp.registry
import lastuserapp.mailclient
import lastuserapp.models
import lastuserapp.forms
import lastuserapp.views
