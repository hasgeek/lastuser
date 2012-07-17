# -*- coding: utf-8 -*-

from flask import Flask, Markup
from markdown import markdown


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

app = Flask('lastuserapp')
app.config.from_object('lastuserapp')
try:
    app.config.from_object('lastuserapp.settings')
except ImportError:
    import sys
    print >> sys.stderr, "Please create a settings.py with the necessary settings. See settings-sample.py."
    sys.exit()

for msg in __MESSAGES:
    app.config[msg] = Markup(markdown(app.config.get(msg, '')))


import lastuserapp.assets
import lastuserapp.mailclient
import lastuserapp.models
import lastuserapp.forms
import lastuserapp.views
import lastuserapp.loghandler
