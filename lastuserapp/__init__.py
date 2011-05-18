# -*- coding: utf-8 -*-

__version__ = '0.1'

from flask import Flask, Markup
from markdown import markdown


__MESSAGES = ['MESSAGE_FOOTER']

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
