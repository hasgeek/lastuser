# -*- coding: utf-8 -*-

from flask import Blueprint
from flask.ext.assets import Bundle


lastuser_oauth = Blueprint('lastuser_oauth', __name__,
    static_folder='static',
    static_url_path='/static/oauth',
    template_folder='templates')


lastuser_oauth_js = Bundle('lastuser_oauth/js/app.js')
lastuser_oauth_css = Bundle('lastuser_oauth/css/app.css')

from . import forms, views
