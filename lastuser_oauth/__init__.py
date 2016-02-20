# -*- coding: utf-8 -*-

from itsdangerous import JSONWebSignatureSerializer
from flask import Blueprint
from flask.ext.assets import Bundle


class LastuserOAuthBlueprint(Blueprint):
    def init_app(self, app):
        self.serializer = JSONWebSignatureSerializer(
            app.config.get('LASTUSER_SECRET_KEY') or app.config['SECRET_KEY'])


lastuser_oauth = LastuserOAuthBlueprint('lastuser_oauth', __name__,
    static_folder='static',
    static_url_path='/static/oauth',
    template_folder='templates')


lastuser_oauth_js = Bundle('lastuser_oauth/js/app.js')
lastuser_oauth_css = Bundle('lastuser_oauth/css/app.css')

from . import forms, views  # NOQA
