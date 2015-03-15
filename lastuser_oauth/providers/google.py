# -*- coding: utf-8 -*-

from __future__ import absolute_import
from functools import wraps
import requests
from urllib import quote
from baseframe import _
from flask import session, redirect, request
from lastuser_core.registry import LoginProvider, LoginCallbackError
from oauth2client import client

__all__ = ['GoogleProvider']


class GoogleProvider(LoginProvider):
    form = None  # Don't need a form for Google
    info_url = "https://www.googleapis.com/oauth2/v2/userinfo"

    def __init__(self, name, title, client_id, **kwargs):
        self.client_id = client_id
        self.secret = kwargs['secret']
        super(GoogleProvider, self).__init__(name, title, **kwargs)

    def flow(self, callback_url):
        return client.OAuth2WebServerFlow(
            client_id=self.client_id,
            client_secret=self.secret,
            scope=['profile', 'email'],
            redirect_uri=callback_url)

    def do(self, callback_url):
        session['google_callback'] = callback_url
        return redirect(self.flow(callback_url).step1_get_authorize_url())

    def callback(self):
        callback_url = session.pop('google_callback')
        if request.args.get('error'):
            if request.args['error'] == 'access_denied':
                raise LoginCallbackError(_(u"You denied the Google login request"))
            else:
                raise LoginCallbackError(_(u"Unknown failure"))
        code = request.args.get('code', None)
        try:
            credentials = self.flow(callback_url).step2_exchange(code)
            response = requests.get(self.info_url, headers={'Authorization': credentials.token_response['token_type'] + ' ' + credentials.access_token}).json()
        except Exception as e:
            raise LoginCallbackError(_(u"Unable to authenticate via Google. Internal details: {error}").format(error=e))
        return {'email': credentials.id_token['email'],
                'userid': credentials.id_token['email'],
                'username': credentials.id_token['email'],
                'fullname': response['name'],
                'avatar_url': response['picture'],
                'oauth_token': credentials.access_token,
                'oauth_token_secret': None,  # OAuth 2 doesn't need token secrets
                'oauth_token_type': credentials.token_response['token_type']
                }

