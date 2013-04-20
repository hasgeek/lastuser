# -*- coding: utf-8 -*-

from urllib import quote
import requests
from flask import redirect, request
from lastuser_core.registry import LoginProvider, LoginCallbackError
from lastuser_core.utils import get_gravatar_md5sum

__all__ = ['GitHubProvider']


class GitHubProvider(LoginProvider):
    auth_url = "https://github.com/login/oauth/authorize?client_id=%s&redirect_uri=%s"
    token_url = "https://github.com/login/oauth/access_token"
    user_info = "https://api.github.com/user"

    def __init__(self, name, title, key, secret, at_login=True, priority=False):
        self.name = name
        self.title = title
        self.at_login = at_login
        self.priority = priority

        self.key = key
        self.secret = secret

    def do(self, callback_url):
        print callback_url
        return redirect(self.auth_url % (self.key, quote(callback_url)))

    def callback(self):
        if request.args.get('error'):
            if request.args['error'] == 'user_denied':
                raise LoginCallbackError(u"You denied the GitHub login request")
            elif request.args['error'] == 'redirect_uri_mismatch':
                # TODO: Log this as an exception for the server admin to look at
                raise LoginCallbackError(u"This server's callback URL is misconfigured")
            else:
                raise LoginCallbackError(u"Unknown failure")
        code = request.args.get('code', None)
        response = requests.post(self.token_url, headers={'Accept': 'application/json'},
            params={
                'client_id': self.key,
                'client_secret': self.secret,
                'code': code
                }
            ).json()
        if 'error' in response:
            raise LoginCallbackError(response['error'])
        ghinfo = requests.get(self.user_info, params={'access_token': response['access_token']}).json()
        md5sum = get_gravatar_md5sum(ghinfo['avatar_url'])
        return {'email_md5sum': md5sum,
                'userid': ghinfo['login'],
                'username': ghinfo['login'],
                'fullname': ghinfo.get('name'),
                'avatar_url': ghinfo.get('avatar_url'),
                'oauth_token': response['access_token'],
                'oauth_token_secret': None,  # OAuth 2 doesn't need token secrets
                'oauth_token_type': response['token_type']
                }
