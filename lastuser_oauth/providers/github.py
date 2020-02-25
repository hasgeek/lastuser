# -*- coding: utf-8 -*-

from urllib.parse import quote

from flask import redirect, request

import requests

from baseframe import _
from lastuser_core.registry import LoginCallbackError, LoginProvider

__all__ = ['GitHubProvider']


class GitHubProvider(LoginProvider):
    at_username = True
    auth_url = 'https://github.com/login/oauth/authorize?client_id={client_id}&redirect_uri={redirect_uri}&scope={scope}'
    token_url = 'https://github.com/login/oauth/access_token'
    user_info = 'https://api.github.com/user'
    user_emails = 'https://api.github.com/user/emails'

    def __init__(
        self, name, title, key, secret, at_login=True, priority=False, icon=None
    ):
        self.name = name
        self.title = title
        self.at_login = at_login
        self.priority = priority
        self.icon = icon

        self.key = key
        self.secret = secret

    def do(self, callback_url):
        return redirect(
            self.auth_url.format(
                client_id=self.key, redirect_uri=quote(callback_url), scope='user:email'
            )
        )

    def callback(self):
        if request.args.get('error'):
            if request.args['error'] == 'user_denied':
                raise LoginCallbackError(_("You denied the GitHub login request"))
            elif request.args['error'] == 'redirect_uri_mismatch':
                # TODO: Log this as an exception for the server admin to look at
                raise LoginCallbackError(
                    _("This server's callback URL is misconfigured")
                )
            else:
                raise LoginCallbackError(_("Unknown failure"))
        code = request.args.get('code', None)
        try:
            response = requests.post(
                self.token_url,
                headers={'Accept': 'application/json'},
                params={
                    'client_id': self.key,
                    'client_secret': self.secret,
                    'code': code,
                },
            ).json()
            if 'error' in response:
                raise LoginCallbackError(response['error'])
            ghinfo = requests.get(
                self.user_info,
                headers={
                    "Authorization": "token {token}".format(
                        token=response['access_token']
                    )
                },
            ).json()
            ghemails = requests.get(
                self.user_emails,
                headers={
                    'Accept': 'application/vnd.github.v3+json',
                    "Authorization": "token {token}".format(
                        token=response['access_token']
                    ),
                },
            ).json()
        except requests.ConnectionError as e:
            raise LoginCallbackError(
                _(
                    "GitHub appears to be having temporary issues. Please try again. Internal details: {error}"
                ).format(error=e)
            )

        email = None
        emails = []
        if ghemails and isinstance(ghemails, (list, tuple)):
            for result in ghemails:
                if result.get('verified') and not result['email'].endswith(
                    '@users.noreply.github.com'
                ):
                    emails.append(result['email'])
        if emails:
            email = emails[0]
        return {
            'email': email,
            'emails': emails,
            'userid': ghinfo['login'],
            'username': ghinfo['login'],
            'fullname': ghinfo.get('name'),
            'avatar_url': ghinfo.get('avatar_url'),
            'oauth_token': response['access_token'],
            'oauth_token_secret': None,  # OAuth 2 doesn't need token secrets
            'oauth_token_type': response['token_type'],
        }
