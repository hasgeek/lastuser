# -*- coding: utf-8 -*-

from functools import wraps
import requests
from httplib import BadStatusLine
from flask.ext.oauth import OAuth, OAuthException  # OAuth 1.0a
from lastuser_core.registry import LoginProvider, LoginInitError, LoginCallbackError

__all__ = ['TwitterProvider']


def twitter_exception_handler(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except (OAuthException, BadStatusLine, AttributeError), e:
            raise LoginCallbackError(e)
    return decorated_function


class TwitterProvider(LoginProvider):
    def __init__(self, name, title, key, secret, at_login=True, priority=True):
        self.name = name
        self.title = title
        self.at_login = at_login
        self.priority = priority
        oauth = OAuth()
        twitter = oauth.remote_app('twitter',
            base_url='https://api.twitter.com/1/',
            request_token_url='https://api.twitter.com/oauth/request_token',
            access_token_url='https://api.twitter.com/oauth/access_token',
            authorize_url='https://api.twitter.com/oauth/authenticate',
            consumer_key=key,
            consumer_secret=secret,
            )

        twitter.tokengetter(lambda token=None: None)  # We have no use for tokengetter

        self.callback = twitter_exception_handler(twitter.authorized_handler(self.unwrapped_callback))
        self.twitter = twitter

    def do(self, callback_url):
        try:
            return self.twitter.authorize(callback=callback_url)
        except (OAuthException, BadStatusLine), e:
            raise LoginInitError(e)

    def unwrapped_callback(self, resp):
        if resp is None:
            raise LoginCallbackError("You denied the request to login")

        # Try to read more from the user's Twitter profile
        try:
            twinfo = requests.get('http://api.twitter.com/1/users/lookup.json',
                params={'user_id': resp['user_id']}).json()[0]
        except:  # Ignore all errors since this data is optional and there are many errors requests could raise
            twinfo = {}

        return {'userid': resp['user_id'],
                'username': resp['screen_name'],
                'fullname': twinfo.get('name', '@' + resp['screen_name']),
                'avatar_url': twinfo.get('profile_image_url', '').replace("_normal.", "_bigger."),
                'oauth_token': resp['oauth_token'],
                'oauth_token_secret': resp['oauth_token_secret'],
                'oauth_token_type': None,  # Twitter doesn't have token types
                }
