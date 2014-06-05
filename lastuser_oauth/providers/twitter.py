# -*- coding: utf-8 -*-

from functools import wraps
from tweepy import TweepError, OAuthHandler as TwitterOAuthHandler, API as TwitterAPI
from httplib import BadStatusLine
from ssl import SSLError
from socket import error as socket_error, gaierror
from flask.ext.oauth import OAuth, OAuthException  # OAuth 1.0a
from lastuser_core.registry import LoginProvider, LoginInitError, LoginCallbackError

__all__ = ['TwitterProvider']


def twitter_exception_handler(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except (OAuthException, BadStatusLine, AttributeError, socket_error, gaierror) as e:
            raise LoginCallbackError(e)
    return decorated_function


class TwitterProvider(LoginProvider):
    def __init__(self, name, title, key, secret, access_key, access_secret, at_login=True, priority=True):
        self.name = name
        self.title = title
        self.at_login = at_login
        self.priority = priority
        self.consumer_key = key
        self.consumer_secret = secret
        self.access_key = access_key
        self.access_secret = access_secret
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
        except (OAuthException, BadStatusLine, SSLError, gaierror), e:
            raise LoginInitError(e)

    def unwrapped_callback(self, resp):
        if resp is None:
            raise LoginCallbackError("You denied the request to login")

        # Try to read more from the user's Twitter profile
        auth = TwitterOAuthHandler(self.consumer_key, self.consumer_secret)
        if self.access_key is not None and self.access_secret is not None:
            auth.set_access_token(self.access_key, self.access_secret)
        else:
            auth.set_access_token(resp['oauth_token'], resp['oauth_token_secret'])
        api = TwitterAPI(auth)
        try:
            twinfo = api.lookup_users(user_ids=[resp['user_id']])[0]
            fullname = twinfo.name
            avatar_url = twinfo.profile_image_url_https.replace("_normal.", "_bigger.")
        except TweepError:
            fullname = None
            avatar_url = None

        return {'userid': resp['user_id'],
                'username': resp['screen_name'],
                'fullname': fullname,
                'avatar_url': avatar_url,
                'oauth_token': resp['oauth_token'],
                'oauth_token_secret': resp['oauth_token_secret'],
                'oauth_token_type': None,  # Twitter doesn't have token types
                }
