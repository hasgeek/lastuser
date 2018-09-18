# -*- coding: utf-8 -*-

from functools import wraps
from tweepy import TweepError, OAuthHandler as TwitterOAuthHandler, API as TwitterAPI
from httplib import BadStatusLine
from ssl import SSLError
from socket import error as socket_error, gaierror
from flask_oauth import OAuth, OAuthException  # OAuth 1.0a
from baseframe import _
from lastuser_core.registry import LoginProvider, LoginInitError, LoginCallbackError

__all__ = ['TwitterProvider']


def twitter_exception_handler(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except (OAuthException, BadStatusLine, AttributeError, socket_error, gaierror) as e:
            raise LoginCallbackError(e)
        except KeyError:
            # XXX: Twitter sometimes returns a 404 with no Content-Type header. This causes a
            # KeyError in the Flask-OAuth library. Catching the KeyError here is a kludge.
            # We need to get Flask-OAuth fixed or stop using it.
            raise LoginCallbackError(_("Twitter had an intermittent error. Please try again"))
    return decorated_function


class TwitterProvider(LoginProvider):
    at_username = True

    def __init__(self, name, title, key, secret, access_key, access_secret, at_login=True, priority=True, icon=None):
        self.name = name
        self.title = title
        self.at_login = at_login
        self.priority = priority
        self.icon = icon
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
        except (OAuthException, BadStatusLine, SSLError, socket_error, gaierror), e:
            raise LoginInitError(e)
        except KeyError:
            # As above, the lack of a Content-Type header in a 404 response breaks Flask-OAuth. Catch it.
            raise LoginInitError(_("Twitter had an intermittent error. Please try again"))

    def unwrapped_callback(self, resp):
        if resp is None:
            raise LoginCallbackError(_("You denied the request to login"))

        # Try to read more from the user's Twitter profile
        auth = TwitterOAuthHandler(self.consumer_key, self.consumer_secret)
        auth.set_access_token(resp['oauth_token'], resp['oauth_token_secret'])
        api = TwitterAPI(auth)
        try:
            twinfo = api.verify_credentials(include_entities='false', skip_status='true', include_email='true')
            fullname = twinfo.name
            avatar_url = twinfo.profile_image_url_https.replace('_normal.', '_bigger.')
            email = getattr(twinfo, 'email', None)
        except TweepError:
            fullname = None
            avatar_url = None
            email = None

        return {'email': email,
                'userid': resp['user_id'],
                'username': resp['screen_name'],
                'fullname': fullname,
                'avatar_url': avatar_url,
                'oauth_token': resp['oauth_token'],
                'oauth_token_secret': resp['oauth_token_secret'],
                'oauth_token_type': None,  # Twitter doesn't have token types
                }
