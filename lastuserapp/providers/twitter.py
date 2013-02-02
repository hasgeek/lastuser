# -*- coding: utf-8 -*-

from functools import wraps
from httplib import BadStatusLine
from flask import redirect, url_for, flash, g
from flask.ext.oauth import OAuth, OAuthException  # OAuth 1.0a
from coaster.views import get_next_url
from lastuserapp.models import UserExternalId
from lastuserapp.registry import LoginProvider


def twitter_exception_handler(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except (OAuthException, BadStatusLine, AttributeError), e:
            flash("Twitter login failed: %s" % unicode(e), category="error")
            return redirect(url_for('login'))
    return decorated_function


class TwitterProvider(LoginProvider):
    def __init__(self, name, key, secret):
        self.name = name
        oauth = OAuth()
        twitter = oauth.remote_app('twitter',
            base_url='https://api.twitter.com/1/',
            request_token_url='https://api.twitter.com/oauth/request_token',
            access_token_url='https://api.twitter.com/oauth/access_token',
            authorize_url='https://api.twitter.com/oauth/authenticate',
            consumer_key=key,
            consumer_secret=secret,
            )

        # This is never called since we only use Twitter as a login provider
        @twitter.tokengetter
        def get_twitter_token():
            if g.user:
                extid = UserExternalId.query.filter_by(user=g.user, service=self.name).first()
                if extid:
                    return (extid.oauth_token, extid.oauth_token_secret)
            return None

        self.callback = twitter.authorized_handler(self.callback)
        self.twitter = twitter

    def do(self, **kwargs):
        next_url = get_next_url(referrer=False, default=None)
        try:
            return self.twitter.authorize(callback=url_for('login_service',
                service=self.name, next=next_url))
        except (OAuthException, BadStatusLine), e:
            flash("Twitter login failed: %s" % unicode(e), category="error")
            return redirect(next_url or get_next_url(referrer=True))

    def unwrapped_callback(self, **kwargs):
        pass
