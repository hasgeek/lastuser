# -*- coding: utf-8 -*-

from __future__ import absolute_import
from functools import wraps
from flask import session
from .openid import oid, OpenIdProvider
from openid.fetchers import HTTPFetchingError
from lastuser_core.registry import LoginCallbackError

__all__ = ['GoogleProvider']


def exception_handler(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except HTTPFetchingError as e:
            raise LoginCallbackError(e)
    return decorated_function


class GoogleProvider(OpenIdProvider):
    form = None  # Don't need a form for Google

    def __init__(self, *args, **kwargs):
        super(GoogleProvider, self).__init__(*args, **kwargs)
        self.do = exception_handler(oid.loginhandler(self.unwrapped_do))

    def unwrapped_do(self, callback_url=None, form=None):
        session['openid_service'] = self.name
        return oid.try_login('https://www.google.com/accounts/o8/id',
            ask_for=['email', 'fullname'])
