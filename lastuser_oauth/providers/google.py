# -*- coding: utf-8 -*-

from flask import session
from .openid import oid, OpenIdProvider

__all__ = ['GoogleProvider']


class GoogleProvider(OpenIdProvider):
    form = None  # Don't need a form for Google

    def __init__(self, *args, **kwargs):
        super(GoogleProvider, self).__init__(*args, **kwargs)
        self.do = oid.loginhandler(self.unwrapped_do)

    def unwrapped_do(self, callback_url=None, form=None):
        session['openid_service'] = self.name
        return oid.try_login('https://www.google.com/accounts/o8/id',
            ask_for=['email', 'fullname', 'nickname'])
