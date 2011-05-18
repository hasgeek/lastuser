# -*- coding: utf-8 -*-

from functools import wraps

from flask import g, request, session, flash, redirect, url_for

from lastuserapp import app
from lastuserapp.models import db, User


@app.before_request
def lookup_current_user():
    """
    If there's a userid in the session, retrieve the user object and add
    to the request namespace object g.
    """
    g.user = None
    if 'userid' in session:
        g.user = User.query.filter_by(userid=session['userid']).first()


def requires_login(f):
    """
    Decorator to require a login for the given view.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if g.user is None:
            flash(u"You need to be logged in for that page")
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


def get_next_url(referrer=False):
    if referrer:
        return request.args.get('next') or request.referrer or url_for('index')
    else:
        return request.args.get('next') or url_for('index')


def login_internal(user):
    g.user = user
    session['userid'] = user.userid


def logout_internal():
    g.user = None
    session.pop('userid', None)
    session.pop('userid_external', None)
    session.permanent = False


def register_internal(username, fullname, password):
    user = User(username=username, fullname=fullname, password=password)
    db.session.add(user)
    return user


# The order of these imports is critical.
# index.py must always be first.
# profile.py must always be last

import lastuserapp.views.index
import lastuserapp.views.login
import lastuserapp.views.oauthclient
import lastuserapp.views.openidclient
import lastuserapp.views.oauth
import lastuserapp.views.client
import lastuserapp.views.httperror
import lastuserapp.views.profile
