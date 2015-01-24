# -*- coding: utf-8 -*-

import os
from datetime import datetime, timedelta
from functools import wraps
from urllib import unquote
from pytz import common_timezones
from flask import g, current_app, request, session, flash, redirect, url_for, Response
from coaster.views import get_current_url
from baseframe import _
from lastuser_core.models import db, User, ClientCredential, UserSession
from lastuser_core.signals import user_login, user_logout, user_registered
from .. import lastuser_oauth

valid_timezones = set(common_timezones)


@lastuser_oauth.before_app_request
def lookup_current_user():
    """
    If there's a userid in the session, retrieve the user object and add
    to the request namespace object g.
    """
    g.user = None
    g.usersession = None

    if 'sessionid' in session:
        usersession = UserSession.authenticate(buid=session['sessionid'])
        g.usersession = usersession
        if usersession:
            usersession.access()
            db.session.commit()  # Save access
            g.user = usersession.user
        else:
            session.pop('sessionid', None)

    # Transition users with 'userid' to 'sessionid'
    if 'userid' in session:
        if not g.usersession:
            user = User.get(userid=session['userid'])
            if user:
                usersession = UserSession(user=user)
                usersession.access()
                db.session.commit()  # Save access
                g.usersession = usersession
                g.user = user
                session['sessionid'] = usersession.buid
        session.pop('userid', None)

    # This will be set to True downstream by the requires_login decorator
    g.login_required = False


@lastuser_oauth.after_app_request
def hasuser_cookie(response):
    """
    Add a userid cookie, for use from JS to check if a user is logged in.
    """
    response.set_cookie('hasuser', value='1' if g.user else '0', max_age=31557600,  # Keep this cookie for a year.
        expires=datetime.utcnow() + timedelta(days=365),                            # Expire one year from now.
        httponly=False)                                                             # Allow reading this from JS.

    return response


@lastuser_oauth.after_app_request
def cache_expiry_headers(response):
    if 'Expires' not in response.headers:
        response.headers['Expires'] = 'Fri, 01 Jan 1990 00:00:00 GMT'
    if 'Cache-Control' in response.headers:
        if 'private' not in response.headers['Cache-Control']:
            response.headers['Cache-Control'] = 'private, ' + response.headers['Cache-Control']
    else:
        response.headers['Cache-Control'] = 'private'
    return response


@lastuser_oauth.app_template_filter('usessl')
def usessl(url):
    """
    Convert a URL to https:// if SSL is enabled in site config
    """
    if not current_app.config.get('USE_SSL'):
        return url
    if url.startswith('//'):  # //www.example.com/path
        return 'https:' + url
    if url.startswith('/'):  # /path
        url = os.path.join(request.url_root, url[1:])
    if url.startswith('http:'):  # http://www.example.com
        url = 'https:' + url[5:]
    return url


@lastuser_oauth.app_template_filter('nossl')
def nossl(url):
    """
    Convert a URL to http:// if using SSL
    """
    if url.startswith('//'):
        return 'http:' + url
    if url.startswith('/') and request.url.startswith('https:'):  # /path and SSL is on
        url = os.path.join(request.url_root, url[1:])
    if url.startswith('https://'):
        return 'http:' + url[6:]
    return url


def requires_login(f):
    """
    Decorator to require a login for the given view.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        g.login_required = True
        if g.user is None:
            flash(_(u"You need to be logged in for that page"), 'info')
            session['next'] = get_current_url()
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def requires_login_no_message(f):
    """
    Decorator to require a login for the given view.
    Does not display a message asking the user to login.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        g.login_required = True
        if g.user is None:
            session['next'] = get_current_url()
            if 'message' in request.args and request.args['message']:
                flash(request.args['message'], 'info')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def _client_login_inner():
    if request.authorization is None or not request.authorization.username:
        return Response('Client credentials required', 401,
            {'WWW-Authenticate': 'Basic realm="Client credentials"'})
    credential = ClientCredential.get(name=request.authorization.username)
    if credential is None or not credential.secret_is(request.authorization.password):
        return Response('Invalid client credentials', 401,
            {'WWW-Authenticate': 'Basic realm="Client credentials"'})
    if credential:
        credential.accessed_at = datetime.utcnow()
        db.session.commit()
    g.client = credential.client


def requires_client_login(f):
    """
    Decorator to require a client login via HTTP Basic Authorization.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        result = _client_login_inner()
        if result is None:
            return f(*args, **kwargs)
        else:
            return result
    return decorated_function


def requires_user_or_client_login(f):
    """
    Decorator to require a user or client login (user by cookie, client by HTTP Basic).
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        g.login_required = True
        # Check for user first:
        if g.user is not None:
            return f(*args, **kwargs)
        # If user is not logged in, check for client
        result = _client_login_inner()
        if result is None:
            return f(*args, **kwargs)
        else:
            return result
    return decorated_function


def login_internal(user):
    g.user = user
    usersession = UserSession(user=user)
    usersession.access()
    session['sessionid'] = usersession.buid
    session.permanent = True
    autoset_timezone(user)
    user_login.send(user)


def autoset_timezone(user):
    # Set the user's timezone automatically if available
    if user.timezone is None or user.timezone not in valid_timezones:
        if request.cookies.get('timezone'):
            timezone = unquote(request.cookies.get('timezone'))
            if timezone in valid_timezones:
                user.timezone = timezone


def logout_internal():
    user = g.user
    g.user = None
    if g.usersession:
        g.usersession.revoke()
        g.usersession = None
    session.pop('sessionid', None)
    session.pop('userid', None)
    session.pop('merge_userid', None)
    session.pop('userid_external', None)
    session.pop('avatar_url', None)
    session.permanent = False
    if user is not None:
        user_logout.send(user)


def register_internal(username, fullname, password):
    user = User(username=username, fullname=fullname, password=password)
    if not username:
        user.username = None
    db.session.add(user)
    user_registered.send(user)
    return user


def set_loginmethod_cookie(response, value):
    response.set_cookie('login', value, max_age=31557600,  # Keep this cookie for a year
        expires=datetime.utcnow() + timedelta(days=365),   # Expire one year from now
        httponly=True)
    return response
