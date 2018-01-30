# -*- coding: utf-8 -*-

import os
from datetime import datetime, timedelta
from functools import wraps
from urllib import unquote
from pytz import common_timezones
import itsdangerous
from flask import g, current_app, request, session, flash, redirect, url_for, Response
from coaster.auth import current_auth, add_auth_attribute
from coaster.sqlalchemy import failsafe_add
from coaster.views import get_current_url
from baseframe import _
from lastuser_core.models import db, User, ClientCredential, UserSession
from lastuser_core.signals import user_login, user_registered
from .. import lastuser_oauth
from urlparse import urlparse

valid_timezones = set(common_timezones)


# g.* attributes are deprecated and no longer used by Lastuser.
# They are referenced in Baseframe however, which itself depends on
# Flask-Lastuser being upgraded to be fully compatible with current_auth.

def _set_user(user):
    add_auth_attribute('user', user)
    g.user = user


def _set_usersession(session):
    add_auth_attribute('session', session)
    g.usersession = session


def _set_login_required(required):
    add_auth_attribute('login_required', required)
    g.login_required = required


def _set_lastuser_cookie(cookie):
    add_auth_attribute('cookie', cookie)
    g.lastuser_cookie = cookie


@lastuser_oauth.before_app_request
def lookup_current_user():
    """
    If there's a buid in the session, retrieve the user object and add
    to the request namespace object g.
    """
    _set_user(None)
    _set_usersession(None)

    lastuser_cookie = {}
    lastuser_cookie_headers = {}  # Ignored for now, intended for future changes

    # Migrate data from Flask cookie session
    if 'sessionid' in session:
        lastuser_cookie['sessionid'] = session.pop('sessionid')
    if 'userid' in session:
        lastuser_cookie['userid'] = session.pop('userid')

    if 'lastuser' in request.cookies:
        try:
            lastuser_cookie, lastuser_cookie_headers = lastuser_oauth.serializer.loads(
                request.cookies['lastuser'], return_header=True)
        except itsdangerous.BadSignature:
            lastuser_cookie = {}

    if 'sessionid' in lastuser_cookie:
        _set_usersession(UserSession.authenticate(buid=lastuser_cookie['sessionid']))
        if current_auth.session:
            current_auth.session.access()
            db.session.commit()  # Save access
            _set_user(current_auth.session.user)

    # Transition users with 'userid' to 'sessionid'
    if not current_auth.session and 'userid' in lastuser_cookie:
        _set_user(User.get(buid=lastuser_cookie['userid']))
        if current_auth.is_authenticated:
            _set_usersession(UserSession(user=current_auth.user))
            current_auth.session.access()
            db.session.commit()  # Save access

    if current_auth.session:
        lastuser_cookie['sessionid'] = current_auth.session.buid
    else:
        lastuser_cookie.pop('sessionid', None)
    if current_auth.is_authenticated:
        lastuser_cookie['userid'] = current_auth.user.buid
    else:
        lastuser_cookie.pop('userid', None)

    _set_lastuser_cookie(lastuser_cookie)
    # This will be set to True downstream by the requires_login decorator
    _set_login_required(False)


@lastuser_oauth.after_app_request
def lastuser_cookie(response):
    """
    Save lastuser login cookie and hasuser JS-readable flag cookie.
    """
    expires = datetime.utcnow() + timedelta(days=365)
    response.set_cookie('lastuser',
        value=lastuser_oauth.serializer.dumps(current_auth.cookie, header_fields={'v': 1}),
        max_age=31557600,                                         # Keep this cookie for a year.
        expires=expires,                                          # Expire one year from now.
        domain=current_app.config.get('LASTUSER_COOKIE_DOMAIN'),  # Place cookie in master domain.
        httponly=True)                                            # Don't allow reading this from JS.

    response.set_cookie('hasuser',
        value='1' if current_auth.is_authenticated else '0',
        max_age=31557600,              # Keep this cookie for a year.
        expires=expires,               # Expire one year from now.
        httponly=False)                # Allow reading this from JS.

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
        _set_login_required(True)
        if not current_auth.is_authenticated:
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
        _set_login_required(True)
        if not current_auth.is_authenticated:
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
        credential.accessed_at = db.func.utcnow()
        db.session.commit()
    add_auth_attribute('client', credential.client)


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
        _set_login_required(True)
        # Check for user first:
        if current_auth.is_authenticated:
            return f(*args, **kwargs)
        # If user is not logged in, check for client
        result = _client_login_inner()
        if result is None:
            return f(*args, **kwargs)
        else:
            return result
    return decorated_function


def get_scheme_netloc(uri):
    parsed_uri = urlparse(uri)
    return (parsed_uri.scheme, parsed_uri.netloc)


def requires_client_id_or_user_or_client_login(f):
    """
    Decorator to require a client_id and session or a user or client login
    (client_id and session in the request args, user by cookie, client by HTTP Basic).
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        _set_login_required(True)

        # Check if http referrer and given client id match a registered client
        if 'client_id' in request.values and 'session' in request.values and request.referrer:
            client_cred = ClientCredential.get(request.values['client_id'])
            if client_cred is not None and get_scheme_netloc(client_cred.client.website) == get_scheme_netloc(request.referrer):
                if UserSession.authenticate(buid=request.values['session']) is not None:
                    return f(*args, **kwargs)

        # If we didn't get a valid client_id and session, maybe there's a user?
        if current_auth.is_authenticated:
            return f(*args, **kwargs)

        # If user is not logged in, check for client credentials in the request authorization header.
        # If no error reported, call the function, else return error.
        result = _client_login_inner()
        if result is None:
            return f(*args, **kwargs)
        else:
            return result
    return decorated_function


def login_internal(user):
    _set_user(user)
    usersession = UserSession(user=user)
    usersession.access()
    _set_usersession(usersession)
    current_auth.cookie['sessionid'] = usersession.buid
    current_auth.cookie['userid'] = user.buid
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
    _set_user(None)
    if current_auth.session:
        current_auth.session.revoke()
        _set_usersession(None)
    session.pop('sessionid', None)
    session.pop('userid', None)
    session.pop('merge_userid', None)
    session.pop('merge_buid', None)
    session.pop('userid_external', None)
    session.pop('avatar_url', None)
    current_auth.cookie.pop('sessionid', None)
    current_auth.cookie.pop('userid', None)
    session.permanent = False


def register_internal(username, fullname, password):
    user = User(username=username, fullname=fullname, password=password)
    if not username:
        user.username = None
    if user.username:
        # We can only use failsafe_add when a unique identifier like username is present
        user = failsafe_add(db.session, user, username=user.username)
    else:
        db.session.add(user)
    user_registered.send(user)
    return user


def set_loginmethod_cookie(response, value):
    response.set_cookie('login', value, max_age=31557600,  # Keep this cookie for a year
        expires=datetime.utcnow() + timedelta(days=365),   # Expire one year from now
        httponly=True)
    return response
