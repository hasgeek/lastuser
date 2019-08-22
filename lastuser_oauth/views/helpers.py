# -*- coding: utf-8 -*-

from datetime import timedelta
from functools import wraps
from urllib import unquote
from urlparse import urlparse

from flask import Response, current_app, flash, redirect, request, session, url_for
import itsdangerous

from pytz import common_timezones

from baseframe import _
from coaster.auth import add_auth_attribute, current_auth, request_has_auth
from coaster.sqlalchemy import failsafe_add
from coaster.utils import utcnow
from coaster.views import get_current_url
from lastuser_core.models import ClientCredential, User, UserSession, db
from lastuser_core.signals import user_login, user_registered

from .. import lastuser_oauth

valid_timezones = set(common_timezones)


class LoginManager(object):
    def _load_user(self):
        """
        If there's a buid in the session, retrieve the user object and add
        to the request namespace object g.
        """
        add_auth_attribute('user', None)
        add_auth_attribute('session', None)

        lastuser_cookie = {}
        lastuser_cookie_headers = {}  # Ignored for now, intended for future changes

        # Migrate data from Flask cookie session
        if 'sessionid' in session:
            lastuser_cookie['sessionid'] = session.pop('sessionid')
        if 'userid' in session:
            lastuser_cookie['userid'] = session.pop('userid')

        if 'lastuser' in request.cookies:
            try:
                (
                    lastuser_cookie,
                    lastuser_cookie_headers,
                ) = lastuser_oauth.serializer.loads(
                    request.cookies['lastuser'], return_header=True
                )
            except itsdangerous.BadSignature:
                lastuser_cookie = {}

        if 'sessionid' in lastuser_cookie:
            add_auth_attribute(
                'session', UserSession.authenticate(buid=lastuser_cookie['sessionid'])
            )
            if current_auth.session:
                current_auth.session.access()
                db.session.commit()  # Save access
                add_auth_attribute('user', current_auth.session.user)

        # Transition users with 'userid' to 'sessionid'
        if not current_auth.session and 'userid' in lastuser_cookie:
            add_auth_attribute('user', User.get(buid=lastuser_cookie['userid']))
            if current_auth.is_authenticated:
                add_auth_attribute('session', UserSession(user=current_auth.user))
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

        lastuser_cookie['updated_at'] = utcnow().isoformat()

        add_auth_attribute('cookie', lastuser_cookie)
        # This will be set to True downstream by the requires_login decorator
        add_auth_attribute('login_required', False)


@lastuser_oauth.after_app_request
def lastuser_cookie(response):
    """
    Save lastuser login cookie and hasuser JS-readable flag cookie.
    """
    if request_has_auth() and hasattr(current_auth, 'cookie'):
        expires = utcnow() + timedelta(days=365)
        response.set_cookie(
            'lastuser',
            value=lastuser_oauth.serializer.dumps(
                current_auth.cookie, header_fields={'v': 1}
            ),
            max_age=31557600,  # Keep this cookie for a year.
            expires=expires,  # Expire one year from now.
            domain=current_app.config.get(
                'LASTUSER_COOKIE_DOMAIN'
            ),  # Place cookie in master domain.
            secure=current_app.config[
                'SESSION_COOKIE_SECURE'
            ],  # HTTPS cookie if session is too.
            httponly=True,
        )  # Don't allow reading this from JS.

        response.set_cookie(
            'hasuser',
            value='1' if current_auth.is_authenticated else '0',
            max_age=31557600,  # Keep this cookie for a year.
            expires=expires,  # Expire one year from now.
            secure=current_app.config[
                'SESSION_COOKIE_SECURE'
            ],  # HTTPS cookie if session is too.
            httponly=False,
        )  # Allow reading this from JS.

    return response


@lastuser_oauth.after_app_request
def cache_expiry_headers(response):
    if 'Expires' not in response.headers:
        response.headers['Expires'] = 'Fri, 01 Jan 1990 00:00:00 GMT'
    if 'Cache-Control' in response.headers:
        if 'private' not in response.headers['Cache-Control']:
            response.headers['Cache-Control'] = (
                'private, ' + response.headers['Cache-Control']
            )
    else:
        response.headers['Cache-Control'] = 'private'
    return response


def requires_login(f):
    """
    Decorator to require a login for the given view.
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        add_auth_attribute('login_required', True)
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
    However, if a message received in ``request.args['message']``,
    it is displayed. This is an insecure channel for client apps
    to display a helper message.
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        add_auth_attribute('login_required', True)
        if not current_auth.is_authenticated:
            session['next'] = get_current_url()
            if 'message' in request.args and request.args['message']:
                flash(request.args['message'], 'info')
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


def _client_login_inner():
    if request.authorization is None or not request.authorization.username:
        return Response(
            'Client credentials required',
            401,
            {'WWW-Authenticate': 'Basic realm="Client credentials"'},
        )
    credential = ClientCredential.get(name=request.authorization.username)
    if credential is None or not credential.secret_is(request.authorization.password):
        return Response(
            'Invalid client credentials',
            401,
            {'WWW-Authenticate': 'Basic realm="Client credentials"'},
        )
    if credential:
        credential.accessed_at = db.func.utcnow()
        db.session.commit()
    add_auth_attribute('client', credential.client, actor=True)


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
        add_auth_attribute('login_required', True)
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
        add_auth_attribute('login_required', True)

        # Check if http referrer and given client id match a registered client
        if (
            'client_id' in request.values
            and 'session' in request.values
            and request.referrer
        ):
            client_cred = ClientCredential.get(request.values['client_id'])
            if client_cred is not None and get_scheme_netloc(
                client_cred.client.website
            ) == get_scheme_netloc(request.referrer):
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
    add_auth_attribute('user', user)
    usersession = UserSession(user=user)
    usersession.access()
    add_auth_attribute('session', usersession)
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
    add_auth_attribute('user', None)
    if current_auth.session:
        current_auth.session.revoke()
        add_auth_attribute('session', None)
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
    response.set_cookie(
        'login',
        value,
        max_age=31557600,  # Keep this cookie for a year
        expires=utcnow() + timedelta(days=365),  # Expire one year from now
        secure=current_app.config['SESSION_COOKIE_SECURE'],
        httponly=True,
    )
    return response
