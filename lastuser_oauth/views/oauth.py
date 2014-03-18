# -*- coding: utf-8 -*-

from datetime import datetime, timedelta
import urlparse
from flask import g, render_template, redirect, request, jsonify, get_flashed_messages
from coaster import newsecret

from lastuser_core.utils import make_redirect_url
from lastuser_core import resource_registry
from lastuser_core.models import (db, Client, AuthCode, AuthToken, UserFlashMessage,
    UserClientPermissions, TeamClientPermissions, getuser, Resource, ResourceAction)
from .. import lastuser_oauth
from ..forms import AuthorizeForm
from .helpers import requires_login_no_message, requires_client_login
from .resource import get_userinfo


class ScopeException(Exception):
    pass


def verifyscope(scope, client):
    """
    Verify if requested scope is valid for this client. Scope must be a list.
    """
    resources = {}  # resource_object: [action_object, ...]

    for item in scope:
        if item not in resource_registry:  # Validation is only required for non-internal resources
            # Validation 1: namespace:resource/action is properly formatted
            if ':' not in item:
                raise ScopeException(u"No namespace specified for external resource ‘{scope}’ in scope".format(scope=item))
            itemparts = item.split(':')
            if len(itemparts) != 2:
                raise ScopeException(u"Too many ':' characters in ‘{scope}’ in scope".format(scope=item))
            namespace, item = itemparts[0], itemparts[1]
            if '/' in item:
                parts = item.split('/')
                if len(parts) != 2:
                    raise ScopeException(u"Too many / characters in ‘{scope}’ in scope".format(scope=item))
                resource_name, action_name = parts
            else:
                resource_name = item
                action_name = None
            resource = Resource.get(name=resource_name, namespace=namespace)
            # Validation 2: Resource exists & client has access to it
            if not resource:
                raise ScopeException(u"Unknown resource ‘{resource}’ under namespace ’{namespace}’ in scope".format(resource=resource_name, namespace=namespace))
            # Validation 3: Action is valid
            if action_name:
                action = resource.get_action(action_name)
                if not action:
                    raise ScopeException(u"Unknown action ‘{action}’ on resource ‘{resource}’ under namespace ’{namespace}’".format(
                        action=action_name, resource=resource_name, namespace=namespace))
                resources.setdefault(resource, []).append(action)
            else:
                resources.setdefault(resource, [])
    return resources


def oauth_auth_403(reason):
    """
    Returns 403 errors for /auth
    """
    return render_template('oauth403.html', reason=reason), 403


def oauth_make_auth_code(client, scope, redirect_uri):
    """
    Make an auth code for a given client. Caller must commit
    the database session for this to work.
    """
    authcode = AuthCode(user=g.user, client=client, scope=scope, redirect_uri=redirect_uri)
    authcode.code = newsecret()
    db.session.add(authcode)
    return authcode.code


def clear_flashed_messages():
    """
    Clear pending flashed messages. This is useful when redirecting the user to a
    remote site where they cannot see the messages. If they return much later,
    they could be confused by a message for an action they do not recall.
    """
    list(get_flashed_messages())


def save_flashed_messages():
    """
    Save flashed messages so they can be relayed back to trusted clients.
    """
    for index, (category, message) in enumerate(get_flashed_messages(with_categories=True)):
        db.session.add(UserFlashMessage(user=g.user, seq=index, category=category, message=message))


def oauth_auth_success(client, redirect_uri, state, code):
    """
    Commit session and redirect to OAuth redirect URI
    """
    if client.trusted:
        save_flashed_messages()
    else:
        clear_flashed_messages()
    db.session.commit()
    if state is None:
        response = redirect(make_redirect_url(redirect_uri, code=code), code=302)
    else:
        response = redirect(make_redirect_url(redirect_uri, code=code, state=state), code=302)
    response.headers['Cache-Control'] = 'no-cache, no-store, max-age=0, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    return response


def oauth_auth_error(redirect_uri, state, error, error_description=None, error_uri=None):
    """
    Auth request resulted in an error. Return to client.
    """
    params = {'error': error}
    if state is not None:
        params['state'] = state
    if error_description is not None:
        params['error_description'] = error_description
    if error_uri is not None:
        params['error_uri'] = error_uri
    clear_flashed_messages()
    response = redirect(make_redirect_url(redirect_uri, **params), code=302)
    response.headers['Cache-Control'] = 'no-cache, no-store, max-age=0, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    return response


@lastuser_oauth.route('/auth', methods=['GET', 'POST'])
@requires_login_no_message
def oauth_authorize():
    """
    OAuth2 server -- authorization endpoint
    """
    form = AuthorizeForm()

    response_type = request.args.get('response_type')
    client_id = request.args.get('client_id')
    redirect_uri = request.args.get('redirect_uri')
    scope = request.args.get('scope', u'').split(u' ')
    state = request.args.get('state')

    # Validation 1.1: Client_id present
    if not client_id:
        return oauth_auth_403(u"Missing client_id")
    # Validation 1.2: Client exists
    client = Client.query.filter_by(key=client_id).first()
    if not client:
        return oauth_auth_403(u"Unknown client_id")

    # Validation 1.2.1: Is the client active?
    if not client.active:
        return oauth_auth_error(client.redirect_uri, state, 'unauthorized_client')

    # Validation 1.3: Cross-check redirect_uri
    if not redirect_uri:
        redirect_uri = client.redirect_uri
        if not redirect_uri:  # Validation 1.3.1: No redirect_uri specified
            return oauth_auth_403(u"No redirect URI specified")
    elif redirect_uri != client.redirect_uri:
        if urlparse.urlsplit(redirect_uri).hostname != urlparse.urlsplit(client.redirect_uri).hostname:
            return oauth_auth_error(client.redirect_uri, state, 'invalid_request', u"Redirect URI hostname doesn't match")

    # Validation 1.4: Client allows login for this user
    if not client.allow_any_login:
        if client.user:
            perms = UserClientPermissions.query.filter_by(user=g.user, client=client).first()
        else:
            perms = TeamClientPermissions.query.filter_by(client=client).filter(
                TeamClientPermissions.team_id.in_([team.id for team in g.user.teams])).first()
        if not perms:
            return oauth_auth_error(client.redirect_uri, state, 'invalid_scope', u"You do not have access to this application")

    # Validation 2.1: Is response_type present?
    if not response_type:
        return oauth_auth_error(redirect_uri, state, 'invalid_request', "response_type missing")
    # Validation 2.2: Is response_type acceptable?
    if response_type not in [u'code']:
        return oauth_auth_error(redirect_uri, state, 'unsupported_response_type')

    # Validation 3.1: Is scope present?
    if not scope:
        return oauth_auth_error(redirect_uri, state, 'invalid_request', "Scope not specified")

    # Validation 3.2: Is scope valid?
    try:
        resources = verifyscope(scope, client)
    except ScopeException as scopeex:
        return oauth_auth_error(redirect_uri, state, 'invalid_scope', unicode(scopeex))

    # Validations complete. Now ask user for permission
    # If the client is trusted (Lastuser feature, not in OAuth2 spec), don't ask user.
    # The client does not get access to any data here -- they still have to authenticate to /token.
    if request.method == 'GET' and client.trusted:
        # Return auth token. No need for user confirmation
        return oauth_auth_success(client, redirect_uri, state, oauth_make_auth_code(client, scope, redirect_uri))

    # If there is an existing auth token with the same or greater scope, don't ask user again; authorise silently
    existing_token = AuthToken.query.filter_by(user=g.user, client=client).first()
    if existing_token and set(scope).issubset(set(existing_token.scope)):
        return oauth_auth_success(client, redirect_uri, state, oauth_make_auth_code(client, scope, redirect_uri))

    # First request. Ask user.
    if form.validate_on_submit():
        if 'accept' in request.form:
            # User said yes. Return an auth code to the client
            return oauth_auth_success(client, redirect_uri, state, oauth_make_auth_code(client, scope, redirect_uri))
        elif 'deny' in request.form:
            # User said no. Return "access_denied" error (OAuth2 spec)
            return oauth_auth_error(redirect_uri, state, 'access_denied')
        # else: shouldn't happen, so just show the form again

    # GET request or POST with invalid CSRF
    return render_template('authorize.html',
        form=form,
        client=client,
        redirect_uri=redirect_uri,
        scope=scope,
        resources=resources,
        resource_registry=resource_registry,
        )


def oauth_token_error(error, error_description=None, error_uri=None):
    params = {'error': error}
    if error_description is not None:
        params['error_description'] = error_description
    if error_uri is not None:
        params['error_uri'] = error_uri
    response = jsonify(**params)
    response.headers['Cache-Control'] = 'no-cache, no-store, max-age=0, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.status_code = 400
    return response


def oauth_make_token(user, client, scope):
    token = AuthToken.query.filter_by(user=user, client=client).first()
    if token:
        token.add_scope(scope)
    else:
        token = AuthToken(user=user, client=client, scope=scope, token_type='bearer')
        db.session.add(token)
    # TODO: Look up Resources for items in scope; look up their providing clients apps,
    # and notify each client app of this token
    return token


def oauth_token_success(token, **params):
    params['access_token'] = token.token
    params['token_type'] = token.token_type
    params['scope'] = u' '.join(token.scope)
    if token.client.trusted:
        # Trusted client. Send back waiting user messages.
        for ufm in list(UserFlashMessage.query.filter_by(user=token.user).all()):
            params.setdefault('messages', []).append({
                'category': ufm.category,
                'message': ufm.message
                })
            db.session.delete(ufm)
    # TODO: Understand how refresh_token works.
    if token.validity:
        params['expires_in'] = token.validity
        # No refresh tokens for client_credentials tokens
        if token.user is not None:
            params['refresh_token'] = token.refresh_token
    response = jsonify(**params)
    response.headers['Cache-Control'] = 'no-cache, no-store, max-age=0, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    db.session.commit()
    return response


@lastuser_oauth.route('/token', methods=['POST'])
@requires_client_login
def oauth_token():
    """
    OAuth2 server -- token endpoint
    """
    # Always required parameters
    grant_type = request.form.get('grant_type')
    client = g.client  # Provided by @requires_client_login
    scope = request.form.get('scope', u'').split(u' ')
    # if grant_type == 'authorization_code' (POST)
    code = request.form.get('code')
    redirect_uri = request.form.get('redirect_uri')
    # if grant_type == 'password' (GET)
    username = request.form.get('username')
    password = request.form.get('password')

    # Validations 1: Required parameters
    if not grant_type:
        return oauth_token_error('invalid_request', "Missing grant_type")
    # grant_type == 'refresh_token' is not supported. All tokens are permanent unless revoked
    if grant_type not in ['authorization_code', 'client_credentials', 'password']:
        return oauth_token_error('unsupported_grant_type')

    # Validations 2: client scope
    if grant_type == 'client_credentials':
        # Client data. User isn't part of it
        try:
            verifyscope(scope, client)
        except ScopeException as scopeex:
            return oauth_token_error('invalid_scope', unicode(scopeex))

        token = oauth_make_token(user=None, client=client, scope=scope)
        return oauth_token_success(token)

    # Validations 3: auth code
    elif grant_type == 'authorization_code':
        authcode = AuthCode.query.filter_by(code=code, client=client).first()
        if not authcode:
            return oauth_token_error('invalid_grant', "Unknown auth code")
        if authcode.created_at < (datetime.utcnow() - timedelta(minutes=1)):  # XXX: Time limit: 1 minute
            db.session.delete(authcode)
            db.session.commit()
            return oauth_token_error('invalid_grant', "Expired auth code")
        # Validations 3.1: scope in authcode
        if not scope or scope[0] == '':
            return oauth_token_error('invalid_scope', "Scope is blank")
        if not set(scope).issubset(set(authcode.scope)):
            return oauth_token_error('invalid_scope', "Scope expanded")
        else:
            # Scope not provided. Use whatever the authcode allows
            scope = authcode.scope
        if redirect_uri != authcode.redirect_uri:
            return oauth_token_error('invalid_client', "redirect_uri does not match")

        token = oauth_make_token(user=authcode.user, client=client, scope=scope)
        db.session.delete(authcode)
        return oauth_token_success(token, userinfo=get_userinfo(user=authcode.user, client=client, scope=scope))

    elif grant_type == 'password':
        # Validations 4.1: password grant_type is only for trusted clients
        if not client.trusted:
            # Refuse to untrusted clients
            return oauth_token_error('unauthorized_client', "Client is not trusted for password grant_type")
        # Validations 4.2: Are username and password provided and correct?
        if not username or not password:
            return oauth_token_error('invalid_request', "Username or password not provided")
        user = getuser(username)
        if not user:
            return oauth_token_error('invalid_client', "No such user")  # XXX: invalid_client doesn't seem right
        if not user.password_is(password):
            return oauth_token_error('invalid_client', "Password mismatch")
        # Validations 4.3: verify scope
        try:
            verifyscope(scope, client)
        except ScopeException as scopeex:
            return oauth_token_error('invalid_scope', unicode(scopeex))
        # All good. Grant access
        token = oauth_make_token(user=user, client=client, scope=scope)
        return oauth_token_success(token, userinfo=get_userinfo(user=user, client=client, scope=scope))
