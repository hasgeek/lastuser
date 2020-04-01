# -*- coding: utf-8 -*-

from flask import get_flashed_messages, jsonify, redirect, render_template, request

from baseframe import _
from coaster.auth import current_auth
from coaster.sqlalchemy import failsafe_add
from coaster.utils import newsecret
from lastuser_core import resource_registry
from lastuser_core.models import (
    AuthClient,
    AuthClientCredential,
    AuthClientTeamPermissions,
    AuthClientUserPermissions,
    AuthCode,
    AuthToken,
    User,
    db,
    getuser,
)
from lastuser_core.utils import make_redirect_url

from .. import lastuser_oauth
from ..forms import AuthorizeForm
from .helpers import requires_client_login, requires_login_no_message
from .resource import get_userinfo


class ScopeException(Exception):
    pass


def verifyscope(scope, auth_client):
    """
    Verify if requested scope is valid for this client. Scope must be a list.
    """
    internal_resources = []  # Names of internal resources
    full_client_access = []  # Clients linked to namespace:* scope

    for item in scope:
        if item == '*':
            # The '*' resource (full access) is only available to trusted clients
            if not auth_client.trusted:
                raise ScopeException(
                    _("Full access is only available to trusted clients")
                )
        elif item in resource_registry:
            if resource_registry[item]['trusted'] and not auth_client.trusted:
                raise ScopeException(
                    _(
                        "The resource {scope} is only available to trusted clients"
                    ).format(scope=item)
                )
            internal_resources.append(item)
        else:

            # Validation 0: Is this an internal wildcard resource?
            if item.endswith('/*'):
                found_internal = False
                wildcard_base = item[:-2]
                for key in resource_registry:
                    if key == wildcard_base or key.startswith(wildcard_base + '/'):
                        if (
                            resource_registry[key]['trusted']
                            and not auth_client.trusted
                        ):
                            # Skip over trusted resources if the client is not trusted
                            continue
                        internal_resources.append(key)
                        found_internal = True
                if found_internal:
                    continue  # Continue to next item in scope, skipping the following

            # Further validation is only required for non-internal resources
            # Validation 1: namespace:resource/action is properly formatted
            if ':' not in item:
                raise ScopeException(
                    _(
                        "No namespace specified for external resource ‘{scope}’ in scope"
                    ).format(scope=item)
                )
            itemparts = item.split(':')
            if len(itemparts) != 2:
                raise ScopeException(
                    _("Too many ‘:’ characters in ‘{scope}’ in scope").format(
                        scope=item
                    )
                )
            namespace, subitem = itemparts
            if '/' in subitem:
                parts = subitem.split('/')
                if len(parts) != 2:
                    raise ScopeException(
                        _("Too many ‘/’ characters in ‘{scope}’ in scope").format(
                            scope=item
                        )
                    )
                resource_name, action_name = parts
            else:
                resource_name = subitem
                action_name = None
            if resource_name == '*' and not action_name:
                resource_client = AuthClient.get(namespace=namespace)
                if resource_client:
                    if resource_client.owner == auth_client.owner:
                        full_client_access.append(resource_client)
                    else:
                        raise ScopeException(
                            _(
                                "This application does not have access to all "
                                "resources of app ‘{title}’"
                            ).format(title=resource_client.title)
                        )
                else:
                    raise ScopeException(
                        _("Unknown resource namespace ‘{namespace}’ in scope").format(
                            namespace=namespace
                        )
                    )

    internal_resources.sort()
    return internal_resources, full_client_access


def oauth_auth_403(reason):
    """
    Returns 403 errors for /auth
    """
    return render_template('oauth403.html.jinja2', reason=reason), 403


def oauth_make_auth_code(auth_client, scope, redirect_uri):
    """
    Make an auth code for a given client. Caller must commit
    the database session for this to work.
    """
    authcode = AuthCode(
        user=current_auth.user,
        user_session=current_auth.session,
        auth_client=auth_client,
        scope=scope,
        redirect_uri=redirect_uri[:1024],
    )
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


def oauth_auth_success(auth_client, redirect_uri, state, code, token=None):
    """
    Commit session and redirect to OAuth redirect URI
    """
    clear_flashed_messages()
    db.session.commit()
    if auth_client.confidential:
        use_fragment = False
    else:
        use_fragment = True
    if token:
        redirect_to = make_redirect_url(
            redirect_uri,
            use_fragment=use_fragment,
            access_token=token.token,
            token_type=token.token_type,
            expires_in=token.validity,
            scope=token._scope,
            state=state,
        )
    else:
        redirect_to = make_redirect_url(
            redirect_uri, use_fragment=use_fragment, code=code, state=state
        )
    if use_fragment:
        return render_template(
            'oauth_public_redirect.html.jinja2',
            auth_client=auth_client,
            redirect_to=redirect_to,
        )
    else:
        response = redirect(redirect_to, code=303)
        response.headers[
            'Cache-Control'
        ] = 'no-cache, no-store, max-age=0, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        return response


def oauth_auth_error(
    redirect_uri, state, error, error_description=None, error_uri=None
):
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
    response = redirect(make_redirect_url(redirect_uri, **params), code=303)
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
    scope = request.args.get('scope', '').split(' ')
    state = request.args.get('state')

    # Validation 1.1: Client_id present
    if not client_id:
        return oauth_auth_403(_("Missing client_id"))
    # Validation 1.2: AuthClient exists

    credential = AuthClientCredential.get(client_id)
    if credential:
        auth_client = credential.auth_client
    else:
        return oauth_auth_403(_("Unknown client_id"))

    # Validation 1.2.1: Is the client active?
    if not auth_client.active:
        return oauth_auth_error(auth_client.redirect_uri, state, 'unauthorized_client')

    # Validation 1.3: Cross-check redirect_uri
    if not redirect_uri:
        redirect_uri = auth_client.redirect_uri
        if not redirect_uri:  # Validation 1.3.1: No redirect_uri specified
            return oauth_auth_403(_("No redirect URI specified"))
    elif redirect_uri not in auth_client.redirect_uris:
        if not auth_client.host_matches(redirect_uri):
            return oauth_auth_error(
                auth_client.redirect_uri,
                state,
                'invalid_request',
                _("Redirect URI hostname doesn't match"),
            )

    # Validation 1.4: AuthClient allows login for this user
    if not auth_client.allow_any_login:
        if auth_client.user:
            perms = AuthClientUserPermissions.query.filter_by(
                user=current_auth.user, auth_client=auth_client
            ).first()
        else:
            perms = (
                AuthClientTeamPermissions.query.filter_by(auth_client=auth_client)
                .filter(
                    AuthClientTeamPermissions.team_id.in_(
                        [team.id for team in current_auth.user.teams]
                    )
                )
                .first()
            )
        if not perms:
            return oauth_auth_error(
                auth_client.redirect_uri,
                state,
                'invalid_scope',
                _("You do not have access to this application"),
            )

    # Validation 2.1: Is response_type present?
    if not response_type:
        return oauth_auth_error(
            redirect_uri, state, 'invalid_request', _("response_type missing")
        )
    # Validation 2.2: Is response_type acceptable?
    if response_type not in ['code', 'token']:
        return oauth_auth_error(redirect_uri, state, 'unsupported_response_type')

    # Validation 3.1: Is scope present?
    if not scope:
        return oauth_auth_error(
            redirect_uri, state, 'invalid_request', _("Scope not specified")
        )

    # Validation 3.2: Is scope valid?
    try:
        internal_resources, full_client_access = verifyscope(scope, auth_client)
    except ScopeException as scopeex:
        return oauth_auth_error(redirect_uri, state, 'invalid_scope', str(scopeex))

    # Validations complete. Now ask user for permission
    # If the client is trusted (Lastuser feature, not in OAuth2 spec), don't ask user.
    # The client does not get access to any data here -- they still have to authenticate to /token.
    if request.method == 'GET' and auth_client.trusted:
        # Return auth token. No need for user confirmation
        if response_type == 'code':
            return oauth_auth_success(
                auth_client,
                redirect_uri,
                state,
                oauth_make_auth_code(auth_client, scope, redirect_uri),
            )
        else:
            return oauth_auth_success(
                auth_client,
                redirect_uri,
                state,
                code=None,
                token=oauth_make_token(
                    current_auth.user, auth_client, scope, current_auth.session
                ),
            )

    # If there is an existing auth token with the same or greater scope, don't ask user again; authorise silently
    if auth_client.confidential:
        existing_token = AuthToken.query.filter_by(
            user=current_auth.user, auth_client=auth_client
        ).first()
    else:
        existing_token = AuthToken.query.filter_by(
            user_session=current_auth.session, auth_client=auth_client
        ).first()
    if existing_token and (
        '*' in existing_token.effective_scope
        or set(scope).issubset(set(existing_token.effective_scope))
    ):
        if response_type == 'code':
            return oauth_auth_success(
                auth_client,
                redirect_uri,
                state,
                oauth_make_auth_code(auth_client, scope, redirect_uri),
            )
        else:
            return oauth_auth_success(
                auth_client,
                redirect_uri,
                state,
                code=None,
                token=oauth_make_token(
                    current_auth.user, auth_client, scope, current_auth.session
                ),
            )

    # If the user was prompted, take their input.
    if form.validate_on_submit():
        if 'accept' in request.form:
            # User said yes. Return an auth code to the client
            if response_type == 'code':
                return oauth_auth_success(
                    auth_client,
                    redirect_uri,
                    state,
                    oauth_make_auth_code(auth_client, scope, redirect_uri),
                )
            else:
                return oauth_auth_success(
                    auth_client,
                    redirect_uri,
                    state,
                    code=None,
                    token=oauth_make_token(
                        current_auth.user, auth_client, scope, current_auth.session
                    ),
                )
        elif 'deny' in request.form:
            # User said no. Return "access_denied" error (OAuth2 spec)
            return oauth_auth_error(redirect_uri, state, 'access_denied')
        else:
            raise ValueError("Received an authorize form without a valid action.")

    # GET request or POST with invalid CSRF
    return (
        render_template(
            'authorize.html.jinja2',
            form=form,
            auth_client=auth_client,
            redirect_uri=redirect_uri,
            internal_resources=internal_resources,
            full_client_access=full_client_access,
            resource_registry=resource_registry,
        ),
        200,
        {'X-Frame-Options': 'SAMEORIGIN'},
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


def oauth_make_token(user, auth_client, scope, user_session=None):
    # Look for an existing token
    if auth_client.confidential:
        token = AuthToken.query.filter_by(user=user, auth_client=auth_client).first()
    elif user_session:
        token = AuthToken.query.filter_by(
            user_session=user_session, auth_client=auth_client
        ).first()
    else:
        raise ValueError("user_session not provided")

    # If token exists, add to the existing scope
    if token:
        token.add_scope(scope)
    else:
        # If there's no existing token, create one
        if auth_client.confidential:
            token = AuthToken(
                user=user, auth_client=auth_client, scope=scope, token_type='bearer'
            )
            token = failsafe_add(db.session, token, user=user, auth_client=auth_client)
        elif user_session:
            token = AuthToken(
                user_session=user_session,
                auth_client=auth_client,
                scope=scope,
                token_type='bearer',
            )
            token = failsafe_add(
                db.session, token, user_session=user_session, auth_client=auth_client
            )
    return token


def oauth_token_success(token, **params):
    params['access_token'] = token.token
    params['token_type'] = token.token_type
    params['scope'] = ' '.join(token.effective_scope)
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
    OAuth2 server -- token endpoint (confidential clients only)
    """
    # Always required parameters
    grant_type = request.form.get('grant_type')
    auth_client = current_auth.auth_client  # Provided by @requires_client_login
    scope = request.form.get('scope', '').split(' ')
    # if grant_type == 'authorization_code' (POST)
    code = request.form.get('code')
    redirect_uri = request.form.get('redirect_uri')
    # if grant_type == 'password' (POST)
    username = request.form.get('username')
    password = request.form.get('password')
    # if grant_type == 'client_credentials'
    buid = request.form.get('buid') or request.form.get(
        'userid'
    )  # XXX: Deprecated userid parameter

    # Validations 1: Required parameters
    if not grant_type:
        return oauth_token_error('invalid_request', _("Missing grant_type"))
    # grant_type == 'refresh_token' is not supported. All tokens are permanent unless revoked
    if grant_type not in ['authorization_code', 'client_credentials', 'password']:
        return oauth_token_error('unsupported_grant_type')

    # Validations 2: client scope
    if grant_type == 'client_credentials':
        # AuthClient data; user isn't part of it OR trusted client and automatic scope
        try:
            # Confirm the client has access to the scope it wants
            verifyscope(scope, auth_client)
        except ScopeException as scopeex:
            return oauth_token_error('invalid_scope', str(scopeex))

        if buid:
            if auth_client.trusted:
                user = User.get(buid=buid)
                if user:
                    # This client is trusted and can receive a user access token.
                    # However, don't grant it the scope it wants as the user's
                    # permission was not obtained. Instead, the client's
                    # pre-approved scope will be used for the token's effective scope.
                    token = oauth_make_token(
                        user=user, auth_client=auth_client, scope=[]
                    )
                    return oauth_token_success(
                        token,
                        userinfo=get_userinfo(
                            user=token.user,
                            auth_client=auth_client,
                            scope=token.effective_scope,
                        ),
                    )
                else:
                    return oauth_token_error('invalid_grant', _("Unknown user"))
            else:
                return oauth_token_error('invalid_grant', _("Untrusted client app"))
        else:
            token = oauth_make_token(user=None, auth_client=auth_client, scope=scope)
        return oauth_token_success(token)

    # Validations 3: auth code
    elif grant_type == 'authorization_code':
        authcode = AuthCode.query.filter_by(code=code, auth_client=auth_client).first()
        if not authcode:
            return oauth_token_error('invalid_grant', _("Unknown auth code"))
        if not authcode.is_valid():
            db.session.delete(authcode)
            db.session.commit()
            return oauth_token_error('invalid_grant', _("Expired auth code"))
        # Validations 3.1: scope in authcode
        if not scope or scope[0] == '':
            return oauth_token_error('invalid_scope', _("Scope is blank"))
        if not set(scope).issubset(set(authcode.scope)):
            return oauth_token_error('invalid_scope', _("Scope expanded"))
        else:
            # Scope not provided. Use whatever the authcode allows
            scope = authcode.scope
        if redirect_uri != authcode.redirect_uri:
            return oauth_token_error('invalid_client', _("redirect_uri does not match"))

        token = oauth_make_token(
            user=authcode.user, auth_client=auth_client, scope=scope
        )
        db.session.delete(authcode)
        return oauth_token_success(
            token,
            userinfo=get_userinfo(
                user=authcode.user,
                auth_client=auth_client,
                scope=token.effective_scope,
                user_session=authcode.user_session,
            ),
        )

    elif grant_type == 'password':
        # Validations 4.1: password grant_type is only for trusted clients
        if not auth_client.trusted:
            # Refuse to untrusted clients
            return oauth_token_error(
                'unauthorized_client',
                _("AuthClient is not trusted for password grant_type"),
            )
        # Validations 4.2: Are username and password provided and correct?
        if not username or not password:
            return oauth_token_error(
                'invalid_request', _("Username or password not provided")
            )
        user = getuser(username)
        if not user:
            return oauth_token_error(
                'invalid_client', _("No such user")
            )  # XXX: invalid_client doesn't seem right
        if not user.password_is(password):
            return oauth_token_error('invalid_client', _("Password mismatch"))
        # Validations 4.3: verify scope
        try:
            verifyscope(scope, auth_client)
        except ScopeException as scopeex:
            return oauth_token_error('invalid_scope', str(scopeex))
        # All good. Grant access
        token = oauth_make_token(user=user, auth_client=auth_client, scope=scope)
        return oauth_token_success(
            token,
            userinfo=get_userinfo(user=user, auth_client=auth_client, scope=scope),
        )
