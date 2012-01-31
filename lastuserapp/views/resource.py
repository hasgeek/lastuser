# -*- coding: utf-8 -*-

from flask import jsonify, request, g

from lastuserapp import app
from lastuserapp.models import AuthToken, Resource, ResourceAction, UserClientPermissions
from lastuserapp.views import provides_resource, requires_client_login


def get_userinfo(user, client, scope=[]):
    userinfo = {'userid': user.userid,
                'username': user.username,
                'fullname': user.fullname}
    if 'email' in scope:
        userinfo['email'] = unicode(user.email)
    perms = UserClientPermissions.query.filter_by(user=user, client=client).first()
    if perms:
        userinfo['permissions'] = perms.permissions.split(u' ')
    return userinfo


def resource_error(error, description=None, uri=None):
    params = {'status': 'error', 'error': error}
    if description:
        params['error_description'] = description
    if uri:
        params['error_uri'] = uri

    response = jsonify(params)
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    response.status_code = 400
    return response


def token_verify_result(status, **params):
    params['status'] = status
    response = jsonify(params)
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    return response


@app.route('/api/1/token/verify', methods=['POST'])
@requires_client_login
def token_verify():
    token = request.form.get('access_token')
    client_resource = request.form.get('resource') # Can only be a single resource
    if not client_resource:
        # No resource specified by caller
        return resource_error('no_resource')
    if not token:
        # No token specified by caller
        return resource_error('no_token')

    authtoken = AuthToken.query.filter_by(token=token).first()
    if not authtoken:
        # No such auth token
        return token_verify_result('error', error='no_token')
    if client_resource not in authtoken.scope:
        # Token does not grant access to this resource
        return token_verify_result('error', error='access_denied')
    if '/' in client_resource:
        parts = client_resource.split('/')
        if len(parts) != 2:
            return token_verify_result('error', error='invalid_scope')
        resource_name, action_name = parts
    else:
        resource_name = client_resource
        action_name = None
    resource = Resource.query.filter_by(name=resource_name).first()
    if not resource or resource.client != g.client:
        # Resource does not exist or does not belong to this client
        return token_verify_result('error', error='access_denied')
    if action_name:
        action = ResourceAction.query.filter_by(name=action_name, resource=resource).first()
        if not action:
            return token_verify_result('error', error='access_denied')

    # All validations passed. Token is valid for this client and scope. Return with information on the token
    # TODO: Don't return validity. Set the HTTP cache headers instead.
    params = {'validity': 120} # Period (in seconds) for which this assertion may be cached.
    if authtoken.user:
        params['userinfo'] = get_userinfo(authtoken.user, g.client)
    params['clientinfo'] = {
        'title': authtoken.client.title,
        'userid': authtoken.client.user.userid,
        'owner': authtoken.client.owner,
        'website': authtoken.client.website,
        'key': authtoken.client.key,
        'trusted': authtoken.client.trusted,
        }
    return token_verify_result('ok', **params)


@app.route('/api/1/email')
@provides_resource('email')
def resource_email(authtoken, args, files=None):
    """
    Return user's primary email address.
    """
    return {'email': unicode(authtoken.user.email)}
