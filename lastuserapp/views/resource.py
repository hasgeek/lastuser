# -*- coding: utf-8 -*-

from flask import jsonify, request, g

from lastuserapp import app
from lastuserapp.models import (getuser, User, Organization, AuthToken, Resource, ResourceAction,
    UserClientPermissions, TeamClientPermissions)
from lastuserapp.views import provides_resource, requires_client_login


def get_userinfo(user, client, scope=[]):
    userinfo = {'userid': user.userid,
                'username': user.username,
                'fullname': user.fullname}
    if 'email' in scope:
        userinfo['email'] = unicode(user.email)
    if 'organizations' in scope:
        userinfo['organizations'] = {
            'owner': [{'userid': org.userid, 'name': org.name, 'title': org.title} for org in user.organizations_owned()],
            'member': [{'userid': org.userid, 'name': org.name, 'title': org.title} for org in user.organizations()],
            }
        userinfo['teams'] = [{'userid': team.userid, 'title': team.title, 'org': team.org.userid} for team in user.teams]
    if client.user:
        perms = UserClientPermissions.query.filter_by(user=user, client=client).first()
        if perms:
            userinfo['permissions'] = perms.permissions.split(u' ')
    else:
        perms = TeamClientPermissions.query.filter_by(client=client).filter(
            TeamClientPermissions.team_id.in_([team.id for team in user.teams])).all()
        permsset = set()
        for permob in perms:
            permsset.update(permob.permissions.split(u' '))
        userinfo['permissions'] = sorted(permsset)
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


def api_result(status, **params):
    params['status'] = status
    response = jsonify(params)
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    return response


# --- Client access endpoints -------------------------------------------------

@app.route('/api/1/token/verify', methods=['POST'])
@requires_client_login
def token_verify():
    token = request.form.get('access_token')
    client_resource = request.form.get('resource')  # Can only be a single resource
    if not client_resource:
        # No resource specified by caller
        return resource_error('no_resource')
    if not token:
        # No token specified by caller
        return resource_error('no_token')

    authtoken = AuthToken.query.filter_by(token=token).first()
    if not authtoken:
        # No such auth token
        return api_result('error', error='no_token')
    if client_resource not in authtoken.scope:
        # Token does not grant access to this resource
        return api_result('error', error='access_denied')
    if '/' in client_resource:
        parts = client_resource.split('/')
        if len(parts) != 2:
            return api_result('error', error='invalid_scope')
        resource_name, action_name = parts
    else:
        resource_name = client_resource
        action_name = None
    resource = Resource.query.filter_by(name=resource_name).first()
    if not resource or resource.client != g.client:
        # Resource does not exist or does not belong to this client
        return api_result('error', error='access_denied')
    if action_name:
        action = ResourceAction.query.filter_by(name=action_name, resource=resource).first()
        if not action:
            return api_result('error', error='access_denied')

    # All validations passed. Token is valid for this client and scope. Return with information on the token
    # TODO: Don't return validity. Set the HTTP cache headers instead.
    params = {'validity': 120}  # Period (in seconds) for which this assertion may be cached.
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
    return api_result('ok', **params)


@app.route('/api/1/user/get_by_userid', methods=['POST'])
@requires_client_login
def user_get_by_userid():
    """
    Returns user or organization with the given userid (LastUser internal userid)
    """
    userid = request.form.get('userid')
    if not userid:
        return api_result('error', error='no_userid_provided')
    user = User.query.filter_by(userid=userid).first()
    if user:
        return api_result('ok',
            type='user',
            userid=user.userid,
            name=user.username,
            title=user.fullname)
    else:
        org = Organization.query.filter_by(userid=userid).first()
        if org:
            return api_result('ok',
                type='organization',
                userid=org.userid,
                name=org.name,
                title=org.title)
        else:
            return api_result('error', error='not_found')


@app.route('/api/1/user/get', methods=['POST'])
@requires_client_login
def user_get():
    """
    Returns user with the given username, email address or Twitter id
    """
    name = request.form.get('name')
    if not name:
        return api_result('error', error='no_name_provided')
    user = getuser(name)
    if user:
        return api_result('ok',
            type='user',
            userid=user.userid,
            name=user.username,
            title=user.fullname)
    else:
        return api_result('error', error='not_found')


@app.route('/api/1/org/get_teams', methods=['POST'])
@requires_client_login
def org_team_get():
    """
    Returns a list of teams in the given organization.
    """
    if not g.client.team_access:
        return api_result('error', 'no_team_access')
    org_userids = request.form.getlist('org')
    if not org_userids:
        return api_result('error', 'no_org_provided')
    organizations = Organization.query.filter(Organization.userid.in_(org_userids)).all()
    if not organizations:
        return api_result('error', 'no_such_organization')
    orgteams = {}
    for org in organizations:
        # If client has access to team information, make a list of teams.
        # XXX: Should trusted clients have access anyway? Will this be an abuse
        # of the trusted flag? It was originally meant to only bypass user authorization
        # on login to HasGeek websites as that would have been very confusing to users.
        # XXX: Return user list here?
        if g.client in org.clients_with_team_access():
            orgteams[org.userid] = [{'userid': team.userid, 'title': team.title} for team in org.teams]
    return api_result('ok', org_teams=orgteams)


# --- Token-based resource endpoints ------------------------------------------

@app.route('/api/1/email')
@provides_resource('email')
def resource_email(authtoken, args, files=None):
    """
    Return user's email addresses.
    """
    if 'all' in args and int(args['all']):
        return {'email': unicode(authtoken.user.email),
                'all': [unicode(email) for email in authtoken.user.emails]}
    else:
        return {'email': unicode(authtoken.user.email)}


#@app.route('/api/1/email/add')
#@provides_resource('email/add')
#def resource_email_add(authtoken, args, files=None):
#    """
#    Add an email address to the user's account.
#    """
#    pass
