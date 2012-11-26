# -*- coding: utf-8 -*-

from sqlalchemy import or_
from flask import request, g
from coaster import getbool
from coaster.views import jsonp

from lastuserapp import app
from lastuserapp.models import (db, getuser, User, Organization, AuthToken, Resource,
    ResourceAction, UserClientPermissions, TeamClientPermissions)
from lastuserapp.views.helpers import requires_client_login, requires_user_or_client_login
from lastuserapp.registry import registry


def get_userinfo(user, client, scope=[], get_permissions=True):
    if 'id' in scope:
        userinfo = {'userid': user.userid,
                    'username': user.username,
                    'fullname': user.fullname,
                    'timezone': user.timezone}
    else:
        userinfo = {}
    if 'email' in scope:
        userinfo['email'] = unicode(user.email)
    if 'organizations' in scope:
        userinfo['organizations'] = {
            'owner': [{'userid': org.userid, 'name': org.name, 'title': org.title} for org in user.organizations_owned()],
            'member': [{'userid': org.userid, 'name': org.name, 'title': org.title} for org in user.organizations()],
            }
        userinfo['teams'] = [{'userid': team.userid,
                              'title': team.title,
                              'org': team.org.userid,
                              'owners': team == team.org.owners} for team in user.teams]
    if get_permissions:
        if client.user:
            perms = UserClientPermissions.query.filter_by(user=user, client=client).first()
            if perms:
                userinfo['permissions'] = perms.access_permissions.split(u' ')
        else:
            perms = TeamClientPermissions.query.filter_by(client=client).filter(
                TeamClientPermissions.team_id.in_([team.id for team in user.teams])).all()
            permsset = set()
            for permob in perms:
                permsset.update(permob.access_permissions.split(u' '))
            userinfo['permissions'] = sorted(permsset)
    return userinfo


def resource_error(error, description=None, uri=None):
    params = {'status': 'error', 'error': error}
    if description:
        params['error_description'] = description
    if uri:
        params['error_uri'] = uri

    response = jsonp(params)
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Pragma'] = 'no-cache'
    response.status_code = 400
    return response


def api_result(status, **params):
    params['status'] = status
    response = jsonp(params)
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
        params['userinfo'] = get_userinfo(authtoken.user, g.client, scope=authtoken.scope)
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
    Returns user or organization with the given userid (Lastuser internal userid)
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


@app.route('/api/1/user/autocomplete')
@requires_user_or_client_login
def user_autocomplete():
    """
    Returns users (id and name only) matching the search term.
    """
    # Don't allow a % anywhere but at the end
    q = request.args.get('q', '').replace('%', '')
    if not q:
        return api_result('error', error='no_query_provided')
    q += '%'
    # Use User._username since 'username' is a hybrid property that checks for validity
    # before passing on to _username, the actual column name on the model
    users = db.session.query(User.userid, User.fullname, User._username).filter(
        or_(
            User.fullname.like(q),
            User._username.like(q)
            )
        ).limit(10).all()
    result = [{
            'userid': u.userid,
            'buid': u.userid,
            'name': '%s (~%s)' % (u.fullname, u._username) if u._username else u.fullname}
        for u in users]
    return api_result('ok', users=result)


# This is org/* instead of organizations/* because it's a client resource. TODO: Reconsider
@app.route('/api/1/org/get_teams', methods=['POST'])
@requires_client_login
def org_team_get():
    """
    Returns a list of teams in the given organization.
    """
    if not g.client.team_access:
        return api_result('error', error='no_team_access')
    org_userids = request.form.getlist('org')
    if not org_userids:
        return api_result('error', error='no_org_provided')
    organizations = Organization.query.filter(Organization.userid.in_(org_userids)).all()
    if not organizations:
        return api_result('error', error='no_such_organization')
    orgteams = {}
    for org in organizations:
        # If client has access to team information, make a list of teams.
        # XXX: Should trusted clients have access anyway? Will this be an abuse
        # of the trusted flag? It was originally meant to only bypass user authorization
        # on login to HasGeek websites as that would have been very confusing to users.
        # XXX: Return user list here?
        if g.client in org.clients_with_team_access():
            orgteams[org.userid] = [{'userid': team.userid,
                                     'org': org.userid,
                                     'title': team.title,
                                     'owners': team == org.owners} for team in org.teams]
    return api_result('ok', org_teams=orgteams)


# --- Token-based resource endpoints ------------------------------------------

@app.route('/api/1/id')
@registry.resource('id', u'Read your name and username')
def resource_id(authtoken, args, files=None):
    """
    Return user's id
    """
    return get_userinfo(authtoken.user, authtoken.client, scope=['id'], get_permissions=False)


@app.route('/api/1/email')
@registry.resource('email', u'Read your email address')
def resource_email(authtoken, args, files=None):
    """
    Return user's email addresses.
    """
    if 'all' in args and getbool(args['all']):
        return {'email': unicode(authtoken.user.email),
                'all': [unicode(email) for email in authtoken.user.emails]}
    else:
        return {'email': unicode(authtoken.user.email)}


@app.route('/api/1/email/add', methods=['POST'])
@registry.resource('email/add', u'Add an email address to your profile')
def resource_email_add(authtoken, args, files=None):
    """
    Add an email address to the user's profile.
    """
    email = args['email']
    return {'email': email}  # TODO


@app.route('/api/1/organizations')
@registry.resource('organizations', u'Read the organizations you are a member of')
def resource_organizations(authtoken, args, files=None):
    """
    Return user's organizations and teams.
    """
    return get_userinfo(authtoken.user, authtoken.client, scope=['organizations'], get_permissions=False)


@app.route('/api/1/notice/send')
@registry.resource('notice/send', u'Send you notifications')
def resource_notice_send(authtoken, args, files=None):
    pass
