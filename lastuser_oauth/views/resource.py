# -*- coding: utf-8 -*-

from sqlalchemy import or_
from sqlalchemy.orm import defer
from flask import request, g
from coaster import getbool
from coaster.views import jsonp, requestargs

from lastuser_core.models import (db, getuser, User, Organization, AuthToken, Resource,
    ResourceAction, UserClientPermissions, TeamClientPermissions, USER_STATUS,
    UserExternalId, UserEmail)
from lastuser_core import resource_registry
from .. import lastuser_oauth
from .helpers import requires_client_login, requires_user_or_client_login


defer_cols_user = (
    defer('created_at'),
    defer('updated_at'),
    defer('pw_hash'),
    defer('timezone'),
    defer('description'),
    )

defer_cols_org = (
    defer('created_at'),
    defer('updated_at'),
    defer('description'),
    )


def get_userinfo(user, client, scope=[], get_permissions=True):
    if 'id' in scope:
        userinfo = {'userid': user.userid,
                    'username': user.username,
                    'fullname': user.fullname,
                    'timezone': user.timezone,
                    'oldids': [o.userid for o in user.oldids]}
    else:
        userinfo = {}
    if 'email' in scope:
        userinfo['email'] = unicode(user.email)
    if 'phone' in scope:
        userinfo['phone'] = unicode(user.phone)
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
    response.headers['Cache-Control'] = 'no-cache, no-store, max-age=0, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.status_code = 400
    return response


def api_result(status, **params):
    status_code = 200
    if status in (200, 201):
        status_code = status
        status = 'ok'
    params['status'] = status
    response = jsonp(params)
    response.status_code = status_code
    response.headers['Cache-Control'] = 'no-cache, no-store, max-age=0, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    return response


# --- Client access endpoints -------------------------------------------------

@lastuser_oauth.route('/api/1/token/verify', methods=['POST'])
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
        'buid': authtoken.client.user.userid,
        'owner_title': authtoken.client.owner_title,
        'website': authtoken.client.website,
        'key': authtoken.client.key,
        'trusted': authtoken.client.trusted,
        }
    return api_result('ok', **params)


@lastuser_oauth.route('/api/1/user/get_by_userid', methods=['GET', 'POST'])
@requires_user_or_client_login
def user_get_by_userid():
    """
    Returns user or organization with the given userid (Lastuser internal userid)
    """
    userid = request.values.get('userid')
    if not userid:
        return api_result('error', error='no_userid_provided')
    user = User.query.filter_by(userid=userid, status=USER_STATUS.ACTIVE).options(*defer_cols_user).first()
    if user:
        return api_result('ok',
            type='user',
            userid=user.userid,
            buid=user.userid,
            name=user.username,
            title=user.fullname)
    else:
        org = Organization.query.filter_by(userid=userid).options(*defer_cols_org).first()
        if org:
            return api_result('ok',
                type='organization',
                userid=org.userid,
                buid=org.userid,
                name=org.name,
                title=org.title)
        else:
            return api_result('error', error='not_found')


@lastuser_oauth.route('/api/1/user/get_by_userids', methods=['GET', 'POST'])
@requires_user_or_client_login
@requestargs('userid[]')
def user_get_by_userids(userid):
    """
    Returns users and organizations with the given userids (Lastuser internal userid).
    This is identical to get_by_userid but accepts multiple userids and returns a list
    of matching users and organizations
    """
    if not userid:
        return api_result('error', error='no_userid_provided')
    users = User.query.filter(User.userid.in_(userid),
        User.status == USER_STATUS.ACTIVE).options(*defer_cols_user).all()
    orgs = Organization.query.filter(Organization.userid.in_(userid)).options(*defer_cols_org).all()
    return api_result('ok',
        results=[
            {'type': 'user',
             'buid': u.userid,
             'userid': u.userid,
             'name': u.username,
             'title': u.fullname,
             'label': u.pickername} for u in users] + [
            {'type': 'organization',
             'buid': o.userid,
             'userid': o.userid,
             'name': o.name,
             'title': o.fullname,
             'label': o.pickername} for o in orgs]
        )


@lastuser_oauth.route('/api/1/user/get', methods=['GET', 'POST'])
@requires_user_or_client_login
@requestargs('name')
def user_get(name):
    """
    Returns user with the given username, email address or Twitter id
    """
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


@lastuser_oauth.route('/api/1/user/getusers', methods=['GET', 'POST'])
@requires_user_or_client_login
@requestargs('name[]')
def user_getall(name):
    """
    Returns users with the given username, email address or Twitter id
    """
    names = name
    userids = set()  # Dupe checker
    if not names:
        return api_result('error', error='no_name_provided')
    results = []
    for name in names:
        user = getuser(name)
        if user and user.userid not in userids:
            results.append({
                'type': 'user',
                'userid': user.userid,
                'buid': user.userid,
                'name': user.username,
                'title': user.fullname,
                'label': user.pickername,
                })
            userids.add(user.userid)
    if not results:
        return api_result('error', error='not_found')
    else:
        return api_result('ok', results=results)


@lastuser_oauth.route('/api/1/user/autocomplete', methods=['GET', 'POST'])
@requires_user_or_client_login
def user_autocomplete():
    """
    Returns users (userid, username, fullname, twitter, github or email) matching the search term.
    """
    # Escape the '%' and '_' wildcards in SQL LIKE clauses.
    # Some SQL dialects respond to '[' and ']', so remove them.
    q = request.values.get('q', '').replace('%', '\\%').replace('_', '\\_').replace('[', '').replace(']', '')
    if not q:
        return api_result('error', error='no_query_provided')
    q += '%'
    # Use User._username since 'username' is a hybrid property that checks for validity
    # before passing on to _username, the actual column name on the model
    users = User.query.filter(User.status == USER_STATUS.ACTIVE,
        or_(  # Match against userid (exact value only), fullname or username, case insensitive
            User.userid == q[:-1],
            db.func.lower(User.fullname).like(db.func.lower(q)),
            db.func.lower(User._username).like(db.func.lower(q))
            )
        ).options(*defer_cols_user).limit(100).all()  # Limit to 100 results
    if q.startswith('@'):
        # Add Twitter/GitHub accounts to the head of results
        # TODO: Move this query to a login provider class method
        users = User.query.filter(User.status == USER_STATUS.ACTIVE, User.id.in_(
            db.session.query(UserExternalId.user_id).filter(
                UserExternalId.service.in_([u'twitter', u'github']),
                db.func.lower(UserExternalId.username).like(db.func.lower(q[1:]))
            ).subquery())).options(*defer_cols_user).limit(100).all() + users
    elif '@' in q:
        users = User.query.filter(User.status == USER_STATUS.ACTIVE, User.id.in_(
            db.session.query(UserEmail.user_id).filter(
                db.func.lower(UserEmail.email).like(db.func.lower(q))
            ).subquery())).options(*defer_cols_user).limit(100).all() + users
    result = [{
        'userid': u.userid,
        'buid': u.userid,
        'name': u.username,
        'title': u.fullname,
        'label': u.pickername} for u in users]
    return api_result('ok', users=result)


# This is org/* instead of organizations/* because it's a client resource. TODO: Reconsider
@lastuser_oauth.route('/api/1/org/get_teams', methods=['GET', 'POST'])
@requires_client_login
def org_team_get():
    """
    Returns a list of teams in the given organization.
    """
    if not g.client.team_access:
        return api_result('error', error='no_team_access')
    org_userids = request.values.getlist('org')
    if not org_userids:
        return api_result('error', error='no_org_provided')
    organizations = Organization.query.filter(Organization.userid.in_(org_userids)).options(*defer_cols_org).all()
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

@lastuser_oauth.route('/api/1/id')
@resource_registry.resource('id', u"Read your name and username")
def resource_id(authtoken, args, files=None):
    """
    Return user's id
    """
    if 'all' in args and getbool(args['all']):
        return get_userinfo(authtoken.user, authtoken.client, scope=authtoken.scope, get_permissions=True)
    else:
        return get_userinfo(authtoken.user, authtoken.client, scope=['id'], get_permissions=False)


@lastuser_oauth.route('/api/1/email')
@resource_registry.resource('email', u"Read your email address")
def resource_email(authtoken, args, files=None):
    """
    Return user's email addresses.
    """
    if 'all' in args and getbool(args['all']):
        return {'email': unicode(authtoken.user.email),
                'all': [unicode(email) for email in authtoken.user.emails]}
    else:
        return {'email': unicode(authtoken.user.email)}


@lastuser_oauth.route('/api/1/email/add', methods=['POST'])
@resource_registry.resource('email/add', u"Add an email address to your profile")
def resource_email_add(authtoken, args, files=None):
    """
    TODO: Add an email address to the user's profile.
    """
    email = args['email']
    return {'email': email}  # TODO


@lastuser_oauth.route('/api/1/phone')
@resource_registry.resource('phone', u"Read your phone number")
def resource_phone(authtoken, args, files=None):
    """
    Return user's phone numbers.
    """
    if 'all' in args and getbool(args['all']):
        return {'phone': unicode(authtoken.user.phone),
                'all': [unicode(phone) for phone in authtoken.user.phones]}
    else:
        return {'phone': unicode(authtoken.user.phone)}


@lastuser_oauth.route('/api/1/user/externalids')
@resource_registry.resource('user/externalids', u"Read user's login providers' data", trusted=True)
def resource_login_providers(authtoken, args, files=None):
    """
    Return user's login providers' data.
    """
    service = args.get('service')
    response = {}
    for extid in authtoken.user.externalids:
        if service is None or extid.service == service:
            response[extid.service] = {
                "userid": unicode(extid.userid),
                "username": unicode(extid.username),
                "oauth_token": unicode(extid.oauth_token),
                "oauth_token_secret": unicode(extid.oauth_token_secret),
                "oauth_token_type": unicode(extid.oauth_token_type)
            }
    return response


@lastuser_oauth.route('/api/1/organizations')
@resource_registry.resource('organizations', u"Read the organizations you are a member of")
def resource_organizations(authtoken, args, files=None):
    """
    Return user's organizations and teams.
    """
    return get_userinfo(authtoken.user, authtoken.client, scope=['organizations'], get_permissions=False)


@lastuser_oauth.route('/api/1/notice/send')
@resource_registry.resource('notice/send', u"Send you notifications")
def resource_notice_send(authtoken, args, files=None):
    pass
