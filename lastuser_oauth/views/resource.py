# -*- coding: utf-8 -*-

from urlparse import urlparse
from werkzeug.exceptions import BadRequest
from flask import request, g, abort, render_template, jsonify
from coaster.utils import getbool
from coaster.views import requestargs, jsonp
from baseframe import _, __

from lastuser_core.models import (db, getuser, User, Organization, AuthToken, Resource,
    ResourceAction, UserClientPermissions, TeamClientPermissions, UserSession, ClientCredential)
from lastuser_core import resource_registry
from .. import lastuser_oauth
from .helpers import requires_client_login, requires_user_or_client_login, requires_client_id_or_user_or_client_login


def get_userinfo(user, client, scope=[], session=None, get_permissions=True):

    teams = {}

    if '*' in scope or 'id' in scope or 'id/*' in scope:
        userinfo = {'userid': user.userid,
                    'uuid': user.uuid,
                    'username': user.username,
                    'fullname': user.fullname,
                    'timezone': user.timezone,
                    'avatar': user.avatar,
                    'oldids': [o.userid for o in user.oldids],
                    'olduuids': [o.uuid for o in user.oldids]}
    else:
        userinfo = {}

    if session:
        userinfo['sessionid'] = session.buid

    if '*' in scope or 'email' in scope or 'email/*' in scope:
        userinfo['email'] = unicode(user.email)
    if '*' in scope or 'phone' in scope or 'phone/*' in scope:
        userinfo['phone'] = unicode(user.phone)
    if '*' in scope or 'organizations' in scope or 'organizations/*' in scope:
        userinfo['organizations'] = {
            'owner': [{'userid': org.userid, 'uuid': org.uuid, 'name': org.name, 'title': org.title, 'domain': org.domain} for org in user.organizations_owned()],
            'member': [{'userid': org.userid, 'uuid': org.uuid, 'name': org.name, 'title': org.title, 'domain': org.domain} for org in user.organizations_memberof()],
            'all': [{'userid': org.userid, 'uuid': org.uuid, 'name': org.name, 'title': org.title, 'domain': org.domain} for org in user.organizations()],
            }

    if '*' in scope or 'organizations' in scope or 'teams' in scope or 'organizations/*' in scope or 'teams/*' in scope:
        for team in user.teams:
            teams[team.userid] = {
                'userid': team.userid,
                'uuid': team.uuid,
                'title': team.title,
                'org': team.org.userid,
                'org_uuid': team.org.uuid,
                'domain': team.domain,
                'owners': team == team.org.owners,
                'members': team == team.org.members,
                'member': True}

    if '*' in scope or 'teams' in scope or 'teams/*' in scope:
        for org in user.organizations_owned():
            for team in org.teams:
                if team.userid not in teams:
                    teams[team.userid] = {
                        'userid': team.userid,
                        'uuid': team.uuid,
                        'title': team.title,
                        'org': team.org.userid,
                        'org_uuid': team.org.uuid,
                        'domain': team.domain,
                        'owners': team == team.org.owners,
                        'members': team == team.org.members,
                        'member': False}

    if teams:
        userinfo['teams'] = teams.values()

    if get_permissions:
        if client.user:
            perms = UserClientPermissions.query.filter_by(user=user, client=client).first()
            if perms:
                userinfo['permissions'] = perms.access_permissions.split(u' ')
        else:
            permsset = set()
            if user.teams:
                perms = TeamClientPermissions.query.filter_by(client=client).filter(
                    TeamClientPermissions.team_id.in_([team.id for team in user.teams])).all()
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

    response = jsonify(params)
    response.headers['Cache-Control'] = 'private, no-cache, no-store, max-age=0, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.status_code = 400
    return response


def api_result(status, _jsonp=False, **params):
    status_code = 200
    if status in (200, 201):
        status_code = status
        status = 'ok'
    params['status'] = status
    if _jsonp:
        response = jsonp(params)
    else:
        response = jsonify(params)
    response.status_code = status_code
    response.headers['Cache-Control'] = 'private, no-cache, no-store, max-age=0, must-revalidate'
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

    authtoken = AuthToken.get(token=token)
    if not authtoken:
        # No such auth token
        return api_result('error', error='no_token')
    if (g.client.namespace + ':' + client_resource not in authtoken.effective_scope) and (
            g.client.namespace + ':*' not in authtoken.effective_scope):
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
    if resource_name != '*':
        resource = Resource.get(resource_name, client=g.client)
        if not resource:
            # Resource does not exist or does not belong to this client
            return api_result('error', error='access_denied')
        if action_name and action_name != '*':
            action = ResourceAction.query.filter_by(name=action_name, resource=resource).first()
            if not action:
                return api_result('error', error='access_denied')

    # All validations passed. Token is valid for this client and scope. Return with information on the token
    # TODO: Don't return validity. Set the HTTP cache headers instead.
    params = {'validity': 120}  # Period (in seconds) for which this assertion may be cached.
    if authtoken.user:
        params['userinfo'] = get_userinfo(authtoken.user, g.client, scope=authtoken.effective_scope)
    params['clientinfo'] = {
        'title': authtoken.client.title,
        'userid': authtoken.client.owner.userid,
        'buid': authtoken.client.owner.userid,
        'uuid': authtoken.client.owner.uuid,
        'owner_title': authtoken.client.owner.pickername,
        'website': authtoken.client.website,
        'key': authtoken.client.key,
        'trusted': authtoken.client.trusted,
        }
    return api_result('ok', **params)


@lastuser_oauth.route('/api/1/token/get_scope', methods=['POST'])
@requires_client_login
def token_get_scope():
    token = request.form.get('access_token')
    if not token:
        # No token specified by caller
        return resource_error('no_token')

    authtoken = AuthToken.get(token=token)
    if not authtoken:
        # No such auth token
        return api_result('error', error='no_token')

    client_resources = []
    nsprefix = g.client.namespace + ':'
    for item in authtoken.effective_scope:
        if item.startswith(nsprefix):
            client_resources.append(item[len(nsprefix):])

    if not client_resources:
        return api_result('error', error='no_access')

    # All validations passed. Token is valid for this client. Return with information on the token
    # TODO: Don't return validity. Set the HTTP cache headers instead.
    params = {'validity': 120}  # Period (in seconds) for which this assertion may be cached.
    if authtoken.user:
        params['userinfo'] = get_userinfo(authtoken.user, g.client, scope=authtoken.effective_scope)
    params['clientinfo'] = {
        'title': authtoken.client.title,
        'userid': authtoken.client.owner.userid,
        'buid': authtoken.client.owner.userid,
        'uuid': authtoken.client.owner.uuid,
        'owner_title': authtoken.client.owner.pickername,
        'website': authtoken.client.website,
        'key': authtoken.client.key,
        'trusted': authtoken.client.trusted,
        'scope': client_resources,
        }
    return api_result('ok', **params)


@lastuser_oauth.route('/api/1/resource/sync', methods=['POST'])
@requires_client_login
def sync_resources():
    resources = request.get_json().get('resources', [])
    actions_list = {}
    results = {}

    for name in resources:
        if '/' in name:
            parts = name.split('/')
            if len(parts) != 2:
                results[name] = {'status': 'error', 'error': _(u"Invalid resource name {name}").format(name=name)}
                continue
            resource_name, action_name = parts
        else:
            resource_name = name
            action_name = None
        description = resources[name].get('description')
        siteresource = getbool(resources[name].get('siteresource'))
        restricted = getbool(resources[name].get('restricted'))
        actions_list.setdefault(resource_name, [])
        resource = Resource.get(name=resource_name, client=g.client)
        if resource:
            results[resource.name] = {'status': 'exists', 'actions': {}}
            if not action_name and resource.description != description:
                resource.description = description
                results[resource.name]['status'] = 'updated'
            if not action_name and resource.siteresource != siteresource:
                resource.siteresource = siteresource
                results[resource.name]['status'] = 'updated'
            if not action_name and resource.restricted != restricted:
                resource.restricted = restricted
                results[resource.name]['status'] = 'updated'
        else:
            resource = Resource(client=g.client, name=resource_name,
                title=resources.get(resource_name, {}).get('title') or resource_name.title(),
                description=resources.get(resource_name, {}).get('description') or u'')
            db.session.add(resource)
            results[resource.name] = {'status': 'added', 'actions': {}}

        if action_name:
            if action_name not in actions_list[resource_name]:
                actions_list[resource_name].append(action_name)
            action = resource.get_action(name=action_name)
            if action:
                if description != action.description:
                    action.description = description
                    results[resource.name]['actions'][action.name] = {'status': 'updated'}
                else:
                    results[resource.name]['actions'][action.name] = {'status': 'exists'}
            else:
                # FIXME: What is "title" here? This assignment doesn't seem right
                action = ResourceAction(resource=resource, name=action_name,
                    title=resources[name].get('title') or action_name.title() + " " + resource.title,
                    description=description)
                db.session.add(action)
                results[resource.name]['actions'][action.name] = {'status': 'added'}

    # Deleting resources & actions not defined in client application.
    for resource_name in actions_list:
        resource = Resource.get(name=resource_name, client=g.client)
        actions = ResourceAction.query.filter(
            ~ResourceAction.name.in_(actions_list[resource_name]), ResourceAction.resource == resource)
        for action in actions.all():
            results[resource_name]['actions'][action.name] = {'status': 'deleted'}
        actions.delete(synchronize_session='fetch')
    del_resources = Resource.query.filter(
        ~Resource.name.in_(actions_list.keys()), Resource.client == g.client)
    for resource in del_resources.all():
        ResourceAction.query.filter_by(resource=resource).delete(synchronize_session='fetch')
        results[resource.name] = {'status': 'deleted'}
    del_resources.delete(synchronize_session='fetch')

    db.session.commit()

    return api_result('ok', results=results)


@lastuser_oauth.route('/api/1/user/get_by_userid', methods=['GET', 'POST'])
@requires_user_or_client_login
def user_get_by_userid():
    """
    Returns user or organization with the given userid (Lastuser internal userid)
    """
    userid = request.values.get('userid')
    if not userid:
        return api_result('error', error='no_userid_provided')
    user = User.get(userid=userid, defercols=True)
    if user:
        return api_result('ok',
            _jsonp=True,
            type='user',
            userid=user.userid,
            buid=user.userid,
            uuid=user.uuid,
            name=user.username,
            title=user.fullname,
            label=user.pickername,
            timezone=user.timezone,
            oldids=[o.userid for o in user.oldids],
            olduuids=[o.uuid for o in user.oldids])
    else:
        org = Organization.get(userid=userid, defercols=True)
        if org:
            return api_result('ok',
                _jsonp=True,
                type='organization',
                userid=org.userid,
                buid=org.userid,
                uuid=org.uuid,
                name=org.name,
                title=org.title,
                label=org.pickername)
    return api_result('error', error='not_found', _jsonp=True)


@lastuser_oauth.route('/api/1/user/get_by_userids', methods=['GET', 'POST'])
@requires_client_id_or_user_or_client_login
@requestargs('userid[]')
def user_get_by_userids(userid):
    """
    Returns users and organizations with the given userids (Lastuser internal userid).
    This is identical to get_by_userid but accepts multiple userids and returns a list
    of matching users and organizations
    """
    if not userid:
        return api_result('error', error='no_userid_provided', _jsonp=True)
    users = User.all(userids=userid)
    orgs = Organization.all(userids=userid)
    return api_result('ok',
        _jsonp=True,
        results=[
            {'type': 'user',
             'buid': u.userid,
             'userid': u.userid,
             'uuid': u.uuid,
             'name': u.username,
             'title': u.fullname,
             'label': u.pickername,
             'timezone': u.timezone,
             'oldids': [o.userid for o in u.oldids],
             'olduuids': [o.uuid for o in u.oldids]} for u in users] + [
            {'type': 'organization',
             'buid': o.userid,
             'userid': o.userid,
             'uuid': o.uuid,
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
            buid=user.userid,
            uuid=user.uuid,
            name=user.username,
            title=user.fullname,
            label=user.pickername,
            timezone=user.timezone,
            oldids=[o.userid for o in user.oldids],
            olduuids=[o.uuid for o in user.oldids])
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
                'uuid': user.uuid,
                'name': user.username,
                'title': user.fullname,
                'label': user.pickername,
                'timezone': user.timezone,
                'oldids': [o.userid for o in user.oldids],
                'olduuids': [o.uuid for o in user.oldids],
                })
            userids.add(user.userid)
    if not results:
        return api_result('error', error='not_found')
    else:
        return api_result('ok', results=results)


@lastuser_oauth.route('/api/1/user/autocomplete', methods=['GET', 'POST'])
@requires_client_id_or_user_or_client_login
def user_autocomplete():
    """
    Returns users (userid, username, fullname, twitter, github or email) matching the search term.
    """
    q = request.values.get('q', '')
    if not q:
        return api_result('error', error='no_query_provided')
    users = User.autocomplete(q)
    result = [{
        'userid': u.userid,
        'buid': u.userid,
        'uuid': u.uuid,
        'name': u.username,
        'title': u.fullname,
        'label': u.pickername} for u in users]
    return api_result('ok', users=result, _jsonp=True)


# This is org/* instead of organizations/* because it's a client resource. TODO: Reconsider
# DEPRECATED, to be removed soon
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
    organizations = Organization.all(userids=org_userids)
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
                                     'uuid': team.uuid,
                                     'org': org.userid,
                                     'org_uuid': org.uuid,
                                     'title': team.title,
                                     'owners': team == org.owners} for team in org.teams]
    return api_result('ok', org_teams=orgteams)


# --- Public endpoints --------------------------------------------------------

@lastuser_oauth.route('/api/1/login/beacon.html')
@requestargs('client_id', 'login_url')
def login_beacon_iframe(client_id, login_url):
    cred = ClientCredential.get(client_id)
    client = cred.client if cred else None
    if client is None:
        abort(404)
    if not client.host_matches(login_url):
        abort(400)
    return render_template('login_beacon.html', client=client, login_url=login_url), 200, {
        'Expires': 'Fri, 01 Jan 1990 00:00:00 GMT',
        'Cache-Control': 'private, max-age=86400'
        }


@lastuser_oauth.route('/api/1/login/beacon.json')
@requestargs('client_id')
def login_beacon_json(client_id):
    cred = ClientCredential.get(client_id)
    client = cred.client if cred else None
    if client is None:
        abort(404)
    if g.user:
        token = client.authtoken_for(g.user)
    else:
        token = None
    response = jsonify({
        'hastoken': True if token else False
        })
    response.headers['Expires'] = 'Fri, 01 Jan 1990 00:00:00 GMT'
    response.headers['Cache-Control'] = 'private, max-age=300'
    return response


# --- Token-based resource endpoints ------------------------------------------

@lastuser_oauth.route('/api/1/id')
@resource_registry.resource('id', __(u"Read your name and basic profile data"))
def resource_id(authtoken, args, files=None):
    """
    Return user's id
    """
    if 'all' in args and getbool(args['all']):
        return get_userinfo(authtoken.user, authtoken.client, scope=authtoken.effective_scope, get_permissions=True)
    else:
        return get_userinfo(authtoken.user, authtoken.client, scope=['id'], get_permissions=False)


@lastuser_oauth.route('/api/1/session/verify', methods=['POST'])
@resource_registry.resource('session/verify', __(u"Verify user session"), scope='id')
def session_verify(authtoken, args, files=None):
    sessionid = args['sessionid']
    session = UserSession.authenticate(buid=sessionid)
    if session and session.user == authtoken.user:
        session.access(client=authtoken.client)
        db.session.commit()
        return {
            'active': True,
            'sessionid': session.buid,
            'userid': session.user.userid,
            'user_uuid': session.user.uuid,
            'sudo': session.has_sudo,
            }
    else:
        return {'active': False}


@lastuser_oauth.route('/api/1/avatar/edit', methods=['POST'])
@resource_registry.resource('avatar/edit', __(u"Update your profile picture"))
def resource_avatar_edit(authtoken, args, files=None):
    """
    Set a user's avatar image
    """
    avatar = args['avatar']
    parsed = urlparse(avatar)
    if parsed.scheme == 'https' and parsed.netloc:
        # Accept any properly formatted URL.
        # TODO: Add better validation.
        authtoken.user.avatar = avatar
        return {'avatar': authtoken.user.avatar}
    else:
        raise BadRequest(_("Invalid avatar URL"))


@lastuser_oauth.route('/api/1/email')
@resource_registry.resource('email', __(u"Read your email address"))
def resource_email(authtoken, args, files=None):
    """
    Return user's email addresses.
    """
    if 'all' in args and getbool(args['all']):
        return {'email': unicode(authtoken.user.email),
                'all': [unicode(email) for email in authtoken.user.emails if not email.private]}
    else:
        return {'email': unicode(authtoken.user.email)}


@lastuser_oauth.route('/api/1/email/add', methods=['POST'])
@resource_registry.resource('email/add', __(u"Add an email address to your profile"))
def resource_email_add(authtoken, args, files=None):
    """
    TODO: Add an email address to the user's profile.
    """
    email = args['email']
    return {'email': email}  # TODO


@lastuser_oauth.route('/api/1/phone')
@resource_registry.resource('phone', __(u"Read your phone number"))
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
@resource_registry.resource('user/externalids',
    __(u"Access your external account information such as Twitter and Google"), trusted=True)
def resource_login_providers(authtoken, args, files=None):
    """
    Return user's login providers' data.
    """
    service = args.get('service')
    response = {}
    for extid in authtoken.user.externalids:
        if service is None or extid.service == service:
            response[extid.service] = {
                'userid': unicode(extid.userid),
                'username': unicode(extid.username),
                'oauth_token': unicode(extid.oauth_token),
                'oauth_token_secret': unicode(extid.oauth_token_secret),
                'oauth_token_type': unicode(extid.oauth_token_type)
            }
    return response


@lastuser_oauth.route('/api/1/user/new', methods=['POST'])
@resource_registry.resource('user/new', __(u"Create a new user account"), trusted=True)
def resource_user_new(authtoken, args, files=None):
    # Set User.client to authtoken.client and User.referrer to authtoken.user
    pass


@lastuser_oauth.route('/api/1/organizations')
@resource_registry.resource('organizations', __(u"Read the organizations you are a member of"))
def resource_organizations(authtoken, args, files=None):
    """
    Return user's organizations and teams that they are a member of.
    """
    return get_userinfo(authtoken.user, authtoken.client, scope=['organizations'], get_permissions=False)


@lastuser_oauth.route('/api/1/organizations/new', methods=['POST'])
@resource_registry.resource('organizations/new', __(u"Create a new organization"), trusted=True)
def resource_organizations_new(authtoken, args, files=None):
    pass


@lastuser_oauth.route('/api/1/organizations/edit', methods=['POST'])
@resource_registry.resource('organizations/edit', __(u"Edit your organizations"), trusted=True)
def resource_organizations_edit(authtoken, args, files=None):
    pass


@lastuser_oauth.route('/api/1/teams')
@resource_registry.resource('teams', __(u"Read the list of teams in your organizations"))
def resource_teams(authtoken, args, files=None):
    """
    Return user's organizations' teams.
    """
    return get_userinfo(authtoken.user, authtoken.client, scope=['teams'], get_permissions=False)


@lastuser_oauth.route('/api/1/teams/new', methods=['POST'])
@resource_registry.resource('teams/new', __(u"Create a new team in your organizations"), trusted=True)
def resource_teams_new(authtoken, args, files=None):
    pass


# GET to read member list, POST to write to it
@lastuser_oauth.route('/api/1/teams/edit', methods=['GET', 'POST'])
@resource_registry.resource('teams/edit', __(u"Edit your organizations' teams"), trusted=True)
def resource_teams_edit(authtoken, args, files=None):
    pass


@lastuser_oauth.route('/api/1/notice/send')
@resource_registry.resource('notice/send', __(u"Send you notifications"))
def resource_notice_send(authtoken, args, files=None):
    pass
