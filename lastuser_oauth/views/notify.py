# -*- coding: utf-8 -*-

import requests
from flask_rq import job
from lastuser_core.models import AuthToken
from lastuser_core.signals import user_data_changed, org_data_changed, team_data_changed, session_revoked


user_changes_to_notify = set(['merge', 'profile', 'email', 'email-claim', 'email-delete',
    'email-update-primary', 'phone', 'phone-claim', 'phone-delete', 'team-membership'])


@session_revoked.connect
def notify_session_revoked(session):
    for client in session.clients:
        if client.notification_uri:
            send_notice.delay(client.notification_uri, data={
                'userid': session.user.buid,  # XXX: Deprecated parameter
                'buid': session.user.buid,
                'type': 'user',
                'changes': ['logout'],
                'sessionid': session.buid
                })


@user_data_changed.connect
def notify_user_data_changed(user, changes):
    """
    Look for changes that need to be notified to client apps,
    then look for apps that have user data and accept notifications,
    and then notify them.
    """
    if user_changes_to_notify & set(changes):
        # We have changes that apps need to hear about
        for token in user.authtokens:
            if token.is_valid() and token.client.notification_uri:
                tokenscope = token.effective_scope
                notify_changes = []
                for change in changes:
                    if change in ['merge', 'profile']:
                        notify_changes.append(change)
                    elif change in ['email', 'email-claim', 'email-delete', 'email-update-primary']:
                        if 'email' in tokenscope or 'email/*' in tokenscope:
                            notify_changes.append(change)
                    elif change in ['phone', 'phone-claim', 'phone-delete']:
                        if 'phone' in tokenscope or 'phone/*' in tokenscope:
                            notify_changes.append(change)
                    elif change in ['team-membership']:
                        if ('organizations' in tokenscope or 'organizations/*' in tokenscope or
                                'teams' in tokenscope or 'teams/*' in tokenscope):
                            notify_changes.append(change)
                if notify_changes:
                    send_notice.delay(token.client.notification_uri, data={
                        'userid': user.buid,  # XXX: Deprecated parameter
                        'buid': user.buid,
                        'type': 'user',
                        'changes': notify_changes
                        })


@org_data_changed.connect
def notify_org_data_changed(org, user, changes, team=None):
    """
    Like :func:`notify_user_data_changed`, except we'll also look at
    all other owners of this org to find apps that need to be notified.
    """
    client_users = {}
    if team is not None:
        team_access = set(org.clients_with_team_access()) | (set(user.clients_with_team_access()) if user else set())
    else:
        team_access = []
    for token in AuthToken.all(users=org.owners.users):
        if ('organizations' in token.effective_scope or 'organizations/*' in token.effective_scope) and token.client.notification_uri and token.is_valid():
            if team is not None:
                if token.client not in team_access:
                    continue
            client_users.setdefault(token.client, []).append(token.user)
    # Now we have a list of clients to notify and a list of users to notify them with
    for client, users in client_users.items():
        if user is not None and user in users:
            notify_user = user
        else:
            notify_user = users[0]  # First user available
        send_notice.delay(client.notification_uri, data={
            'userid': notify_user.buid,  # XXX: Deprecated parameter
            'buid': notify_user.buid,
            'type': 'org' if team is None else 'team',
            'orgid': org.buid,
            'teamid': team.buid if team is not None else None,
            'changes': changes,
            })


@team_data_changed.connect
def notify_team_data_changed(team, user, changes):
    """
    Pass-through function that calls :func:`notify_org_data_changed`.
    """
    notify_org_data_changed(team.org, user=user, changes=['team-' + c for c in changes], team=team)


@job('lastuser')
def send_notice(url, params=None, data=None, method='POST'):
    requests.request(method, url, params=params, data=data)
