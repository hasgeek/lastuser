# -*- coding: utf-8 -*-

import requests
from flask.ext.rq import job
from lastuser_core.models import AuthToken
from lastuser_core.signals import user_data_changed, org_data_changed, team_data_changed


user_changes_to_notify = set(['merge', 'profile', 'email', 'email-claim', 'email-delete',
    'phone', 'phone-claim', 'phone-delete'])


@user_data_changed.connect
def notify_user_data_changed(user, changes):
    """
    Look for changes that need to be notified to client apps,
    then look for apps that have user data and accept notifications,
    and then notify them.
    """
    if user_changes_to_notify & set(changes):
        # We have changes that apps need to hear about
        for token in AuthToken.query.filter_by(user=user).all():
            if token.client.notification_uri:
                notify_changes = []
                for change in changes:
                    if change in ['merge', 'profile']:
                        notify_changes.append(change)
                    elif change in ['email', 'email-claim', 'email-delete']:
                        if 'email' in token.scope:
                            notify_changes.append(change)
                    elif change in ['phone', 'phone-claim', 'phone-delete']:
                        if 'phone' in token.scope:
                            notify_changes.append(change)
                if notify_changes:
                    send_notice.delay(token.client.notification_uri, data=
                        {'userid': user.userid,
                        'type': 'user',
                        'changes': notify_changes})


@org_data_changed.connect
def notify_org_data_changed(org, user, changes, team=None):
    """
    Like :func:`notify_user_data_changed`, except we'll also look at
    all other owners of this org to find apps that need to be notified.
    """
    client_users = {}
    if team is not None:
        team_access = set(org.clients_with_team_access()) | set(user.clients_with_team_access())
    else:
        team_access = []
    for token in AuthToken.query.filter(AuthToken.user_id.in_([u.id for u in org.owners.users])).all():
        if 'organizations' in token.scope and token.client.notification_uri:
            if team is not None:
                if token.client not in team_access:
                    continue
            client_users.setdefault(token.client, []).append(token.user)
    # Now we have a list of clients to notify and a list of users to notify them with
    for client, users in client_users.items():
        if user in users:
            notify_user = user
        else:
            notify_user = users[0]  # First user available
        send_notice.delay(client.notification_uri, data=
            {'userid': notify_user.userid,
            'type': 'org' if team is None else 'team',
            'orgid': org.userid,
            'teamid': team.userid if team is not None else None,
            'changes': changes,
            })


@team_data_changed.connect
def notify_team_data_changed(team, user, changes):
    """
    Pass-through function that calls :func:`notify_org_data_changed`.
    """
    notify_org_data_changed(team.org, user=user, changes=['team-' + c for c in changes], team=team)


@job("lastuser")
def send_notice(url, params=None, data=None, method='POST'):
    requests.request(method, url, params=params, data=data)
