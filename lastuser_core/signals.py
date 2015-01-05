# -*- coding: utf-8 -*-

from flask.signals import Namespace
from sqlalchemy import event as sqla_event
from .models import User, Organization, Team


lastuser_signals = Namespace()

model_user_new = lastuser_signals.signal('model-user-new')
model_user_edited = lastuser_signals.signal('model-user-edited')
model_user_deleted = lastuser_signals.signal('model-user-deleted')

model_org_new = lastuser_signals.signal('model-org-new')
model_org_edited = lastuser_signals.signal('model-org-edited')
model_org_deleted = lastuser_signals.signal('model-org-deleted')

model_team_new = lastuser_signals.signal('model-team-new')
model_team_edited = lastuser_signals.signal('model-team-edited')
model_team_deleted = lastuser_signals.signal('model-team-deleted')

resource_access_granted = lastuser_signals.signal('resource-access-granted')

# Higher level signals
user_login = lastuser_signals.signal('user-login')
user_logout = lastuser_signals.signal('user-logout')
user_registered = lastuser_signals.signal('user-registered')
user_data_changed = lastuser_signals.signal('user-data-changed')
org_data_changed = lastuser_signals.signal('org-data-changed')
team_data_changed = lastuser_signals.signal('team-data-changed')
session_revoked = lastuser_signals.signal('session-revoked')


@sqla_event.listens_for(User, 'after_insert')
def _user_new(mapper, connection, target):
    model_user_new.send(target)


@sqla_event.listens_for(User, 'after_update')
def _user_edited(mapper, connection, target):
    model_user_edited.send(target)


@sqla_event.listens_for(User, 'after_delete')
def _user_deleted(mapper, connection, target):
    model_user_deleted.send(target)


@sqla_event.listens_for(Organization, 'after_insert')
def _org_new(mapper, connection, target):
    model_org_new.send(target)


@sqla_event.listens_for(Organization, 'after_update')
def _org_edited(mapper, connection, target):
    model_org_edited.send(target)


@sqla_event.listens_for(Organization, 'after_delete')
def _org_deleted(mapper, connection, target):
    model_org_deleted.send(target)


@sqla_event.listens_for(Team, 'after_insert')
def _team_new(mapper, connection, target):
    model_team_new.send(target)


@sqla_event.listens_for(Team, 'after_update')
def _team_edited(mapper, connection, target):
    model_team_edited.send(target)


@sqla_event.listens_for(Team, 'after_delete')
def _team_deleted(mapper, connection, target):
    model_team_deleted.send(target)
