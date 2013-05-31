# -*- coding: utf-8 -*-

from flask.signals import Namespace
from sqlalchemy import event as sqla_event
from .models import User, Organization, Team


lastuser_signals = Namespace()

user_new = lastuser_signals.signal('user-new')
user_edited = lastuser_signals.signal('user-edited')
user_deleted = lastuser_signals.signal('user-deleted')

org_new = lastuser_signals.signal('org-new')
org_edited = lastuser_signals.signal('org-edited')
org_deleted = lastuser_signals.signal('org-deleted')

team_new = lastuser_signals.signal('team-new')
team_edited = lastuser_signals.signal('team-edited')
team_deleted = lastuser_signals.signal('team-deleted')

resource_access_granted = lastuser_signals.signal('resource-access-granted')


@sqla_event.listens_for(User, 'after_insert')
def _user_new(mapper, connection, target):
    user_new.send(target)


@sqla_event.listens_for(User, 'after_update')
def _user_edited(mapper, connection, target):
    user_edited.send(target)


@sqla_event.listens_for(User, 'after_delete')
def _user_deleted(mapper, connection, target):
    user_deleted.send(target)


@sqla_event.listens_for(Organization, 'after_insert')
def _org_new(mapper, connection, target):
    org_new.send(target)


@sqla_event.listens_for(Organization, 'after_update')
def _org_edited(mapper, connection, target):
    org_edited.send(target)


@sqla_event.listens_for(Organization, 'after_delete')
def _org_deleted(mapper, connection, target):
    org_deleted.send(target)


@sqla_event.listens_for(Team, 'after_insert')
def _team_new(mapper, connection, target):
    team_new.send(target)


@sqla_event.listens_for(Team, 'after_update')
def _team_edited(mapper, connection, target):
    team_edited.send(target)


@sqla_event.listens_for(Team, 'after_delete')
def _team_deleted(mapper, connection, target):
    team_deleted.send(target)
