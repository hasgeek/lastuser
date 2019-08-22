# -*- coding: utf-8 -*-

from sqlalchemy import event as sqla_event

from flask.signals import Namespace

from .models import (
    Organization,
    Team,
    User,
    UserEmail,
    UserEmailClaim,
    UserPhone,
    UserPhoneClaim,
)

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

model_useremail_new = lastuser_signals.signal('model-useremail-new')
model_useremail_edited = lastuser_signals.signal('model-useremail-edited')
model_useremail_deleted = lastuser_signals.signal('model-useremail-deleted')

model_useremailclaim_new = lastuser_signals.signal('model-useremail-new')
model_useremailclaim_edited = lastuser_signals.signal('model-useremail-edited')
model_useremailclaim_deleted = lastuser_signals.signal('model-useremail-deleted')

model_userphone_new = lastuser_signals.signal('model-useremail-new')
model_userphone_edited = lastuser_signals.signal('model-useremail-edited')
model_userphone_deleted = lastuser_signals.signal('model-useremail-deleted')

model_userphoneclaim_new = lastuser_signals.signal('model-useremail-new')
model_userphoneclaim_edited = lastuser_signals.signal('model-useremail-edited')
model_userphoneclaim_deleted = lastuser_signals.signal('model-useremail-deleted')

resource_access_granted = lastuser_signals.signal('resource-access-granted')

# Higher level signals
user_login = lastuser_signals.signal('user-login')
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


@sqla_event.listens_for(UserEmail, 'after_insert')
def _useremail_new(mapper, connection, target):
    model_useremail_new.send(target)


@sqla_event.listens_for(UserEmail, 'after_update')
def _useremail_edited(mapper, connection, target):
    model_useremail_edited.send(target)


@sqla_event.listens_for(UserEmail, 'after_delete')
def _useremail_deleted(mapper, connection, target):
    model_useremail_deleted.send(target)


@sqla_event.listens_for(UserEmailClaim, 'after_insert')
def _useremailclaim_new(mapper, connection, target):
    model_useremailclaim_new.send(target)


@sqla_event.listens_for(UserEmailClaim, 'after_update')
def _useremailclaim_edited(mapper, connection, target):
    model_useremailclaim_edited.send(target)


@sqla_event.listens_for(UserEmailClaim, 'after_delete')
def _useremailclaim_deleted(mapper, connection, target):
    model_useremailclaim_deleted.send(target)


@sqla_event.listens_for(UserPhone, 'after_insert')
def _userphone_new(mapper, connection, target):
    model_userphone_new.send(target)


@sqla_event.listens_for(UserPhone, 'after_update')
def _userphone_edited(mapper, connection, target):
    model_userphone_edited.send(target)


@sqla_event.listens_for(UserPhone, 'after_delete')
def _userphone_deleted(mapper, connection, target):
    model_userphone_deleted.send(target)


@sqla_event.listens_for(UserPhoneClaim, 'after_insert')
def _userphoneclaim_new(mapper, connection, target):
    model_userphoneclaim_new.send(target)


@sqla_event.listens_for(UserPhoneClaim, 'after_update')
def _userphoneclaim_edited(mapper, connection, target):
    model_userphoneclaim_edited.send(target)


@sqla_event.listens_for(UserPhoneClaim, 'after_delete')
def _userphoneclaim_deleted(mapper, connection, target):
    model_userphoneclaim_deleted.send(target)
