# -*- coding: utf-8 -*-

from datetime import datetime, timedelta
from werkzeug import cached_property
from werkzeug.useragents import UserAgent
from flask import request
from coaster.utils import buid as make_buid
from . import db, BaseMixin
from .user import User
from ..signals import session_revoked

__all__ = ['UserSession']


class UserSession(BaseMixin, db.Model):
    __tablename__ = 'user_session'
    __bind_key__ = 'lastuser'

    buid = db.Column(db.Unicode(22), nullable=False, unique=True, default=make_buid)

    user_id = db.Column(None, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship(User, backref=db.backref('sessions', cascade='all, delete-orphan', lazy='dynamic'))

    ipaddr = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.Unicode(250), nullable=False)

    accessed_at = db.Column(db.DateTime, nullable=False)
    revoked_at = db.Column(db.DateTime, nullable=True)
    sudo_enabled_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow())

    def __init__(self, **kwargs):
        super(UserSession, self).__init__(**kwargs)
        if not self.buid:
            self.buid = make_buid()

    def access(self):
        # `accessed_at` will be different from the automatic `updated_at` in one
        # crucial context: when the session was revoked remotely
        self.accessed_at = datetime.utcnow()
        self.ipaddr = request.environ.get('REMOTE_ADDR', u'')
        self.user_agent = request.user_agent.string[:250] or u''

    @cached_property
    def ua(self):
        return UserAgent(self.user_agent)

    @property
    def has_sudo(self):
        return self.sudo_enabled_at > datetime.utcnow() - timedelta(hours=1)

    def set_sudo(self):
        self.sudo_enabled_at = datetime.utcnow()

    def revoke(self):
        if not self.revoked_at:
            self.revoked_at = datetime.utcnow()
            session_revoked.send(self)

    @classmethod
    def get(cls, buid):
        return cls.query.filter_by(buid=buid).one_or_none()

    @classmethod
    def authenticate(cls, buid):
        return cls.query.filter(
            # Session key must match.
            cls.buid == buid,
            # Sessions are valid for two weeks...
            cls.accessed_at > datetime.utcnow() - timedelta(days=14),
            # ...unless explicitly revoked (or user logged out)
            cls.revoked_at == None).one_or_none()


# Patch a retriever into the User class. This could be placed in the
# UserSession.user relationship's backref with a custom primaryjoin
# clause and explicit foreign_keys.
def active_sessions(self):
    return self.sessions.filter(
        UserSession.accessed_at > datetime.utcnow() - timedelta(days=14),
        UserSession.revoked_at == None).all()

User.active_sessions = active_sessions
