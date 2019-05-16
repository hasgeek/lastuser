# -*- coding: utf-8 -*-

from datetime import timedelta
from werkzeug import cached_property
from ua_parser import user_agent_parser
from flask import request
from coaster.utils import buid as make_buid, utcnow
from coaster.sqlalchemy import make_timestamp_columns
from . import db, BaseMixin
from .user import User
from ..signals import session_revoked

__all__ = ['UserSession']


session_client = db.Table(
    'session_client', db.Model.metadata,
    *(make_timestamp_columns() + (
        db.Column('user_session_id', None, db.ForeignKey('user_session.id'), nullable=False, primary_key=True),
        db.Column('client_id', None, db.ForeignKey('client.id'), nullable=False, primary_key=True)))
    )


class UserSession(BaseMixin, db.Model):
    __tablename__ = 'user_session'

    buid = db.Column(db.Unicode(22), nullable=False, unique=True, default=make_buid)
    sessionid = db.synonym('buid')

    user_id = db.Column(None, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship(User, backref=db.backref('sessions', cascade='all, delete-orphan', lazy='dynamic'))

    ipaddr = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.Unicode(250), nullable=False)

    accessed_at = db.Column(db.TIMESTAMP(timezone=True), nullable=False)
    revoked_at = db.Column(db.TIMESTAMP(timezone=True), nullable=True)
    sudo_enabled_at = db.Column(db.TIMESTAMP(timezone=True), nullable=False, default=db.func.utcnow())

    def __init__(self, **kwargs):
        super(UserSession, self).__init__(**kwargs)
        if not self.buid:
            self.buid = make_buid()

    def access(self, client=None):
        """
        Mark a session as currently active.

        :param client: For API calls from clients, save the client instead of IP address and User-Agent
        """
        # `accessed_at` will be different from the automatic `updated_at` in one
        # crucial context: when the session was revoked remotely. `accessed_at` won't
        # be updated at that time.
        self.accessed_at = db.func.utcnow()
        with db.session.no_autoflush:
            if client:
                if client not in self.clients:  # self.clients is defined via Client.sessions
                    self.clients.append(client)
                else:
                    # If we've seen this client in this session before, only update the timestamp
                    db.session.execute(session_client.update().where(
                        session_client.c.user_session_id == self.id).where(
                        session_client.c.client_id == client.id).values(
                        updated_at=db.func.utcnow()))
            else:
                self.ipaddr = request.remote_addr or u''
                self.user_agent = unicode(request.user_agent.string[:250]) or u''

    @cached_property
    def ua(self):
        return user_agent_parser.Parse(self.user_agent)

    @property
    def has_sudo(self):
        return self.sudo_enabled_at > utcnow() - timedelta(hours=1)

    def set_sudo(self):
        self.sudo_enabled_at = db.func.utcnow()

    def revoke(self):
        if not self.revoked_at:
            self.revoked_at = db.func.utcnow()
            session_revoked.send(self)

    @classmethod
    def get(cls, buid):
        return cls.query.filter_by(buid=buid).one_or_none()

    @classmethod
    def authenticate(cls, buid):
        return cls.query.filter(
            # Session key must match.
            cls.buid == buid,
            # Sessions are valid for one year...
            cls.accessed_at > db.func.utcnow() - timedelta(days=365),
            # ...unless explicitly revoked (or user logged out)
            cls.revoked_at == None).one_or_none()  # NOQA


User.active_sessions = db.relationship(UserSession,
    lazy='dynamic',
    primaryjoin=db.and_(
        UserSession.user_id == User.id,
        UserSession.accessed_at > db.func.utcnow() - timedelta(days=14),
        UserSession.revoked_at == None  # NOQA
        )
    )
