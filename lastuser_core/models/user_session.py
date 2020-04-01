# -*- coding: utf-8 -*-

from datetime import timedelta

from flask import request
from werkzeug.utils import cached_property

from ua_parser import user_agent_parser

from coaster.sqlalchemy import make_timestamp_columns
from coaster.utils import buid as make_buid
from coaster.utils import utcnow

from ..signals import session_revoked
from . import BaseMixin, db
from .user import User

__all__ = ['UserSession']


auth_client_user_session = db.Table(
    'auth_client_user_session',
    db.Model.metadata,
    *(
        make_timestamp_columns()
        + (
            db.Column(
                'user_session_id',
                None,
                db.ForeignKey('user_session.id'),
                nullable=False,
                primary_key=True,
            ),
            db.Column(
                'auth_client_id',
                None,
                db.ForeignKey('auth_client.id'),
                nullable=False,
                primary_key=True,
            ),
        )
    ),
)


class UserSession(BaseMixin, db.Model):
    __tablename__ = 'user_session'

    buid = db.Column(db.Unicode(22), nullable=False, unique=True, default=make_buid)
    sessionid = db.synonym('buid')

    user_id = db.Column(None, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship(
        User,
        backref=db.backref('sessions', cascade='all, delete-orphan', lazy='dynamic'),
    )

    ipaddr = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.UnicodeText, nullable=False)

    accessed_at = db.Column(db.TIMESTAMP(timezone=True), nullable=False)
    revoked_at = db.Column(db.TIMESTAMP(timezone=True), nullable=True)
    sudo_enabled_at = db.Column(
        db.TIMESTAMP(timezone=True), nullable=False, default=db.func.utcnow()
    )

    def __init__(self, **kwargs):
        super(UserSession, self).__init__(**kwargs)
        if not self.buid:
            self.buid = make_buid()

    def access(self, auth_client=None):
        """
        Mark a session as currently active.

        :param auth_client: For API calls from clients, save the client instead of IP address and User-Agent
        """
        # `accessed_at` will be different from the automatic `updated_at` in one
        # crucial context: when the session was revoked remotely. `accessed_at` won't
        # be updated at that time.
        self.accessed_at = db.func.utcnow()
        with db.session.no_autoflush:
            if auth_client:
                if (
                    auth_client not in self.auth_clients
                ):  # self.clients is defined via Client.sessions
                    self.auth_clients.append(auth_client)
                else:
                    # If we've seen this client in this session before, only update the timestamp
                    db.session.execute(
                        auth_client_user_session.update()
                        .where(auth_client_user_session.c.user_session_id == self.id)
                        .where(
                            auth_client_user_session.c.auth_client_id == auth_client.id
                        )
                        .values(updated_at=db.func.utcnow())
                    )
            else:
                self.ipaddr = request.remote_addr or ''
                self.user_agent = str(request.user_agent.string[:250]) or ''

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
            cls.revoked_at.is_(None),
        ).one_or_none()


User.active_sessions = db.relationship(
    UserSession,
    lazy='dynamic',
    primaryjoin=db.and_(
        UserSession.user_id == User.id,
        UserSession.accessed_at > db.func.utcnow() - timedelta(days=14),
        UserSession.revoked_at.is_(None),
    ),
)
