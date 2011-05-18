# -*- coding: utf-8 -*-
from lastuserapp.models import db, User
from lastuserapp.utils import newid, newsecret

class Client(db.Model):
    """OAuth client applications"""
    __tablename__ = 'client'
    id = db.Column(db.Integer, primary_key=True)
    #: User who owns this client
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship(User, primaryjoin=user_id == User.id, backref='clients')
    #: Human-readable title
    title = db.Column(db.Unicode(250), nullable=False)
    #: Long description
    description = db.Column(db.Text, nullable=False, default='')
    #: Human-readable owner name
    owner = db.Column(db.Unicode(250), nullable=False)
    #: Website
    website = db.Column(db.Unicode(250), nullable=False)
    #: Redirect URI
    redirect_uri = db.Column(db.Unicode(250), nullable=False)
    #: Service URI
    service_uri = db.Column(db.Unicode(250), nullable=True)
    #: Active flag
    active = db.Column(db.Boolean, nullable=False, default=True)
    #: Read-only flag
    readonly = db.Column(db.Boolean, nullable=False, default=True)
    #: Allow anyone to login to this app?
    allow_any_login = db.Column(db.Boolean, nullable=False, default=True)
    #: OAuth client key/id
    key = db.Column(db.String(22), nullable=False, unique=True, default=newid)
    #: OAuth client secret
    secret = db.Column(db.String(44), nullable=False, default=newsecret)
    #: Audit fields - registered date
    registered_date = db.Column(db.DateTime, nullable=False, default=db.func.now())
    #: Audit fields - updated date
    updated_date = db.Column(db.DateTime, nullable=False,
        default=db.func.now(), onupdate=db.func.now())
    #: Trusted flag: trusted clients are authorized to access user data
    #: without user consent, but the user must still login and identify themself.
    #: When a single provider provides multiple services, each can be declared
    #: as a trusted client to provide single sign-in across the services
    trusted = db.Column(db.Boolean, nullable=False, default=False)


class Resource(db.Model):
    """
    Resources are provided by client applications. Other client applications
    can request access to user data at resource servers by providing the
    `name` as part of the requested `scope`.
    """
    __tablename__ = 'resource'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Unicode(20), unique=True, nullable=False)
    client_id = db.Column(db.Integer, db.ForeignKey('client.id'), nullable=False)
    client = db.relationship(Client, primaryjoin=client_id == Client.id, backref='resources')
    title = db.Column(db.Unicode(250), nullable=False)
    description = db.Column(db.Text, default='', nullable=False)


class ResourceAction(db.Model):
    """
    Actions that can be performed on resources. There should always be at minimum
    a 'read' action.
    """
    __tablename__ = 'resourceaction'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.Unicode(20), unique=True, nullable=False)
    resource_id = db.Column(db.Integer, db.ForeignKey('resource.id'), nullable=False)
    resource = db.relationship(Resource, primaryjoin=resource_id == Resource.id, backref='actions')
    title = db.Column(db.Unicode(250), nullable=False)
    description = db.Column(db.Text, default='', nullable=False)


class AuthCode(db.Model):
    """Short-lived authorization tokens."""
    __tablename__ = 'authcode'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship(User, primaryjoin=user_id == User.id)
    client_id = db.Column(db.Integer, db.ForeignKey('client.id'), nullable=False)
    client = db.relationship(Client, primaryjoin=client_id == Client.id)
    code = db.Column(db.String(44), default=newsecret, nullable=False)
    _scope = db.Column('scope', db.Unicode(250), nullable=False)
    redirect_uri = db.Column(db.Unicode(250), nullable=False)
    datetime = db.Column(db.DateTime, default=db.func.now(), nullable=False)
    used = db.Column(db.Boolean, default=False, nullable=False)

    @property
    def scope(self):
        return self._scope.split(u' ')

    @scope.setter
    def scope(self, value):
        self._scope = u' '.join(value)

    scope = db.synonym('_scope', descriptor=scope)


class AuthToken(db.Model):
    """Access tokens for access to data."""
    __tablename__ = 'authtoken'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True) # For client-only
    user = db.relationship(User, primaryjoin=user_id == User.id)
    client_id = db.Column(db.Integer, db.ForeignKey('client.id'), nullable=False)
    client = db.relationship(Client, primaryjoin=client_id == Client.id)
    token = db.Column(db.String(22), default=newid, nullable=False, unique=True)
    token_type = db.Column(db.String(250), default='bearer', nullable=False) # 'bearer', 'mac' or a URL
    secret = db.Column(db.String(44), nullable=True)
    _algorithm = db.Column('algorithm', db.String(20), nullable=True)
    _scope = db.Column('scope', db.Unicode(250), nullable=False)
    created_datetime = db.Column(db.DateTime, default=db.func.now(), nullable=False)
    validity = db.Column(db.Integer, nullable=False, default=0) # Validity period in seconds
    refresh_token = db.Column(db.String(22), default=newid, nullable=False)
    updated_datetime = db.Column(db.DateTime, default=db.func.now(), onupdate=db.func.now(), nullable=False)

    @property
    def scope(self):
        return self._scope.split(u' ')

    @scope.setter
    def scope(self, value):
        self._scope = u' '.join(value)

    scope = db.synonym('_scope', descriptor=scope)

    @property
    def algorithm(self):
        return self._algorithm

    @algorithm.setter
    def algorithm(self, value):
        if value is None:
            self._algorithm = None
            self.secret = None
        elif value in ['hmac-sha-1', 'hmac-sha-256']:
            self._algorithm = value
        else:
            raise ValueError, "Unrecognized algorithm '%s'" % value

    algorithm = db.synonym('_algorithm', descriptor=algorithm)


__all__ = ['Client', 'Resource', 'ResourceAction', 'AuthCode', 'AuthToken']
