# -*- coding: utf-8 -*-
from coaster import newid, newsecret

from lastuserapp.models import db, BaseMixin
from lastuserapp.models.user import User, Organization, Team


class Client(BaseMixin, db.Model):
    """OAuth client applications"""
    __tablename__ = 'client'
    #: User who owns this client
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    user = db.relationship(User, primaryjoin=user_id == User.id,
        backref=db.backref('clients', cascade="all, delete-orphan"))
    #: Organization that owns this client. Only one of this or user must be set
    org_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=True)
    org = db.relationship(Organization, primaryjoin=org_id == Organization.id,
        backref=db.backref('clients', cascade="all, delete-orphan"))
    #: Human-readable title
    title = db.Column(db.Unicode(250), nullable=False)
    #: Long description
    description = db.Column(db.UnicodeText, nullable=False, default=u'')
    #: Website
    website = db.Column(db.Unicode(250), nullable=False)
    #: Redirect URI
    redirect_uri = db.Column(db.Unicode(250), nullable=True, default=u'')
    #: Back-end notification URI
    notification_uri = db.Column(db.Unicode(250), nullable=True, default=u'')
    #: Front-end notification URI
    iframe_uri = db.Column(db.Unicode(250), nullable=True, default=u'')
    #: Resource discovery URI
    resource_uri = db.Column(db.Unicode(250), nullable=True, default=u'')
    #: Active flag
    active = db.Column(db.Boolean, nullable=False, default=True)
    #: Allow anyone to login to this app?
    allow_any_login = db.Column(db.Boolean, nullable=False, default=True)
    #: Team access flag
    team_access = db.Column(db.Boolean, nullable=False, default=False)
    #: OAuth client key/id
    key = db.Column(db.String(22), nullable=False, unique=True, default=newid)
    #: OAuth client secret
    secret = db.Column(db.String(44), nullable=False, default=newsecret)
    #: Trusted flag: trusted clients are authorized to access user data
    #: without user consent, but the user must still login and identify themself.
    #: When a single provider provides multiple services, each can be declared
    #: as a trusted client to provide single sign-in across the services
    trusted = db.Column(db.Boolean, nullable=False, default=False)

    def secret_is(self, candidate):
        """
        Check if the provided client secret is valid.
        """
        return self.secret == candidate

    @property
    def owner(self):
        """
        Return human-readable owner name.
        """
        if self.user:
            return self.user.pickername
        elif self.org:
            return self.org.pickername
        else:
            raise AttributeError("This client has no owner")

    def owner_is(self, user):
        return self.user == user or (self.org and self.org in user.organizations_owned())

    def orgs_with_team_access(self):
        """
        Return a list of organizations that this client has access to the teams of.
        """
        return [cta.org for cta in self.org_team_access if cta.access_level == CLIENT_TEAM_ACCESS.ALL]

    def permissions(self, user, inherited=None):
        perms = super(Client, self).permissions(user, inherited)
        perms.add('view')
        if user and self.owner_is(user):
            perms.add('edit')
            perms.add('delete')
            perms.add('assign-permissions')
            perms.add('new-resource')
        return perms


class UserFlashMessage(BaseMixin, db.Model):
    """
    Saved messages for a user, to be relayed to trusted clients.
    """
    __tablename__ = 'userflashmessage'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship(User, primaryjoin=user_id == User.id,
        backref=db.backref("flashmessages", cascade="delete, delete-orphan"))
    seq = db.Column(db.Integer, default=0, nullable=False)
    category = db.Column(db.Unicode(20), nullable=False)
    message = db.Column(db.Unicode(250), nullable=False)


class Resource(BaseMixin, db.Model):
    """
    Resources are provided by client applications. Other client applications
    can request access to user data at resource servers by providing the
    `name` as part of the requested `scope`.
    """
    __tablename__ = 'resource'
    # Resource names are unique across client apps
    name = db.Column(db.Unicode(20), unique=True, nullable=False)
    client_id = db.Column(db.Integer, db.ForeignKey('client.id'), nullable=False)
    client = db.relationship(Client, primaryjoin=client_id == Client.id,
        backref=db.backref('resources', cascade="all, delete-orphan"))
    title = db.Column(db.Unicode(250), nullable=False)
    description = db.Column(db.UnicodeText, default=u'', nullable=False)
    siteresource = db.Column(db.Boolean, default=False, nullable=False)
    trusted = db.Column(db.Boolean, default=False, nullable=False)

    def permissions(self, user, inherited=None):
        perms = super(Resource, self).permissions(user, inherited)
        if user and self.client.owner_is(user):
            perms.add('edit')
            perms.add('delete')
            perms.add('new-action')
        return perms


class ResourceAction(BaseMixin, db.Model):
    """
    Actions that can be performed on resources. There should always be at minimum
    a 'read' action.
    """
    __tablename__ = 'resourceaction'
    name = db.Column(db.Unicode(20), nullable=False)
    resource_id = db.Column(db.Integer, db.ForeignKey('resource.id'), nullable=False)
    resource = db.relationship(Resource, primaryjoin=resource_id == Resource.id,
        backref=db.backref('actions', cascade="all, delete-orphan"))
    title = db.Column(db.Unicode(250), nullable=False)
    description = db.Column(db.UnicodeText, default=u'', nullable=False)

    # Action names are unique per client app
    __table_args__ = (db.UniqueConstraint("name", "resource_id"), {})

    def permissions(self, user, inherited=None):
        perms = super(ResourceAction, self).permissions(user, inherited)
        if user and self.resource.client.owner_is(user):
            perms.add('edit')
            perms.add('delete')
        return perms


class AuthCode(BaseMixin, db.Model):
    """Short-lived authorization tokens."""
    __tablename__ = 'authcode'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship(User, primaryjoin=user_id == User.id)
    client_id = db.Column(db.Integer, db.ForeignKey('client.id'), nullable=False)
    client = db.relationship(Client, primaryjoin=client_id == Client.id,
        backref=db.backref("authcodes", cascade="all, delete-orphan"))
    code = db.Column(db.String(44), default=newsecret, nullable=False)
    _scope = db.Column('scope', db.Unicode(250), nullable=False)
    redirect_uri = db.Column(db.Unicode(250), nullable=False)
    used = db.Column(db.Boolean, default=False, nullable=False)

    @property
    def scope(self):
        return self._scope.split(u' ')

    @scope.setter
    def scope(self, value):
        self._scope = u' '.join(value)

    scope = db.synonym('_scope', descriptor=scope)

    def add_scope(self, additional):
        if isinstance(additional, basestring):
            additional = [additional]
        self.scope = list(set(self.scope).union(set(additional)))


class AuthToken(BaseMixin, db.Model):
    """Access tokens for access to data."""
    __tablename__ = 'authtoken'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)  # Null for client-only tokens
    user = db.relationship(User, primaryjoin=user_id == User.id)
    client_id = db.Column(db.Integer, db.ForeignKey('client.id'), nullable=False)
    client = db.relationship(Client, primaryjoin=client_id == Client.id,
        backref=db.backref("authtokens", cascade="all, delete-orphan"))
    token = db.Column(db.String(22), default=newid, nullable=False, unique=True)
    token_type = db.Column(db.String(250), default='bearer', nullable=False)  # 'bearer', 'mac' or a URL
    secret = db.Column(db.String(44), nullable=True)
    _algorithm = db.Column('algorithm', db.String(20), nullable=True)
    _scope = db.Column('scope', db.Unicode(250), nullable=False)
    validity = db.Column(db.Integer, nullable=False, default=0)  # Validity period in seconds
    refresh_token = db.Column(db.String(22), nullable=True, unique=True)

    # Only one authtoken per user and client. Add to scope as needed
    __table_args__ = (db.UniqueConstraint("user_id", "client_id"), {})

    def __init__(self, **kwargs):
        super(AuthToken, self).__init__(**kwargs)
        self.token = newid()
        if self.user:
            self.refresh_token = newid()
        self.secret = newsecret()

    def refresh(self):
        """
        Create a new token while retaining the refresh token.
        """
        if self.refresh_token is not None:
            self.token = newid()
            self.secret = newsecret()

    @property
    def scope(self):
        return self._scope.split(u' ')

    @scope.setter
    def scope(self, value):
        self._scope = u' '.join(value)

    scope = db.synonym('_scope', descriptor=scope)

    def add_scope(self, additional):
        if isinstance(additional, basestring):
            additional = [additional]
        self.scope = list(set(self.scope).union(set(additional)))

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
            raise ValueError("Unrecognized algorithm '%s'" % value)

    algorithm = db.synonym('_algorithm', descriptor=algorithm)


class Permission(BaseMixin, db.Model):
    __tablename__ = 'permission'
    #: User who created this permission
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    user = db.relationship(User, primaryjoin=user_id == User.id,
        backref=db.backref('permissions_created', cascade="all, delete-orphan"))
    #: Organization which created this permission
    org_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=True)
    org = db.relationship(Organization, primaryjoin=org_id == Organization.id,
        backref=db.backref('permissions_created', cascade="all, delete-orphan"))
    #: Name token
    name = db.Column(db.Unicode(80), nullable=False)
    #: Human-friendly title
    title = db.Column(db.Unicode(250), nullable=False)
    #: Description of what this permission is about
    description = db.Column(db.UnicodeText, default=u'', nullable=False)
    #: Is this permission available to all users and client apps?
    allusers = db.Column(db.Boolean, default=False, nullable=False)

    def owner_is(self, user):
        return self.user == user or (self.org and self.org in user.organizations_owned())

    def owner_name(self):
        if self.user:
            return self.user.pickername
        else:
            return self.org.pickername

    def permissions(self, user, inherited=None):
        perms = super(Permission, self).permissions(user, inherited)
        if user and self.owner_is(user):
            perms.add('edit')
            perms.add('delete')
        return perms


# This model's name is in plural because it defines multiple permissions within each instance
class UserClientPermissions(BaseMixin, db.Model):
    __tablename__ = 'userclientpermissions'
    #: User who has these permissions
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship(User, primaryjoin=user_id == User.id,
        backref=db.backref('permissions', cascade='all, delete-orphan'))
    #: Client app they are assigned on
    client_id = db.Column(db.Integer, db.ForeignKey('client.id'), nullable=False)
    client = db.relationship(Client, primaryjoin=client_id == Client.id,
        backref=db.backref('permissions_users', cascade="all, delete-orphan"))
    #: The permissions as a string of tokens
    permissions = db.Column(db.Unicode(250), default=u'', nullable=False)

    # Only one assignment per user and client
    # TODO: Also define context for permission:
    # a. User1 has permissions x, y (without context) in app1
    # b. User1 has permissions a, b, c in context p in app1
    # Contexts could be defined with a separator, suffixed to the permission
    # such as permission:context/subpath.
    __table_args__ = (db.UniqueConstraint("user_id", "client_id"), {})

    @property
    def pickername(self):
        return self.user.pickername

    @property
    def userid(self):
        return self.user.userid


# This model's name is in plural because it defines multiple permissions within each instance
class TeamClientPermissions(BaseMixin, db.Model):
    __tablename__ = 'teamclientpermissions'
    #: Team which has these permissions
    team_id = db.Column(db.Integer, db.ForeignKey('team.id'), nullable=False)
    team = db.relationship(Team, primaryjoin=team_id == Team.id,
        backref=db.backref('permissions', cascade='all, delete-orphan'))
    #: Client app they are assigned on
    client_id = db.Column(db.Integer, db.ForeignKey('client.id'), nullable=False)
    client = db.relationship(Client, primaryjoin=client_id == Client.id,
        backref=db.backref('permissions_teams', cascade="all, delete-orphan"))
    #: The permissions as a string of tokens
    permissions = db.Column(db.Unicode(250), default=u'', nullable=False)

    # Only one assignment per team and client
    # TODO: Also define context for permission:
    # a. User1 has permissions x, y (without context) in app1
    # b. User1 has permissions a, b, c in context p in app1
    # Contexts could be defined with a separator, suffixed to the permission
    # such as permission:context/subpath.
    __table_args__ = (db.UniqueConstraint("team_id", "client_id"), {})

    @property
    def pickername(self):
        return self.team.pickername

    @property
    def userid(self):
        return self.team.userid


class CLIENT_TEAM_ACCESS:
    NONE = 0     # The default if there's no connecting object
    ALL = 1      # All teams can be seen
    PARTIAL = 2  # TODO: Not supported yet


class ClientTeamAccess(BaseMixin, db.Model):
    __tablename__ = 'clientteamaccess'
    #: Organization whose teams are exposed to the client app
    org_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=True)
    org = db.relationship(Organization, primaryjoin=org_id == Organization.id,
        backref=db.backref('client_team_access', cascade="all, delete-orphan"))
    #: Client app they are exposed to
    client_id = db.Column(db.Integer, db.ForeignKey('client.id'), nullable=False)
    client = db.relationship(Client, primaryjoin=client_id == Client.id,
        backref=db.backref('org_team_access', cascade="all, delete-orphan"))
    access_level = db.Column(db.Integer, default=CLIENT_TEAM_ACCESS.NONE, nullable=False)


class NoticeType(BaseMixin, db.Model):
    __tablename__ = 'noticetype'
    #: User who created this notice type
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship(User, primaryjoin=user_id == User.id,
        backref=db.backref('noticetypes_created', cascade="all, delete-orphan"))
    #: Name token
    name = db.Column(db.Unicode(80), nullable=False)
    #: Human-friendly title
    title = db.Column(db.Unicode(250), nullable=False)
    #: Description of what this notice type is about
    description = db.Column(db.UnicodeText, default=u'', nullable=False)
    #: Is this notice type available to all users and client apps?
    allusers = db.Column(db.Boolean, default=False, nullable=False)


__all__ = ['Client', 'UserFlashMessage', 'Resource', 'ResourceAction', 'AuthCode', 'AuthToken',
    'Permission', 'UserClientPermissions', 'TeamClientPermissions', 'NoticeType',
    'CLIENT_TEAM_ACCESS', 'ClientTeamAccess']
