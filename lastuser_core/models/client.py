# -*- coding: utf-8 -*-

from datetime import timedelta
from hashlib import sha256
import urlparse

from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.orm import load_only
from sqlalchemy.orm.collections import attribute_mapped_collection
from sqlalchemy.orm.query import Query as QueryBaseClass

from baseframe import _
from coaster.utils import buid, newsecret, require_one_of, utcnow

from . import BaseMixin, BaseScopedNameMixin, db
from .session import UserSession
from .user import Organization, Team, User

__all__ = [
    'AuthCode',
    'AuthToken',
    'CLIENT_TEAM_ACCESS',
    'Client',
    'ClientCredential',
    'ClientTeamAccess',
    'NoticeType',
    'Permission',
    'Resource',
    'ResourceAction',
    'TeamClientPermissions',
    'UserClientPermissions',
    'UserFlashMessage',
]


class ScopeMixin(object):
    __scope_null_allowed__ = False

    @declared_attr
    def _scope(cls):
        return db.Column('scope', db.UnicodeText, nullable=cls.__scope_null_allowed__)

    def _scope_get(self):
        if not self._scope:
            return ()
        else:
            return tuple(sorted(self._scope.split()))

    def _scope_set(self, value):
        if isinstance(value, basestring):
            value = [value]
        self._scope = u' '.join(sorted(t.strip() for t in value if t))

    @declared_attr
    def scope(cls):
        return db.synonym('_scope', descriptor=property(cls._scope_get, cls._scope_set))

    def add_scope(self, additional):
        if isinstance(additional, basestring):
            additional = [additional]
        self.scope = list(set(self.scope).union(set(additional)))


class Client(ScopeMixin, BaseMixin, db.Model):
    """OAuth client applications"""

    __tablename__ = 'client'
    __scope_null_allowed__ = True
    #: User who owns this client
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    user = db.relationship(
        User,
        primaryjoin=user_id == User.id,
        backref=db.backref('clients', cascade='all'),
    )
    #: Organization that owns this client. Only one of this or user must be set
    org_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=True)
    org = db.relationship(
        Organization,
        primaryjoin=org_id == Organization.id,
        backref=db.backref('clients', cascade='all'),
    )
    #: Human-readable title
    title = db.Column(db.Unicode(250), nullable=False)
    #: Long description
    description = db.Column(db.UnicodeText, nullable=False, default=u'')
    #: Confidential or public client? Public has no secret key
    confidential = db.Column(db.Boolean, nullable=False)
    #: Website
    website = db.Column(db.UnicodeText, nullable=False)
    #: Namespace: determines inter-app resource access
    namespace = db.Column(db.UnicodeText, nullable=True, unique=True)
    #: Redirect URIs (one or more)
    _redirect_uris = db.Column(
        'redirect_uri', db.UnicodeText, nullable=True, default=u''
    )
    #: Back-end notification URI
    notification_uri = db.Column(db.UnicodeText, nullable=True, default=u'')
    #: Front-end notification URI
    iframe_uri = db.Column(db.UnicodeText, nullable=True, default=u'')
    #: Active flag
    active = db.Column(db.Boolean, nullable=False, default=True)
    #: Allow anyone to login to this app?
    allow_any_login = db.Column(db.Boolean, nullable=False, default=True)
    #: Team access flag
    team_access = db.Column(db.Boolean, nullable=False, default=False)
    #: OAuth client key/id
    key = db.Column(db.String(22), nullable=False, unique=True, default=buid)
    #: Trusted flag: trusted clients are authorized to access user data
    #: without user consent, but the user must still login and identify themself.
    #: When a single provider provides multiple services, each can be declared
    #: as a trusted client to provide single sign-in across the services.
    #: However, resources in the scope column (via ScopeMixin) are granted for
    #: any arbitrary user without explicit user authorization.
    trusted = db.Column(db.Boolean, nullable=False, default=False)

    sessions = db.relationship(
        UserSession,
        lazy='dynamic',
        secondary='session_client',
        backref=db.backref('clients', lazy='dynamic'),
    )

    __table_args__ = (
        db.CheckConstraint(
            db.case([(user_id.isnot(None), 1)], else_=0)
            + db.case([(org_id.isnot(None), 1)], else_=0)
            == 1,
            name='client_user_id_or_org_id',
        ),
    )

    def __repr__(self):
        return u'<Client "{title}" {key}>'.format(title=self.title, key=self.key)

    def secret_is(self, candidate, name):
        """
        Check if the provided client secret is valid.
        """
        credential = self.credentials[name]
        return credential.secret_is(candidate)

    @property
    def redirect_uris(self):
        return tuple(self._redirect_uris.split())

    @redirect_uris.setter
    def redirect_uris(self, value):
        self._redirect_uris = u'\r\n'.join(value)

    @property
    def redirect_uri(self):
        uris = self.redirect_uris  # Assign to local var to avoid splitting twice
        if uris:
            return uris[0]

    def host_matches(self, url):
        netloc = urlparse.urlsplit(url or '').netloc
        if netloc:
            return netloc in [
                urlparse.urlsplit(r).netloc
                for r in list(self.redirect_uris) + [self.website]
            ]
        return False

    @property
    def owner(self):
        return self.user or self.org

    def owner_is(self, user):
        if not user:
            return False
        return self.user == user or (
            self.org and self.org in user.organizations_owned()
        )

    def orgs_with_team_access(self):
        """
        Return a list of organizations that this client has access to the teams of.
        """
        return [
            cta.org
            for cta in self.org_team_access
            if cta.access_level == CLIENT_TEAM_ACCESS.ALL
        ]

    def permissions(self, user, inherited=None):
        perms = super(Client, self).permissions(user, inherited)
        perms.add('view')
        if user and self.owner_is(user):
            perms.add('edit')
            perms.add('delete')
            perms.add('assign-permissions')
            perms.add('new-resource')
        return perms

    def authtoken_for(self, user, user_session=None):
        """Return the authtoken for this user and client. Only works for confidential clients."""
        if self.confidential:
            return AuthToken.query.filter_by(client=self, user=user).one_or_none()
        elif user_session and user_session.user == user:
            return AuthToken.query.filter_by(
                client=self, user_session=user_session
            ).one_or_none()

    @classmethod
    def get(cls, key=None, namespace=None):
        """
        Return a Client identified by its client key or namespace. Only returns active clients.

        :param str key: Client key to lookup
        :param str namespace: Client namespace to lookup
        """
        param, value = require_one_of(True, key=key, namespace=namespace)
        return cls.query.filter_by(**{param: value, 'active': True}).one_or_none()


class ClientCredential(BaseMixin, db.Model):
    """
    Client key and secret hash.

    We use unsalted SHA256 instead of a salted hash or a more secure hash
    like bcrypt because:

    1. Secrets are UUID-based and guaranteed unique before hashing.
       Salting is only beneficial when the source values are the same.
    2. Unlike user passwords, client secrets are used often, up to many times
       per minute. The hash needs to be fast (MD5 or SHA) and reasonably
       safe from collision attacks (eliminating MD5, SHA0 and SHA1). SHA256
       is the fastest available candidate meeting this criteria.
    3. We are stepping up from an industry standard of plain text client
       secrets, not stepping down from stronger hashing.
    4. To allow for a different hash to be used in future, hashes are stored
       prefixed with 'sha256$'.
    """

    __tablename__ = 'client_credential'
    client_id = db.Column(db.Integer, db.ForeignKey('client.id'), nullable=False)
    client = db.relationship(
        Client,
        primaryjoin=client_id == Client.id,
        backref=db.backref(
            'credentials',
            cascade='all, delete-orphan',
            collection_class=attribute_mapped_collection('name'),
        ),
    )

    #: OAuth client key
    name = db.Column(db.String(22), nullable=False, unique=True, default=buid)
    #: User description for this credential
    title = db.Column(db.Unicode(250), nullable=False, default=u'')
    #: OAuth client secret, hashed (64 chars hash plus 7 chars id prefix = 71 chars)
    secret_hash = db.Column(db.String(71), nullable=False)
    #: When was this credential last used for an API call?
    accessed_at = db.Column(db.TIMESTAMP(timezone=True), nullable=True)

    def secret_is(self, candidate):
        return self.secret_hash == 'sha256$' + sha256(candidate).hexdigest()

    @classmethod
    def get(cls, name):
        return cls.query.filter_by(name=name).one_or_none()

    @classmethod
    def new(cls, client):
        """
        Create a new client credential and return (cred, secret). The secret is not
        saved in plaintext, so this is the last time it will be available.

        :param client: The client for which a name/secret pair is being generated
        """
        cred = cls(client=client, name=buid())
        db.session.add(cred)
        secret = newsecret()
        cred.secret_hash = 'sha256$' + sha256(secret).hexdigest()
        return cred, secret


class UserFlashMessage(BaseMixin, db.Model):
    """
    Saved messages for a user, to be relayed to trusted clients.
    """

    __tablename__ = 'userflashmessage'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship(
        User,
        primaryjoin=user_id == User.id,
        backref=db.backref('flashmessages', cascade='delete, delete-orphan'),
    )
    seq = db.Column(db.Integer, default=0, nullable=False)
    category = db.Column(db.UnicodeText, nullable=False)
    message = db.Column(db.UnicodeText, nullable=False)


class Resource(BaseScopedNameMixin, db.Model):
    """
    Resources are provided by client applications. Other client applications
    can request access to user data at resource servers by providing the
    `name` as part of the requested `scope`.
    """

    __tablename__ = 'resource'
    # Resource names are unique within client apps
    name = db.Column(db.Unicode(20), nullable=False)
    client_id = db.Column(db.Integer, db.ForeignKey('client.id'), nullable=False)
    client = db.relationship(
        Client,
        primaryjoin=client_id == Client.id,
        backref=db.backref('resources', cascade='all, delete-orphan'),
    )
    parent = db.synonym('client')
    title = db.Column(db.Unicode(250), nullable=False)
    description = db.Column(db.UnicodeText, default=u'', nullable=False)
    siteresource = db.Column(db.Boolean, default=False, nullable=False)
    restricted = db.Column(db.Boolean, default=False, nullable=False)
    __table_args__ = (
        db.UniqueConstraint('client_id', 'name', name='resource_client_id_name_key'),
    )

    def permissions(self, user, inherited=None):
        perms = super(Resource, self).permissions(user, inherited)
        if user and self.client.owner_is(user):
            perms.add('edit')
            perms.add('delete')
            perms.add('new-action')
        return perms

    @classmethod
    def get(cls, name, client=None, namespace=None):
        """
        Return a Resource with the given name.

        :param str name: Name of the resource.
        """
        require_one_of(client=client, namespace=namespace)

        if client:
            return cls.query.filter_by(name=name, client=client).one_or_none()
        else:
            return (
                cls.query.filter_by(name=name)
                .join(Client)
                .filter(Client.namespace == namespace)
                .one_or_none()
            )

    def get_action(self, name):
        """
        Return a ResourceAction on this Resource with the given name.

        :param str name: Name of the action
        """
        return ResourceAction.get(name=name, resource=self)


class ResourceAction(BaseMixin, db.Model):
    """
    Actions that can be performed on resources.
    """

    __tablename__ = 'resourceaction'
    name = db.Column(db.Unicode(20), nullable=False)
    resource_id = db.Column(db.Integer, db.ForeignKey('resource.id'), nullable=False)
    resource = db.relationship(
        Resource,
        primaryjoin=resource_id == Resource.id,
        backref=db.backref('actions', cascade='all, delete-orphan'),
    )
    title = db.Column(db.Unicode(250), nullable=False)
    description = db.Column(db.UnicodeText, default=u'', nullable=False)

    # Action names are unique per client app
    __table_args__ = (db.UniqueConstraint('resource_id', 'name'),)

    def permissions(self, user, inherited=None):
        perms = super(ResourceAction, self).permissions(user, inherited)
        if user and self.resource.client.owner_is(user):
            perms.add('edit')
            perms.add('delete')
        return perms

    @classmethod
    def get(cls, name, resource):
        """
        Return a ResourceAction on the specified resource with the specified name.

        :param str name: Name of the action
        :param Resource resource: Resource on which this action exists
        """
        return cls.query.filter_by(name=name, resource=resource).one_or_none()


class AuthCode(ScopeMixin, BaseMixin, db.Model):
    """Short-lived authorization tokens"""

    __tablename__ = 'authcode'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship(User, primaryjoin=user_id == User.id)
    client_id = db.Column(db.Integer, db.ForeignKey('client.id'), nullable=False)
    client = db.relationship(
        Client,
        primaryjoin=client_id == Client.id,
        backref=db.backref('authcodes', cascade='all, delete-orphan'),
    )
    session_id = db.Column(None, db.ForeignKey('user_session.id'), nullable=True)
    session = db.relationship(UserSession)
    code = db.Column(db.String(44), default=newsecret, nullable=False)
    redirect_uri = db.Column(db.UnicodeText, nullable=False)
    used = db.Column(db.Boolean, default=False, nullable=False)

    def is_valid(self):
        # Time limit: 3 minutes. Should be reasonable enough to load a page
        # on a slow mobile connection, without keeping the code valid too long
        return not self.used and self.created_at >= utcnow() - timedelta(minutes=3)


class AuthToken(ScopeMixin, BaseMixin, db.Model):
    """Access tokens for access to data"""

    __tablename__ = 'authtoken'
    # Null for client-only tokens and public clients (user is identified via user_session.user there)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    _user = db.relationship(
        User,
        primaryjoin=user_id == User.id,
        backref=db.backref('authtokens', lazy='dynamic', cascade='all, delete-orphan'),
    )
    #: The session in which this token was issued, null for confidential clients
    user_session_id = db.Column(None, db.ForeignKey('user_session.id'), nullable=True)
    user_session = db.relationship(
        UserSession, backref=db.backref('authtokens', lazy='dynamic')
    )
    #: The client this authtoken is for
    client_id = db.Column(
        db.Integer, db.ForeignKey('client.id'), nullable=False, index=True
    )
    client = db.relationship(
        Client,
        primaryjoin=client_id == Client.id,
        backref=db.backref('authtokens', lazy='dynamic', cascade='all, delete-orphan'),
    )
    #: The token
    token = db.Column(db.String(22), default=buid, nullable=False, unique=True)
    #: The token's type
    token_type = db.Column(
        db.String(250), default=u'bearer', nullable=False
    )  # 'bearer', 'mac' or a URL
    #: Token secret for 'mac' type
    secret = db.Column(db.String(44), nullable=True)
    #: Secret's algorithm (for 'mac' type)
    _algorithm = db.Column('algorithm', db.String(20), nullable=True)
    #: Token's validity, 0 = unlimited
    validity = db.Column(
        db.Integer, nullable=False, default=0
    )  # Validity period in seconds
    #: Refresh token, to obtain a new token
    refresh_token = db.Column(db.String(22), nullable=True, unique=True)

    # Only one authtoken per user and client. Add to scope as needed
    __table_args__ = (
        db.UniqueConstraint('user_id', 'client_id'),
        db.UniqueConstraint('user_session_id', 'client_id'),
    )

    @property
    def user(self):
        if self.user_session:
            return self.user_session.user
        else:
            return self._user

    @user.setter
    def user(self, value):
        self._user = value

    user = db.synonym('_user', descriptor=user)

    def __init__(self, **kwargs):
        super(AuthToken, self).__init__(**kwargs)
        self.token = buid()
        if self._user:
            self.refresh_token = buid()
        self.secret = newsecret()

    def __repr__(self):
        return u'<AuthToken {token} of {client} {user}>'.format(
            token=self.token, client=repr(self.client)[1:-1], user=repr(self.user)[1:-1]
        )

    @property
    def effective_scope(self):
        return sorted(set(self.scope) | set(self.client.scope))

    def refresh(self):
        """
        Create a new token while retaining the refresh token.
        """
        if self.refresh_token is not None:
            self.token = buid()
            self.secret = newsecret()

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
            raise ValueError(_(u"Unrecognized algorithm ‘{value}’").format(value=value))

    algorithm = db.synonym('_algorithm', descriptor=algorithm)

    def is_valid(self):
        if self.validity == 0:
            return True  # This token is perpetually valid
        now = utcnow()
        if self.created_at < now - timedelta(seconds=self.validity):
            return False
        return True

    @classmethod
    def migrate_user(cls, olduser, newuser):
        if not olduser or not newuser:
            return  # Don't mess with client-only tokens
        oldtokens = cls.query.filter_by(user=olduser).all()
        newtokens = {}  # Client: token mapping
        for token in cls.query.filter_by(user=newuser).all():
            newtokens.setdefault(token.client_id, []).append(token)

        for token in oldtokens:
            merge_performed = False
            if token.client_id in newtokens:
                for newtoken in newtokens[token.client_id]:
                    if newtoken.user == newuser:
                        # There's another token for newuser with the same client.
                        # Just extend the scope there
                        newtoken.scope = set(newtoken.scope) | set(token.scope)
                        db.session.delete(token)
                        merge_performed = True
                        break
            if merge_performed is False:
                token.user = newuser  # Reassign this token to newuser

    @classmethod
    def get(cls, token):
        """
        Return an AuthToken with the matching token.

        :param str token: Token to lookup
        """
        query = cls.query.filter_by(token=token).options(
            db.joinedload(cls.client).load_only('id', '_scope')
        )
        return query.one_or_none()

    @classmethod  # NOQA: A003
    def all(cls, users):
        """
        Return all AuthToken for the specified users.
        """
        query = cls.query.options(db.joinedload(cls.client).load_only('id', '_scope'))
        if isinstance(users, QueryBaseClass):
            count = users.count()
            if count == 1:
                return query.filter_by(user=users.first()).all()
            elif count > 1:
                return query.filter(
                    AuthToken.user_id.in_(users.options(load_only('id')))
                ).all()
        else:
            count = len(users)
            if count == 1:
                return query.filter_by(user=users[0]).all()
            elif count > 1:
                return query.filter(AuthToken.user_id.in_([u.id for u in users])).all()

        return []


class Permission(BaseMixin, db.Model):
    __tablename__ = 'permission'
    #: User who created this permission
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    user = db.relationship(
        User,
        primaryjoin=user_id == User.id,
        backref=db.backref('permissions_created', cascade='all, delete-orphan'),
    )
    #: Organization which created this permission
    org_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=True)
    org = db.relationship(
        Organization,
        primaryjoin=org_id == Organization.id,
        backref=db.backref('permissions_created', cascade='all, delete-orphan'),
    )
    #: Name token
    name = db.Column(db.Unicode(80), nullable=False)
    #: Human-friendly title
    title = db.Column(db.Unicode(250), nullable=False)
    #: Description of what this permission is about
    description = db.Column(db.UnicodeText, default=u'', nullable=False)
    #: Is this permission available to all users and client apps?
    allusers = db.Column(db.Boolean, default=False, nullable=False)

    __table_args__ = (
        db.CheckConstraint(
            db.case([(user_id.isnot(None), 1)], else_=0)
            + db.case([(org_id.isnot(None), 1)], else_=0)
            == 1,
            name='permission_user_id_or_org_id',
        ),
    )

    def owner_is(self, user):
        return (
            user is not None
            and self.user == user
            or (self.org and self.org in user.organizations_owned())
        )

    @property
    def owner(self):
        return self.user or self.org

    def permissions(self, user, inherited=None):
        perms = super(Permission, self).permissions(user, inherited)
        if user and self.owner_is(user):
            perms.add('edit')
            perms.add('delete')
        return perms

    @classmethod
    def get(cls, name, user=None, org=None, allusers=False):
        """
        Get a permission with the given name and owned by the given user or org,
        or a permission available to all users.

        :param str name: Name of the permission
        :param User user: User who owns this permission
        :param Organization org: Organization which owns this permission
        :param bool allusers: Whether resources that belong to all users should be returned

        One of ``user`` and ``org`` must be specified, unless ``allusers`` is ``True``.
        """
        if allusers:
            return cls.query.filter_by(name=name, allusers=True).one_or_none()
        else:
            param, value = require_one_of(True, user=user, org=org)
            return cls.query.filter_by(**{param: value, 'name': name}).one_or_none()


# This model's name is in plural because it defines multiple permissions within each instance
class UserClientPermissions(BaseMixin, db.Model):
    __tablename__ = 'userclientpermissions'
    #: User who has these permissions
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship(
        User,
        primaryjoin=user_id == User.id,
        backref=db.backref('client_permissions', cascade='all, delete-orphan'),
    )
    #: Client app they are assigned on
    client_id = db.Column(
        db.Integer, db.ForeignKey('client.id'), nullable=False, index=True
    )
    client = db.relationship(
        Client,
        primaryjoin=client_id == Client.id,
        backref=db.backref('user_permissions', cascade='all, delete-orphan'),
    )
    #: The permissions as a string of tokens
    access_permissions = db.Column(
        'permissions', db.UnicodeText, default=u'', nullable=False
    )

    # Only one assignment per user and client
    __table_args__ = (db.UniqueConstraint('user_id', 'client_id'), {})

    # Used by lastuser_ui/client_info.html
    @property
    def pickername(self):
        return self.user.pickername

    # Used by lastuser_ui/client_info.html for url_for
    @property
    def buid(self):
        return self.user.buid

    @classmethod
    def migrate_user(cls, olduser, newuser):
        for operm in olduser.client_permissions:
            merge_performed = False
            for nperm in newuser.client_permissions:
                if nperm.client == operm.client:
                    # Merge permission strings
                    tokens = set(operm.access_permissions.split(' '))
                    tokens.update(set(nperm.access_permissions.split(' ')))
                    if u' ' in tokens:
                        tokens.remove(u' ')
                    nperm.access_permissions = u' '.join(sorted(tokens))
                    db.session.delete(operm)
                    merge_performed = True
            if not merge_performed:
                operm.user = newuser


# This model's name is in plural because it defines multiple permissions within each instance
class TeamClientPermissions(BaseMixin, db.Model):
    __tablename__ = 'teamclientpermissions'
    #: Team which has these permissions
    team_id = db.Column(db.Integer, db.ForeignKey('team.id'), nullable=False)
    team = db.relationship(
        Team,
        primaryjoin=team_id == Team.id,
        backref=db.backref('client_permissions', cascade='all, delete-orphan'),
    )
    #: Client app they are assigned on
    client_id = db.Column(
        db.Integer, db.ForeignKey('client.id'), nullable=False, index=True
    )
    client = db.relationship(
        Client,
        primaryjoin=client_id == Client.id,
        backref=db.backref('team_permissions', cascade='all, delete-orphan'),
    )
    #: The permissions as a string of tokens
    access_permissions = db.Column(
        'permissions', db.UnicodeText, default=u'', nullable=False
    )

    # Only one assignment per team and client
    __table_args__ = (db.UniqueConstraint('team_id', 'client_id'), {})

    # Used by lastuser_ui/client_info.html
    @property
    def pickername(self):
        return self.team.pickername

    # Used by lastuser_ui/client_info.html for url_for
    @property
    def buid(self):
        return self.team.buid


class CLIENT_TEAM_ACCESS:  # NOQA: N801
    NONE = 0  # The default if there's no connecting object
    ALL = 1  # All teams can be seen
    PARTIAL = 2  # TODO: Not supported yet


class ClientTeamAccess(BaseMixin, db.Model):
    __tablename__ = 'clientteamaccess'
    #: Organization whose teams are exposed to the client app
    org_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=True)
    org = db.relationship(
        Organization,
        primaryjoin=org_id == Organization.id,
        backref=db.backref('client_team_access', cascade='all, delete-orphan'),
    )
    #: Client app they are exposed to
    client_id = db.Column(db.Integer, db.ForeignKey('client.id'), nullable=False)
    client = db.relationship(
        Client,
        primaryjoin=client_id == Client.id,
        backref=db.backref('org_team_access', cascade='all, delete-orphan'),
    )
    access_level = db.Column(
        db.Integer, default=CLIENT_TEAM_ACCESS.NONE, nullable=False
    )


class NoticeType(BaseMixin, db.Model):
    __tablename__ = 'noticetype'
    #: User who created this notice type
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship(
        User,
        primaryjoin=user_id == User.id,
        backref=db.backref('noticetypes_created', cascade='all, delete-orphan'),
    )
    #: Name token
    name = db.Column(db.Unicode(80), nullable=False)
    #: Human-friendly title
    title = db.Column(db.Unicode(250), nullable=False)
    #: Description of what this notice type is about
    description = db.Column(db.UnicodeText, default=u'', nullable=False)
    #: Is this notice type available to all users and client apps?
    allusers = db.Column(db.Boolean, default=False, nullable=False)
