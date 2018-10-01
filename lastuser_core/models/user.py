# -*- coding: utf-8 -*-

from datetime import datetime, timedelta
from hashlib import md5
from werkzeug import check_password_hash, cached_property
import bcrypt
import phonenumbers
from sqlalchemy import or_
from sqlalchemy.orm import defer, deferred
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy.ext.associationproxy import association_proxy
from coaster.utils import newsecret, newpin, valid_username, require_one_of, LabeledEnum
from coaster.sqlalchemy import make_timestamp_columns, failsafe_add, add_primary_relationship
from baseframe import _, __

from . import db, BaseMixin, UuidMixin


__all__ = ['Name', 'User', 'UserEmail', 'UserEmailClaim', 'PasswordResetRequest', 'UserExternalId',
           'UserPhone', 'UserPhoneClaim', 'Team', 'Organization', 'UserOldId', 'USER_STATUS']


class Name(UuidMixin, BaseMixin, db.Model):
    """
    Manage common namespace between the User and Organization models.
    """
    __tablename__ = 'name'
    __uuid_primary_key__ = True
    __name_length__ = 63

    #: The "username" assigned to a user or organization (length limit 63 to fit DNS label limit)
    name = db.Column(db.Unicode(__name_length__), nullable=False, unique=True)
    # Only one of the following three may be set:
    #: User that owns this name (limit one per user)
    user_id = db.Column(None, db.ForeignKey('user.id', ondelete='CASCADE'), unique=True, nullable=True)
    user = db.relationship('User', backref=db.backref('_name', uselist=False, cascade='all, delete-orphan'))
    #: Organization that owns this name (limit one per organization)
    org_id = db.Column(None, db.ForeignKey('organization.id', ondelete='CASCADE'), unique=True, nullable=True)
    org = db.relationship('Organization', backref=db.backref('_name', uselist=False, cascade='all, delete-orphan'))
    #: Reserved name (not assigned to any party)
    reserved = db.Column(db.Boolean, nullable=False, default=False, index=True)

    __table_args__ = (
        db.CheckConstraint(
            db.case([(user_id != None, 1)], else_=0) +
            db.case([(org_id != None, 1)], else_=0) +
            db.case([(reserved == True, 1)], else_=0) == 1,
            name='username_owner_check'),  # NOQA
        db.Index('ix_name_name_lower', db.func.lower(name).label('name_lower'),
            unique=True, postgresql_ops={'name_lower': 'varchar_pattern_ops'})
        )

    @property
    def owner(self):
        return self.user or self.org

    @owner.setter
    def owner(self, value):
        if isinstance(value, User):
            self.user = value
            self.org = None
        elif isinstance(value, Organization):
            self.user = None
            self.org = value
        else:
            raise ValueError(value)
        self.reserved = False

    @classmethod
    def get(cls, name):
        return cls.query.filter(db.func.lower(Name.name) == db.func.lower(name)).one_or_none()

    @classmethod
    def validate_name_candidate(cls, name):
        """
        Check if a name is available, returning one of several error codes, or None if all is okay:

        * ``blank``: No name supplied
        * ``invalid``: Invalid characters in name
        * ``long``: Name is longer than allowed size
        * ``reserved``: Name is reserved
        * ``user``: Name is assigned to a user
        * ``org``: Name is assigned to an organization
        """
        if not name:
            return 'blank'
        elif not valid_username(name):
            return 'invalid'
        elif len(name) > cls.__name_length__:
            return 'long'
        existing = cls.get(name)
        if existing:
            if existing.reserved:
                return 'reserved'
            elif existing.user_id:
                return 'user'
            elif existing.org_id:
                return 'org'

    @classmethod
    def is_available_name(cls, name):
        if valid_username(name) and len(name) <= cls.__name_length__:
            if cls.query.filter(db.func.lower(cls.name) == db.func.lower(name)).isempty():
                return True
        return False

    @db.validates('name')
    def validate_name(self, key, value):
        if not valid_username(value):
            raise ValueError("Invalid username: " + value)
        # We don't check for existence in the db since this validator only
        # checks for valid syntax. To confirm the name is actually available,
        # the caller must call :meth:`is_available_name` or attempt to commit
        # to the db and catch IntegrityError.
        return value


class SharedNameMixin(object):
    """
    Common methods between User and Organization to link to Name
    """
    # The `name` property in User and Organization is not over here because
    # of what seems to be a SQLAlchemy bug: we can't override the expression
    # (both models need separate expressions) without triggering an inspection
    # of the `_name` relationship, which does not exist yet as the backrefs
    # are only fully setup when module loading is finished.
    # Doc: https://docs.sqlalchemy.org/en/latest/orm/extensions/hybrid.html#reusing-hybrid-properties-across-subclasses

    def is_valid_name(self, value):
        if not valid_username(value):
            return False
        existing = Name.get(value)
        if existing and existing.owner != self:
            return False
        return True

    def validate_name_candidate(self, name):
        if name and name == self.name:
            return
        return Name.validate_name_candidate(name)


class USER_STATUS(LabeledEnum):
    ACTIVE = (0, 'active', __("Active"))           # Regular, active user
    SUSPENDED = (1, 'suspended', __("Suspended"))  # Suspended account
    MERGED = (2, 'merged', __("Merged"))           # Merged into another user
    INVITED = (3, 'invited', __("Invited"))        # Invited to make an account, doesn't have one yet


class User(SharedNameMixin, UuidMixin, BaseMixin, db.Model):
    __tablename__ = 'user'
    __title_length__ = 80
    userid = db.synonym('buid')  # XXX: Deprecated, still here for Baseframe compatibility
    #: The user's fullname
    fullname = db.Column(db.Unicode(__title_length__), default=u'', nullable=False)
    #: Alias for the user's fullname
    title = db.synonym('fullname')
    #: Bcrypt hash of the user's password
    pw_hash = db.Column(db.String(80), nullable=True)
    #: Timestamp for when the user's password last changed
    pw_set_at = db.Column(db.DateTime, nullable=True)
    #: Expiry date for the password (to prompt user to reset it)
    pw_expires_at = db.Column(db.DateTime, nullable=True)
    #: User's timezone
    timezone = db.Column(db.Unicode(40), nullable=True)
    #: Deprecated, but column preserved for existing data until migration
    description = deferred(db.Column(db.UnicodeText, default=u'', nullable=False))
    #: User's status (active, suspended, merged, etc)
    status = db.Column(db.SmallInteger, nullable=False, default=USER_STATUS.ACTIVE)
    #: User avatar (URL to browser-ready image)
    avatar = db.Column(db.Unicode(250), nullable=True)

    #: Client id that created this user account
    client_id = db.Column(None, db.ForeignKey('client.id',
        use_alter=True, name='user_client_id_fkey'), nullable=True)
    #: If this user was created by a client app via the API, record it here
    client = db.relationship('Client', foreign_keys=[client_id])  # No backref or cascade

    #: Id of user who invited this user
    referrer_id = db.Column(None, db.ForeignKey('user.id',
        use_alter=True, name='user_referrer_id_fkey'), nullable=True)
    #: User who invited this user
    referrer = db.relationship('User', foreign_keys=[referrer_id])

    #: Other user accounts that were merged into this user account
    oldusers = association_proxy('oldids', 'olduser')

    __table_args__ = (
        db.Index('ix_user_fullname_lower', db.func.lower(fullname).label('fullname_lower'),
            postgresql_ops={'fullname_lower': 'varchar_pattern_ops'}),
        )

    _defercols = [
        defer('created_at'),
        defer('updated_at'),
        defer('pw_hash'),
        defer('pw_set_at'),
        defer('pw_expires_at'),
        defer('timezone'),
        defer('client_id'),
        defer('referrer_id'),
        ]

    def __init__(self, password=None, **kwargs):
        self.password = password
        super(User, self).__init__(**kwargs)

    @hybrid_property
    def name(self):
        if self._name:
            return self._name.name

    @name.setter
    def name(self, value):
        if not value:
            self._name = None
        else:
            if self._name is not None:
                self._name.name = value
            else:
                self._name = Name(name=value, owner=self, id=self.uuid)

    @name.expression
    def name(cls):
        return db.select([Name.name]).where(Name.user_id == cls.id).label('name')

    username = db.synonym('name')

    @property
    def is_active(self):
        return self.status == USER_STATUS.ACTIVE

    def merged_user(self):
        if self.status == USER_STATUS.MERGED:
            return UserOldId.get(self.uuid).user
        else:
            return self

    def _set_password(self, password):
        if password is None:
            self.pw_hash = None
        else:
            self.pw_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        self.pw_set_at = db.func.utcnow()
        # Expire passwords after one year. TODO: make this configurable
        self.pw_expires_at = self.pw_set_at + timedelta(days=365)

    #: Write-only property (passwords cannot be read back in plain text)
    password = property(fset=_set_password)

    def password_has_expired(self):
        return self.pw_hash is not None and self.pw_expires_at is not None and self.pw_expires_at <= datetime.utcnow()

    def password_is(self, password):
        if self.pw_hash is None:
            return False

        if self.pw_hash.startswith('sha1$'):  # XXX: DEPRECATED
            return check_password_hash(self.pw_hash, password)
        else:
            return bcrypt.hashpw(password.encode('utf-8'), self.pw_hash.encode('utf-8')) == self.pw_hash.encode('utf-8')

    def __repr__(self):
        return '<User {username} "{fullname}">'.format(username=self.username or self.buid,
            fullname=self.fullname.encode('utf-8'))

    def profileid(self):
        if self.username:
            return self.username
        else:
            return self.buid

    def displayname(self):
        return self.fullname or self.username or self.buid

    @property
    def pickername(self):
        if self.username:
            return u'{fullname} (@{username})'.format(fullname=self.fullname, username=self.username)
        else:
            return self.fullname

    def add_email(self, email, primary=False, type=None, private=False):
        useremail = UserEmail(user=self, email=email, type=type, private=private)
        useremail = failsafe_add(db.session, useremail, user=self, email=email)
        if primary:
            self.primary_email = useremail
        return useremail

    def del_email(self, email):
        useremail = UserEmail.query.filter_by(user=self, email=email).first()
        if useremail:
            db.session.delete(useremail)
        if self.primary_email in (useremail, None):
            db.session.flush()
            self.primary_email = UserEmail.query.filter_by(user=self).first()

    @cached_property
    def email(self):
        """
        Returns primary email address for user.
        """
        # Look for a primary address
        useremail = self.primary_email
        if useremail:
            return useremail
        # No primary? Maybe there's one that's not set as primary?
        useremail = UserEmail.query.filter_by(user=self).first()
        if useremail:
            # XXX: Mark at primary. This may or may not be saved depending on
            # whether the request ended in a database commit.
            self.primary_email = useremail
            return useremail
        # This user has no email address. Return a blank string instead of None
        # to support the common use case, where the caller will use unicode(user.email)
        # to get the email address as a string.
        return u''

    @cached_property
    def phone(self):
        """
        Returns primary phone number for user.
        """
        # Look for a primary address
        userphone = self.primary_phone
        if userphone:
            return userphone
        # No primary? Maybe there's one that's not set as primary?
        userphone = UserPhone.query.filter_by(user=self).first()
        if userphone:
            # XXX: Mark at primary. This may or may not be saved depending on
            # whether the request ended in a database commit.
            self.primary_phone = userphone
            return userphone
        # This user has no phone number. Return a blank string instead of None
        # to support the common use case, where the caller will use unicode(user.phone)
        # to get the phone number as a string.
        return u''

    def organizations(self):
        """
        Return the organizations this user is a member of.
        """
        return sorted(set([team.org for team in self.teams]), key=lambda o: o.title)

    def organizations_owned(self):
        """
        Return the organizations this user is an owner of.
        """
        return sorted(set([team.org for team in self.teams if team.org.owners == team]),
            key=lambda o: o.title)

    def organizations_owned_ids(self):
        """
        Return the database ids of the organizations this user is an owner of. This is used
        for database queries.
        """
        return list(set([team.org.id for team in self.teams if team.org.owners == team]))

    def organizations_memberof(self):
        """
        Return the organizations this user is a member of.
        """
        return sorted(set([team.org for team in self.teams if team.org.members == team]),
            key=lambda o: o.title)

    def organizations_memberof_ids(self):
        """
        Return the database ids of the organizations this user is a member of. This is used
        for database queries.
        """
        return list(set([team.org.id for team in self.teams if team.org.members == team]))

    def is_profile_complete(self):
        """
        Return True if profile is complete (fullname, username and email are present), False
        otherwise.
        """
        return bool(self.fullname and self.username and self.email)

    def available_permissions(self):
        """
        Return all permission objects available to this user
        (either owned by user or available to all users).
        """
        from .client import Permission
        return Permission.query.filter(
            db.or_(Permission.allusers == True, Permission.user == self)  # NOQA
            ).order_by(Permission.name).all()

    def clients_with_team_access(self):
        """
        Return a list of clients with access to the user's organizations' teams.
        """
        return [token.client for token in self.authtokens if 'teams' in token.effective_scope]

    @classmethod
    def get(cls, username=None, buid=None, defercols=False):
        """
        Return a User with the given username or buid.

        :param str username: Username to lookup
        :param str buid: Buid to lookup
        :param bool defercols: Defer loading non-critical columns
        """
        require_one_of(username=username, buid=buid)

        if username is not None:
            query = cls.query.join(Name).filter(Name.name == username)
        else:
            query = cls.query.filter_by(buid=buid)
        if defercols:
            query = query.options(*cls._defercols)
        user = query.one_or_none()
        if user and user.status == USER_STATUS.MERGED:
            user = user.merged_user()
        if user and user.is_active:
            return user

    @classmethod
    def all(cls, buids=None, userids=None, usernames=None, defercols=False):
        """
        Return all matching users.

        :param list buids: Buids to look up
        :param list userids: Alias for ``buids`` (deprecated)
        :param list usernames: Usernames to look up
        :param bool defercols: Defer loading non-critical columns
        """
        users = set()
        if userids and not buids:
            buids = userids
        if buids and usernames:
            query = cls.query.join(Name).filter(or_(cls.buid.in_(buids), Name.name.in_(usernames)))
        elif buids:
            query = cls.query.filter(cls.buid.in_(buids))
        elif usernames:
            query = cls.query.join(Name).filter(Name.name.in_(usernames))
        else:
            raise Exception

        if defercols:
            query = query.options(*cls._defercols)
        for user in query.all():
            user = user.merged_user()
            if user.is_active:
                users.add(user)
        return list(users)

    @classmethod
    def autocomplete(cls, query):
        """
        Return users whose names begin with the query, for autocomplete widgets.
        Looks up users by fullname, username, external ids and email addresses.

        :param str query: Letters to start matching with
        """
        # Escape the '%' and '_' wildcards in SQL LIKE clauses.
        # Some SQL dialects respond to '[' and ']', so remove them.
        query = query.replace(u'%', ur'\%').replace(u'_', ur'\_').replace(u'[', u'').replace(u']', u'') + u'%'
        # Use User._username since 'username' is a hybrid property that checks for validity
        # before passing on to _username, the actual column name on the model.
        # We convert to lowercase and use the LIKE operator since ILIKE isn't standard
        # and doesn't use an index on PostgreSQL (there's a functional index defined below).
        if not query:
            return []
        users = cls.query.join(Name).filter(cls.status == USER_STATUS.ACTIVE,
            or_(  # Match against buid (exact value only), fullname or username, case insensitive
                cls.buid == query[:-1],
                db.func.lower(cls.fullname).like(db.func.lower(query)),
                db.func.lower(Name.name).like(db.func.lower(query))
                )
            ).options(*cls._defercols).limit(100).all()  # Limit to 100 results
        if query.startswith('@') and UserExternalId.__at_username_services__:
            # Add Twitter/GitHub accounts to the head of results
            users = cls.query.filter(cls.status == USER_STATUS.ACTIVE, cls.id.in_(
                db.session.query(UserExternalId.user_id).filter(
                    UserExternalId.service.in_(UserExternalId.__at_username_services__),
                    db.func.lower(UserExternalId.username).like(db.func.lower(query[1:]))
                ).subquery())).options(*cls._defercols).limit(100).all() + users
        elif '@' in query:
            users = cls.query.filter(cls.status == USER_STATUS.ACTIVE, cls.id.in_(
                db.session.query(UserEmail.user_id).filter(UserEmail.user_id != None).filter(  # NOQA
                    db.func.lower(UserEmail.email).like(db.func.lower(query))
                ).subquery())).options(*cls._defercols).limit(100).all() + users
        return users


class UserOldId(UuidMixin, BaseMixin, db.Model):
    __tablename__ = 'useroldid'
    __uuid_primary_key__ = True

    #: Old user account, if still present
    olduser = db.relationship(User, primaryjoin='foreign(UserOldId.id) == remote(User.uuid)',
        backref=db.backref('oldid', uselist=False))
    #: User id of new user
    user_id = db.Column(None, db.ForeignKey('user.id'), nullable=False)
    #: New user account
    user = db.relationship(User, primaryjoin=user_id == User.id,
        backref=db.backref('oldids', cascade='all, delete-orphan'))

    def __repr__(self):
        return '<UserOldId {buid} of {user}>'.format(
            buid=self.buid, user=repr(self.user)[1:-1])

    @classmethod
    def get(cls, uuid):
        return cls.query.filter_by(id=uuid).one_or_none()


# --- Organizations and teams -------------------------------------------------

team_membership = db.Table(
    'team_membership', db.Model.metadata,
    *(make_timestamp_columns() + (
        db.Column('user_id', None, db.ForeignKey('user.id'), nullable=False, primary_key=True),
        db.Column('team_id', None, db.ForeignKey('team.id'), nullable=False, primary_key=True)))
    )


class Organization(SharedNameMixin, UuidMixin, BaseMixin, db.Model):
    __tablename__ = 'organization'
    __title_length__ = 80
    # owners_id cannot be null, but must be declared with nullable=True since there is
    # a circular dependency. The post_update flag on the relationship tackles the circular
    # dependency within SQLAlchemy.
    owners_id = db.Column(None, db.ForeignKey('team.id',
        use_alter=True, name='organization_owners_id_fkey'), nullable=True)
    owners = db.relationship('Team', primaryjoin='Organization.owners_id == Team.id',
        uselist=False, cascade='all', post_update=True)  # No delete-orphan cascade here
    members_id = db.Column(None, db.ForeignKey('team.id',
        use_alter=True, name='organization_members_id_fkey'), nullable=True)
    members = db.relationship('Team', primaryjoin='Organization.members_id == Team.id',
        uselist=False, cascade='all', post_update=True)  # No delete-orphan cascade here
    title = db.Column(db.Unicode(__title_length__), default=u'', nullable=False)
    #: Deprecated, but column preserved for existing data until migration
    description = deferred(db.Column(db.UnicodeText, default=u'', nullable=False))

    #: Client id that created this account
    client_id = db.Column(None, db.ForeignKey('client.id',
        use_alter=True, name='organization_client_id_fkey'), nullable=True)
    #: If this org was created by a client app via the API, record it here
    client = db.relationship('Client', foreign_keys=[client_id])  # No backref or cascade

    _defercols = [
        defer('created_at'),
        defer('updated_at'),
        ]

    def __init__(self, *args, **kwargs):
        super(Organization, self).__init__(*args, **kwargs)
        self.make_teams()

    @hybrid_property
    def name(self):
        if self._name:
            return self._name.name

    @name.setter
    def name(self, value):
        if not value:
            self._name = None
        else:
            if self._name is not None:
                self._name.name = value
            else:
                self._name = Name(name=value, owner=self, id=self.uuid)

    @name.expression
    def name(cls):
        return db.select([Name.name]).where(Name.org_id == cls.id).label('name')

    def make_teams(self):
        if self.owners is None:
            self.owners = Team(title=_(u"Owners"), org=self)
        if self.members is None:
            self.members = Team(title=_(u"Members"), org=self)

    def __repr__(self):
        return '<Organization {name} "{title}">'.format(
            name=self.name or self.buid, title=self.title.encode('utf-8'))

    @property
    def pickername(self):
        if self.name:
            return u'{title} (@{name})'.format(title=self.title, name=self.name)
        else:
            return self.title

    def clients_with_team_access(self):
        """
        Return a list of clients with access to the organization's teams.
        """
        from lastuser_core.models.client import CLIENT_TEAM_ACCESS
        return [cta.client for cta in self.client_team_access if cta.access_level == CLIENT_TEAM_ACCESS.ALL]

    def permissions(self, user, inherited=None):
        perms = super(Organization, self).permissions(user, inherited)
        if user and user in self.owners.users:
            perms.add('view')
            perms.add('edit')
            perms.add('delete')
            perms.add('view-teams')
            perms.add('new-team')
        else:
            if 'view' in perms:
                perms.remove('view')
            if 'edit' in perms:
                perms.remove('edit')
            if 'delete' in perms:
                perms.remove('delete')
        return perms

    def available_permissions(self):
        """
        Return all permission objects available to this organization
        (either owned by this organization or available to all users).
        """
        from .client import Permission
        return Permission.query.filter(
            db.or_(Permission.allusers == True, Permission.org == self)  # NOQA
            ).order_by(Permission.name).all()

    @classmethod
    def get(cls, name=None, buid=None, defercols=False):
        """
        Return an Organization with matching name or buid. Note that ``name`` is the username, not the title.

        :param str name: Name of the organization
        :param str buid: Buid of the organization
        :param bool defercols: Defer loading non-critical columns
        """
        require_one_of(name=name, buid=buid)

        if name is not None:
            query = cls.query.join(Name).filter(Name.name == name)
        else:
            query = cls.query.filter_by(buid=buid)
        if defercols:
            query = query.options(*cls._defercols)
        return query.one_or_none()

    @classmethod
    def all(cls, buids=None, names=None, defercols=False):
        orgs = []
        if buids:
            query = cls.query.filter(cls.buid.in_(buids))
            if defercols:
                query = query.options(*cls._defercols)
            orgs.extend(query.all())
        if names:
            query = cls.query.join(Name).filter(Name.name.in_(names))
            if defercols:
                query = query.options(*cls._defercols)
            orgs.extend(query.all())
        return orgs


class Team(UuidMixin, BaseMixin, db.Model):
    __tablename__ = 'team'
    __title_length__ = 250
    #: Displayed name
    title = db.Column(db.Unicode(__title_length__), nullable=False)
    #: Organization
    org_id = db.Column(None, db.ForeignKey('organization.id'), nullable=False)
    org = db.relationship(Organization, primaryjoin=org_id == Organization.id,
        backref=db.backref('teams', order_by=title, cascade='all, delete-orphan'))
    users = db.relationship(User, secondary='team_membership', lazy='dynamic',
        backref='teams')  # No cascades here! Cascades will delete users

    #: Client id that created this team
    client_id = db.Column(None, db.ForeignKey('client.id',
        use_alter=True, name='team_client_id_fkey'), nullable=True)
    #: If this team was created by a client app via the API, record it here
    client = db.relationship('Client', foreign_keys=[client_id])  # No backref or cascade

    def __repr__(self):
        return '<Team {team} of {org}>'.format(
            team=self.title.encode('utf-8'), org=repr(self.org)[1:-1])

    @property
    def pickername(self):
        return self.title

    def permissions(self, user, inherited=None):
        perms = super(Team, self).permissions(user, inherited)
        if user and user in self.org.owners.users:
            perms.add('edit')
            perms.add('delete')
        return perms

    @classmethod
    def migrate_user(cls, olduser, newuser):
        for team in olduser.teams:
            if team not in newuser.teams:
                newuser.teams.append(team)
        olduser.teams = []

    @classmethod
    def get(cls, buid=None):
        """
        Return a Team with matching buid.

        :param str buid: Buid of the organization
        """
        return cls.query.filter_by(buid=buid).one_or_none()


# -- User email/phone and misc

class UserEmail(BaseMixin, db.Model):
    __tablename__ = 'useremail'
    user_id = db.Column(None, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship(User, primaryjoin=user_id == User.id,
        backref=db.backref('emails', cascade='all, delete-orphan'))
    _email = db.Column('email', db.Unicode(254), unique=True, nullable=False)
    md5sum = db.Column(db.String(32), unique=True, nullable=False)
    domain = db.Column(db.Unicode(253), nullable=False, index=True)

    private = db.Column(db.Boolean, nullable=False, default=False)
    type = db.Column(db.Unicode(30), nullable=True)

    __table_args__ = (
        db.Index('ix_useremail_email_lower', db.func.lower(_email).label('email_lower'),
            unique=True, postgresql_ops={'email_lower': 'varchar_pattern_ops'}),
        )

    def __init__(self, email, **kwargs):
        super(UserEmail, self).__init__(**kwargs)
        self._email = email.lower()
        self.md5sum = md5(self._email).hexdigest()
        self.domain = email.split('@')[-1]

    # XXX: Are hybrid_property and synonym both required?
    # Shouldn't one suffice?
    @hybrid_property
    def email(self):
        return self._email

    #: Make email immutable. There is no setter for email.
    email = db.synonym('_email', descriptor=email)

    def __repr__(self):
        return '<UserEmail {email} of {user}>'.format(
            email=self.email, user=repr(self.user)[1:-1])

    def __unicode__(self):
        return unicode(self.email)

    def __str__(self):
        return str(self.__unicode__())

    @property
    def primary(self):
        return self.user.primary_email == self

    @primary.setter
    def primary(self, value):
        if value:
            self.user.primary_email = self
        else:
            if self.user.primary_email == self:
                self.user.primary_email = None

    @classmethod
    def get(cls, email=None, md5sum=None):
        """
        Return a UserEmail with matching email or md5sum.

        :param str email: Email address to lookup
        :param str md5sum: md5sum of email address to lookup
        """
        require_one_of(email=email, md5sum=md5sum)

        if email:
            return cls.query.filter(cls.email.in_([email, email.lower()])).one_or_none()
        else:
            return cls.query.filter_by(md5sum=md5sum).one_or_none()


class UserEmailClaim(BaseMixin, db.Model):
    __tablename__ = 'useremailclaim'
    user_id = db.Column(None, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship(User, primaryjoin=user_id == User.id,
        backref=db.backref('emailclaims', cascade='all, delete-orphan'))
    _email = db.Column('email', db.Unicode(254), nullable=True, index=True)
    verification_code = db.Column(db.String(44), nullable=False, default=newsecret)
    md5sum = db.Column(db.String(32), nullable=False, index=True)
    domain = db.Column(db.Unicode(253), nullable=False, index=True)

    private = db.Column(db.Boolean, nullable=False, default=False)
    type = db.Column(db.Unicode(30), nullable=True)

    __table_args__ = (db.UniqueConstraint('user_id', 'email'),)

    def __init__(self, email, **kwargs):
        super(UserEmailClaim, self).__init__(**kwargs)
        self.verification_code = newsecret()
        self._email = email.lower()
        self.md5sum = md5(self._email).hexdigest()
        self.domain = email.split('@')[-1]

    @hybrid_property
    def email(self):
        return self._email

    #: Make email immutable. There is no setter for email.
    email = db.synonym('_email', descriptor=email)

    def __repr__(self):
        return '<UserEmailClaim {email} of {user}>'.format(
            email=self.email, user=repr(self.user)[1:-1])

    def __unicode__(self):
        return unicode(self.email)

    def __str__(self):
        return str(self.__unicode__())

    def permissions(self, user, inherited=None):
        perms = super(UserEmailClaim, self).permissions(user, inherited)
        if user and user == self.user:
            perms.add('verify')
        return perms

    @classmethod
    def get(cls, email, user):
        """
        Return a UserEmailClaim with matching email address for the given user.

        :param str email: Email address to lookup
        :param User user: User who claimed this email address
        """
        return cls.query.filter(UserEmailClaim.email.in_([email, email.lower()])).filter_by(user=user).one_or_none()

    @classmethod
    def all(cls, email):
        """
        Return all UserEmailClaim instances with matching email address.

        :param str email: Email address to lookup
        """
        return cls.query.filter(UserEmailClaim.email.in_([email, email.lower()])).order_by(cls.user_id).all()


class UserPhone(BaseMixin, db.Model):
    __tablename__ = 'userphone'
    user_id = db.Column(None, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship(User, primaryjoin=user_id == User.id,
        backref=db.backref('phones', cascade='all, delete-orphan'))
    _phone = db.Column('phone', db.Unicode(16), unique=True, nullable=False)
    gets_text = db.Column(db.Boolean, nullable=False, default=True)

    private = db.Column(db.Boolean, nullable=False, default=False)
    type = db.Column(db.Unicode(30), nullable=True)

    def __init__(self, phone, **kwargs):
        super(UserPhone, self).__init__(**kwargs)
        self._phone = phone

    @hybrid_property
    def phone(self):
        return self._phone

    phone = db.synonym('_phone', descriptor=phone)

    def __repr__(self):
        return '<UserPhone {phone} of {user}>'.format(
            phone=self.phone, user=repr(self.user)[1:-1])

    def __unicode__(self):
        return unicode(self.phone)

    def __str__(self):
        return str(self.__unicode__())

    def parsed(self):
        return phonenumbers.parse(self._phone)

    def formatted(self):
        return phonenumbers.format_number(self.parsed(), phonenumbers.PhoneNumberFormat.INTERNATIONAL)

    @property
    def primary(self):
        return self.user.primary_phone == self

    @primary.setter
    def primary(self, value):
        if value:
            self.user.primary_phone = self
        else:
            if self.user.primary_phone == self:
                self.user.primary_phone = None

    @classmethod
    def get(cls, phone):
        """
        Return a UserPhone with matching phone number.

        :param str phone: Phone number to lookup (must be an exact match)
        """
        return cls.query.filter_by(phone=phone).one_or_none()


class UserPhoneClaim(BaseMixin, db.Model):
    __tablename__ = 'userphoneclaim'
    user_id = db.Column(None, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship(User, primaryjoin=user_id == User.id,
        backref=db.backref('phoneclaims', cascade='all, delete-orphan'))
    _phone = db.Column('phone', db.Unicode(16), nullable=False, index=True)
    gets_text = db.Column(db.Boolean, nullable=False, default=True)
    verification_code = db.Column(db.Unicode(4), nullable=False, default=newpin)
    verification_attempts = db.Column(db.Integer, nullable=False, default=0)

    private = db.Column(db.Boolean, nullable=False, default=False)
    type = db.Column(db.Unicode(30), nullable=True)

    __table_args__ = (db.UniqueConstraint('user_id', 'phone'),)

    def __init__(self, phone, **kwargs):
        super(UserPhoneClaim, self).__init__(**kwargs)
        self.verification_code = newpin()
        self._phone = phone

    @hybrid_property
    def phone(self):
        return self._phone

    phone = db.synonym('_phone', descriptor=phone)

    def __repr__(self):
        return '<UserPhoneClaim {phone} of {user}>'.format(
            phone=self.phone, user=repr(self.user)[1:-1])

    def __unicode__(self):
        return unicode(self.phone)

    def __str__(self):
        return str(self.__unicode__())

    def parsed(self):
        return phonenumbers.parse(self._phone)

    def formatted(self):
        return phonenumbers.format_number(self.parsed(), phonenumbers.PhoneNumberFormat.INTERNATIONAL)

    @hybrid_property
    def verification_expired(self):
        return self.verification_attempts >= 3

    def permissions(self, user, inherited=None):
        perms = super(UserPhoneClaim, self).permissions(user, inherited)
        if user and user == self.user:
            perms.add('verify')
        return perms

    @classmethod
    def get(cls, phone, user):
        """
        Return a UserPhoneClaim with matching phone number for the given user.

        :param str phone: Phone number to lookup (must be an exact match)
        :param User user: User who claimed this phone number
        """
        return cls.query.filter_by(phone=phone, user=user).one_or_none()

    @classmethod
    def all(cls, phone):
        """
        Return all UserPhoneClaim instances with matching phone number.

        :param str phone: Phone number to lookup (must be an exact match)
        """
        return cls.query.filter_by(phone=phone).all()


class PasswordResetRequest(BaseMixin, db.Model):
    __tablename__ = 'passwordresetrequest'
    user_id = db.Column(None, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship(User, primaryjoin=user_id == User.id)
    reset_code = db.Column(db.String(44), nullable=False, default=newsecret)

    def __init__(self, **kwargs):
        super(PasswordResetRequest, self).__init__(**kwargs)
        self.reset_code = newsecret()


class UserExternalId(BaseMixin, db.Model):
    __tablename__ = 'userexternalid'
    __at_username_services__ = []
    user_id = db.Column(None, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship(User, primaryjoin=user_id == User.id,
        backref=db.backref('externalids', cascade='all, delete-orphan'))
    service = db.Column(db.String(20), nullable=False)
    userid = db.Column(db.String(250), nullable=False)  # Unique id (or OpenID)
    username = db.Column(db.Unicode(250), nullable=True)  # LinkedIn returns full URLs
    oauth_token = db.Column(db.String(1000), nullable=True)
    oauth_token_secret = db.Column(db.String(1000), nullable=True)
    oauth_token_type = db.Column(db.String(250), nullable=True)

    __table_args__ = (
        db.UniqueConstraint('service', 'userid'),
        db.Index('ix_userexternalid_username_lower', db.func.lower(username).label('username_lower'),
            postgresql_ops={'username_lower': 'varchar_pattern_ops'})
        )

    def __repr__(self):
        return '<UserExternalId {service}:{username} of {user}>'.format(
            service=self.service, username=self.username, user=repr(self.user)[1:-1])

    @classmethod
    def get(cls, service, userid=None, username=None):
        """
        Return a UserExternalId with the given service and userid or username.

        :param str service: Service to lookup
        :param str userid: Userid to lookup
        :param str username: Username to lookup (may be non-unique)

        Usernames are not guaranteed to be unique within a service. An example is with Google,
        where the userid is a directed OpenID URL, unique but subject to change if the Lastuser
        site URL changes. The username is the email address, which will be the same despite
        different userids.
        """
        param, value = require_one_of(True, userid=userid, username=username)
        return cls.query.filter_by(**{param: value, 'service': service}).one_or_none()

    def permissions(self, user, inherited=None):
        perms = super(UserExternalId, self).permissions(user, inherited)
        if user and user == self.user:
            perms.add('delete_extid')
        return perms


add_primary_relationship(User, 'primary_email', UserEmail, 'user', 'user_id')
add_primary_relationship(User, 'primary_phone', UserPhone, 'user', 'user_id')
