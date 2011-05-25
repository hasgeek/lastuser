# -*- coding: utf-8 -*-

from hashlib import md5
from werkzeug import generate_password_hash, check_password_hash

from lastuserapp.models import db, BaseMixin
from lastuserapp.utils import newid, newsecret

class User(db.Model, BaseMixin):
    __tablename__ = 'user'
    userid = db.Column(db.String(22), unique=True, nullable=False, default=newid)
    fullname = db.Column(db.Unicode(80), default='', nullable=False)
    username = db.Column(db.Unicode(80), unique=True, nullable=True)
    pw_hash = db.Column(db.String(80), nullable=True)
    description = db.Column(db.Text, default='', nullable=False)

    def __init__(self, password=None, **kwargs):
        self.password = password
        super(User, self).__init__(**kwargs)

    def _set_password(self, password):
        if password is None:
            self.pw_hash = None
        else:
            self.pw_hash = generate_password_hash(password)

    password = property(fset=_set_password)

    def password_is(self, password):
        if self.pw_hash is None:
            return False
        return check_password_hash(self.pw_hash, password)

    def __repr__(self):
        return '<User %s "%s">' % (self.username or self.userid, self.fullname)

    def profileid(self):
        if self.username:
            return self.username
        else:
            return self.userid

    def displayname(self):
        return self.fullname or self.username or self.userid

    def add_email(self, email, primary=False):
        # TODO: Need better handling for primary email id
        useremail = UserEmail(user=self, email=email, primary=primary)
        db.session.add(useremail)
        return useremail

    def del_email(self, email):
        setprimary=False
        useremail = UserEmail.query.filter_by(user=self, email=email).first()
        if useremail:
            if useremail.primary:
                setprimary=True
            db.session.delete(useremail)
        if setprimary:
            for emailob in UserEmail.query.filter_by(user_id=self.id).all():
                if emailob is not useremail:
                    emailob.primary=True
                    break

    @property
    def email(self):
        """
        Returns primary email address for user.
        """
        # Look for a primary address
        useremail = UserEmail.query.filter_by(user_id=self.id, primary=True).first()
        if useremail:
            return useremail
        # No primary? Maybe there's one that's not set as primary?
        useremail = UserEmail.query.filter_by(user_id=self.id).first()
        if useremail:
            # XXX: Mark at primary. This may or may not be saved depending on
            # whether the request ended in a database commit.
            useremail.primary=True
            return useremail
        # This user has no email address. Return a blank string instead of None
        # to support the common use case, where the caller will use unicode(user.email)
        # to get the email address as a string.
        return u''


class UserEmail(db.Model, BaseMixin):
    __tablename__ = 'useremail'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship(User, primaryjoin=user_id == User.id,
        backref= db.backref('emails', cascade="all, delete-orphan"))
    _email = db.Column('email', db.Unicode(80), unique=True, nullable=False)
    md5sum = db.Column(db.String(32), unique=True, nullable=False)
    primary = db.Column(db.Boolean, nullable=False, default=False)

    def __init__(self, email, **kwargs):
        super(UserEmail, self).__init__(**kwargs)
        self._email = email
        self.md5sum = md5(self._email).hexdigest()

    @property
    def email(self):
        return self._email

    email = db.synonym('_email', descriptor=email)

    def __repr__(self):
        return u'<UserEmail %s of user %s>' % (self.email, repr(self.user))

    def __unicode__(self):
        return unicode(self.email)

    def __str__(self):
        return str(self.__unicode__())


class UserEmailClaim(db.Model, BaseMixin):
    __tablename__ = 'useremailclaim'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship(User, primaryjoin=user_id == User.id,
        backref = db.backref('emailclaims', cascade="all, delete-orphan"))
    _email = db.Column('email', db.Unicode(80), nullable=True)
    verification_code = db.Column(db.String(44), nullable=False, default=newsecret)
    md5sum = db.Column(db.String(32), unique=True, nullable=False)

    def __init__(self, email, **kwargs):
        super(UserEmailClaim, self).__init__(**kwargs)
        self.verification_code = newsecret()
        self._email = email
        self.md5sum = md5(self._email).hexdigest()

    @property
    def email(self):
        return self._email

    email = db.synonym('_email', descriptor=email)

    def __repr__(self):
        return u'<UserEmailClaim %s of user %s>' % (self.email, repr(self.user))

    def __unicode__(self):
        return unicode(self.email)

    def __str__(self):
        return str(self.__unicode__())


class PasswordResetRequest(db.Model, BaseMixin):
    __tablename__ = 'passwordresetrequest'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship(User, primaryjoin=user_id == User.id)
    reset_code = db.Column(db.String(44), nullable=False, default=newsecret)

    def __init__(self, **kwargs):
        super(PasswordResetRequest, self).__init__(**kwargs)
        self.reset_code = newsecret()


class UserExternalId(db.Model, BaseMixin):
    __tablename__ = 'userexternalid'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship(User, primaryjoin=user_id == User.id,
        backref = db.backref('externalids', cascade="all, delete-orphan"))
    service = db.Column(db.String(20), nullable=False)
    userid = db.Column(db.String(250), nullable=False) # Unique id (or OpenID)
    username = db.Column(db.Unicode(80), nullable=True)
    oauth_token = db.Column(db.String(250), nullable=True)
    oauth_token_secret = db.Column(db.String(250), nullable=True)

    __table_args__ = ( db.UniqueConstraint("service", "userid"), {} )


__all__ = ['User', 'UserEmail', 'UserEmailClaim', 'PasswordResetRequest', 'UserExternalId']
