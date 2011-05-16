#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Encryption
from hashlib import md5
# Datetime
from datetime import datetime, date, timedelta
# URL handling for OAuth2
import urlparse
from urllib import urlencode as make_query_string
# Logging
import logging
# Decorators
from functools import wraps
# Id generation
import uuid
from base64 import urlsafe_b64encode
# Flask and extensions
from flask import (Flask, render_template, g, flash, request, redirect,
                   session, url_for, Response, jsonify, abort, Markup)
from flaskext.sqlalchemy import SQLAlchemy
import flaskext.wtf as wtf
from flaskext.mail import Mail, Message
from flaskext.assets import Environment, Bundle
from flaskext.oauth import OAuth, OAuthException # OAuth 1.0a
# Werkzeug, Flask's base library
from werkzeug import generate_password_hash, check_password_hash
# OAuth 1.0a
# import oauth2
# Other
from markdown import markdown


# --- Status codes ------------------------------------------------------------


# --- Globals and settings ----------------------------------------------------

app = Flask(__name__)
app.config.from_object(__name__)
try:
    app.config.from_object('settings')
except ImportError:
    import sys
    print >> sys.stderr, "Please create a settings.py with the necessary settings. See settings-sample.py."
    sys.exit()

db = SQLAlchemy(app)
assets = Environment(app)
mail = Mail(app)

# OAuth 1.0a handlers
oauth = OAuth()
twitter = oauth.remote_app('twitter',
    base_url='http://api.twitter.com/1/',
    request_token_url='http://api.twitter.com/oauth/request_token',
    access_token_url='http://api.twitter.com/oauth/access_token',
    authorize_url='http://api.twitter.com/oauth/authenticate',
    consumer_key=app.config.get('OAUTH_TWITTER_KEY'),
    consumer_secret=app.config.get('OAUTH_TWITTER_SECRET'),
)



# --- Assets ------------------------------------------------------------------

js = Bundle('js/libs/jquery-1.5.1.min.js',
            'js/libs/jquery.form.js',
            'js/scripts.js',
            filters='jsmin', output='js/packed.js')

assets.register('js_all', js)


# --- Utilities ---------------------------------------------------------------

def requires_login(f):
    """
    Decorator to require a login for the given view.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if g.user is None:
            flash(u"You need to be logged in for that page")
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


def newid():
    """
    Return a new random id that is exactly 22 characters long. See
    http://en.wikipedia.org/wiki/Base64#Variants_summary_table
    for URL-safe Base64
    """
    return urlsafe_b64encode(uuid.uuid4().bytes).rstrip('=')


def newsecret():
    """
    Cheap OAuth secret generator.
    """
    return newid()+newid()


def make_redirect_url(url, **params):
    urlparts = list(urlparse.urlsplit(url))
    # URL parts:
    # 0: scheme
    # 1: netloc
    # 2: path
    # 3: query -- appended to
    # 4: fragment
    queryparts = urlparse.parse_qsl(urlparts[3], keep_blank_values=True)
    queryparts.extend(params.items())
    urlparts[3] = make_query_string(queryparts)
    return urlparse.urlunsplit(urlparts)

def getuser(name):
    if '@' in name:
        useremail = UserEmail.query.filter_by(email=name).first()
        if useremail:
            return useremail.user
        # No verified email id. Look for an unverified id; return first found
        useremail = UserEmailClaim.query.filter_by(email=name).first()
        if useremail:
            return useremail.user
        return None
    else:
        return User.query.filter_by(username=name).first()


# --- Models ------------------------------------------------------------------

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    userid = db.Column(db.String(22), unique=True, nullable=False, default=newid)
    fullname = db.Column(db.Unicode(80), default='', nullable=False)
    username = db.Column(db.Unicode(80), unique=True, nullable=True)
    pw_hash = db.Column(db.String(80), nullable=True)
    registered_date = db.Column(db.DateTime, default=db.func.now(), nullable=False)

    def __init__(self, password=None, **kwargs):
        self.password = password
        super(User, self).__init__(**kwargs)

    def _set_password(self, password):
        if password is None:
            self.pw_hash = None
        else:
            self.pw_hash = generate_password_hash(password)

    password = property(fset=_set_password)

    def check_password(self, password):
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
        # This user has no email address.
        return None


class UserEmail(db.Model):
    __tablename__ = 'useremail'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship(User, primaryjoin=user_id == User.id)
    _email = db.Column('email', db.Unicode(80), unique=True, nullable=False)
    md5sum = db.Column(db.String(32), unique=True, nullable=False)
    primary = db.Column(db.Boolean, nullable=False, default=False)
    registered_date = db.Column(db.DateTime, default=db.func.now(), nullable=False)

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


class UserEmailClaim(db.Model):
    __tablename__ = 'useremailclaim'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship(User, primaryjoin=user_id == User.id)
    _email = db.Column('email', db.Unicode(80), nullable=True)
    verification_code = db.Column(db.String(44), nullable=False, default=newsecret)
    registered_date = db.Column(db.DateTime, default=db.func.now(), nullable=False)
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


class PasswordResetRequest(db.Model):
    __tablename__ = 'passwordresetrequest'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship(User, primaryjoin=user_id == User.id)
    reset_code = db.Column(db.String(44), nullable=False, default=newsecret)
    reset_date = db.Column(db.DateTime, default=db.func.now(), nullable=False)

    def __init__(self, **kwargs):
        super(PasswordResetRequest, self).__init__(**kwargs)
        self.reset_code = newsecret()


class UserExternalId(db.Model):
    __tablename__ = 'userexternalid'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship(User, primaryjoin=user_id == User.id)
    service = db.Column(db.String(20), nullable=False)
    userid = db.Column(db.String(80), nullable=False)
    username = db.Column(db.Unicode(80), nullable=True)
    oauth_token = db.Column(db.String(250), nullable=True)
    oauth_token_secret = db.Column(db.String(250), nullable=True)
    registered_date = db.Column(db.DateTime, default=db.func.now(), nullable=False)

    __table_args__ = ( db.UniqueConstraint("service", "userid"), {} )


class Client(db.Model):
    """OAuth client applications"""
    __tablename__ = 'client'
    id = db.Column(db.Integer, primary_key=True)
    #: User who owns this client
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship(User, primaryjoin=user_id == User.id)
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
    client = db.relationship(Client, primaryjoin=client_id == Client.id)
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
    resource = db.relationship(Resource, primaryjoin=resource_id == Resource.id)
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


# --- Forms -------------------------------------------------------------------

class LoginForm(wtf.Form):
    username = wtf.TextField('Username or Email', validators=[wtf.Required()])
    password = wtf.PasswordField('Password', validators=[wtf.Required()])
    remember = wtf.BooleanField('Remember me')

    def validate_username(self, field):
        existing = getuser(field.data)
        if existing is None:
            raise wtf.ValidationError, "User does not exist"

    def validate_password(self, field):
        user = getuser(self.username.data)
        if user is None or not user.check_password(field.data):
            raise wtf.ValidationError, "Invalid password"
        self.user = user


class RegisterForm(wtf.Form):
    fullname = wtf.TextField('Full name', validators=[wtf.Required()])
    email = wtf.html5.EmailField('Email address', validators=[wtf.Required(), wtf.Email()])
    username = wtf.TextField('Username (optional)', validators=[wtf.Optional()])
    password = wtf.PasswordField('Password', validators=[wtf.Required()])
    confirm_password = wtf.PasswordField('Confirm password',
                          validators=[wtf.Required(), wtf.EqualTo('password')])
    accept_rules = wtf.BooleanField('I accept the terms of service', validators=[wtf.Required()])
    recaptcha = wtf.RecaptchaField('Are you human?',
        description="Type both words. Our apologies for the inconvenience")

    def validate_username(self, field):
        existing = User.query.filter_by(username=field.data).first()
        if existing is not None:
            raise wtf.ValidationError, "That username is taken"

    def validate_email(self, field):
        existing = UserEmail.query.filter_by(email=field.data).first()
        if existing is not None:
            raise wtf.ValidationError, Markup(
                'This email address is already registered. Do you want to <a href="%s">login</a> instead?'
                % url_for('login')
                )


class PasswordResetRequestForm(wtf.Form):
    username = wtf.TextField('Username or Email', validators=[wtf.Required()])

    def validate_username(self, field):
        user = getuser(field.data)
        if user is None:
            raise wtf.ValidationError, "Could not find a user with that id"
        self.user = user


class PasswordResetForm(wtf.Form):
    password = wtf.PasswordField('New password', validators=[wtf.Required()])
    confirm_password = wtf.PasswordField('Confirm password',
                          validators=[wtf.Required(), wtf.EqualTo('password')])


class AuthorizeForm(wtf.Form):
    """
    OAuth authorization form. Has no fields and is only used for CSRF protection.
    """
    pass


class RegisterClientForm(wtf.Form):
    """
    Register a new OAuth client application
    """
    title = wtf.TextField('Application title', validators=[wtf.Required()],
        description="The name of your application")
    description = wtf.TextAreaField('Description', validators=[wtf.Required()],
        description="A description to help users recognize your application")
    owner = wtf.TextField('Organization name', validators=[wtf.Required()],
        description="Name of the organization or individual who owns this application")
    website = wtf.html5.URLField('Application website', validators=[wtf.Required(), wtf.URL()],
        description="Website where users may access this application")
    redirect_uri = wtf.html5.URLField('Redirect URI', validators=[wtf.Required(), wtf.URL()],
        description="OAuth2 Redirect URI")
    service_uri = wtf.html5.URLField('Service URI (optional)', validators=[wtf.Optional(), wtf.URL()],
        description="LastUser resource provider Service URI")
    readonly = wtf.BooleanField('Read-only access')


# --- Routes ------------------------------------------------------------------

@app.before_request
def lookup_current_user():
    """
    If there's a userid in the session, retrieve the user object and add
    to the request namespace object g.
    """
    g.user = None
    if 'userid' in session:
        g.user = User.query.filter_by(userid=session['userid']).first()


def send_email_verify_link(useremail):
    """
    Mail a verification link to the user.
    """
    msg = Message(subject="Confirm your email address",
        recipients=[useremail.email])
    msg.body = render_template("emailverify.md", useremail=useremail)
    msg.html = markdown(msg.body)
    mail.send(msg)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/favicon.ico')
def favicon():
    return redirect(url_for('static', filename='favicon.ico'), code=301)


def login_internal(user):
    g.user = user
    session['userid'] = user.userid


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = form.user
        login_internal(user)
        if form.remember.data:
            session.permanent = True
        else:
            session.permanent = False
        flash('You are now logged in', category='info')
        if 'next' in request.args:
            return redirect(request.args['next'], code=303)
        else:
            return redirect(url_for('index'), code=303)
    return render_template('login.html', form=form)


def logout_internal():
    g.user = None
    if 'userid' in session:
        del session['userid']
    if 'userid_twitter' in session:
        del session['userid_twitter']
    session.permanent = False


@app.route('/logout')
def logout():
    logout_internal()
    flash('You are now logged out', category='info')
    if 'next' in request.args:
        return redirect(request.args['next'], code=303)
    else:
        return redirect(url_for('index'), code=303)


def register_internal(username, fullname, password):
    user = User(username=username, fullname=fullname, password=password)
    db.session.add(user)
    return user


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        user = register_internal(None, form.fullname.data, form.password.data)
        if form.username.data:
            user.username = form.username.data
        useremail = UserEmailClaim(user=user, email=form.email.data)
        db.session.add(useremail)
        send_email_verify_link(useremail)
        db.session.commit()
        login_internal(user)
        flash("You are now one of us. Welcome aboard!", category='info')
        if 'next' in request.args:
            return redirect(request.args['next'], code=303)
        else:
            return redirect(url_for('index'), code=303)
    return render_template('register.html', form=form)


@app.route('/confirm/<md5sum>/<secret>')
def confirm_email(md5sum, secret):
    emailclaim = UserEmailClaim.query.filter_by(md5sum=md5sum).first()
    if emailclaim is not None:
        # Claim exists
        if emailclaim.verification_code == secret:
            # Verification code matches
            if g.user is None or g.user == emailclaim.user:
                # Not logged in as someone else.
                # Claim verified!
                useremail = emailclaim.user.add_email(emailclaim.email)
                db.session.delete(emailclaim)
                db.session.commit()
                return render_template('emailverified.html', user=emailclaim.user, useremail=useremail)
            else:
                # Logged in as someone else. Logout and ask them to login again
                # Note that we don't need them to be logged in to verify a claim.
                # Just that they shouldn't be logged in as someone else.
                # FIXME: Why ask them to login again then?
                logout_internal()
                return redirect(url_for('login', next=request.url))
        else:
            # Verification code doesn't match
            abort(403)
    else:
        # No such email claim
        abort(404)


@app.route('/reset', methods=['GET', 'POST'])
def reset():
    # User wants to reset password
    # Ask for username or email, verify it, and send a reset code
    form = PasswordResetRequestForm()
    if form.validate_on_submit():
        username = form.username.data
        user = form.user
        if '@' in username:
            # They provided an email address. Send reset email to that address
            email = username
        else:
            # Send to their existing address
            # User.email is a UserEmail object
            email = unicode(user.email)
        if not email:
            # They don't have an email address. Now what?
            # How does someone end up here?
            return render_template('reset_noemail.html')
        resetreq = PasswordResetRequest(user=user)
        db.session.add(resetreq)
        msg = Message(subject="Reset your password",
            recipients=[email])
        msg.body = render_template("emailreset.md", user=user, secret=resetreq.reset_code)
        msg.html = markdown(msg.body)
        mail.send(msg)
        db.session.commit()
        return render_template('reset_emailsent.html', email=email)

    return render_template('reset.html', form=form)


@app.route('/reset/<userid>/<secret>', methods=['GET', 'POST'])
def reset_email(userid, secret):
    logout_internal()
    user = User.query.filter_by(userid=userid).first()
    if not user:
        abort(404)
    resetreq = PasswordResetRequest.query.filter_by(user=user, reset_code=secret).first()
    if not resetreq:
        return render_template('reset_invalid.html'), 404
    if resetreq.reset_date < datetime.utcnow() - timedelta(days=1):
        # Reset code has expired (> 24 hours). Delete it
        db.session.delete(resetreq)
        db.session.commit()
        return render_template('reset_invalid.html')

    # Reset code is valid. Now ask user to choose a new password
    form = PasswordResetForm()
    if form.validate_on_submit():
        user.password = form.password.data
        db.session.commit()
        return render_template('reset_complete.html', user=user)
    return render_template('reset_choosepassword.html', user=user, form=form)


@app.route('/apps')
def client_list():
    return render_template('client_list.html', clients=Client.query.all())


@app.route('/apps/new', methods=['GET', 'POST'])
@requires_login
def client_new():
    form = RegisterClientForm()
    if form.validate_on_submit():
        client = Client()
        form.populate_obj(client)
        client.user = g.user
        client.trusted = False
        db.session.add(client)
        db.session.commit()
        return redirect(url_for('client_info', key=client.key), code=303)
    return render_template('client_edit.html', form=form)


@app.route('/apps/<key>')
def client_info(key):
    client = Client.query.filter_by(key=key).first()
    if not client:
        abort(404)
    return render_template('client_info.html', client=client)

@app.route('/apps/<key>/edit', methods=['GET', 'POST'])
def client_edit(key):
    client = Client.query.filter_by(key=key).first()
    if not client:
        abort(404)
    if client.user != g.user:
        abort(403)
    form = RegisterClientForm()
    form.title.data = client.title
    form.description.data = client.description
    form.owner.data = client.owner
    form.website.data = client.website
    form.redirect_uri.data = client.redirect_uri
    form.service_uri.data = client.service_uri
    form.readonly.data = client.readonly
    if form.validate_on_submit():
        form.populate_obj(client)
        db.session.commit()
        return redirect(url_for('client_info', key=client.key), code=303)
    return render_template('client_edit.html', form=form, edit=True)


# --- OAuth client routes -----------------------------------------------------

def get_extid_token(service):
    userid = session.get('userid_%s' % service)
    if userid:
        extid = UserExternalId.query.filter_by(service, userid).first()
        if extid:
            return {'oauth_token': extid.oauth_token,
                    'oauth_token_secret': extid.oauth_token_secret}
    return None


@twitter.tokengetter
def get_twitter_token():
    return get_extid_token('twitter')


@app.route('/login/twitter')
def login_twitter():
    next_url = request.args.get('next') or request.referrer or None
    try:
        return twitter.authorize(callback=url_for('login_twitter_authorized',
            next=next_url))
    except OAuthException, e:
        flash("Twitter login failed: %s" % unicode(e), category="error")
        next_url = next_url or url_for('index')
        return redirect(next_url)


@app.route('/login/twitter/callback')
@twitter.authorized_handler
def login_twitter_authorized(resp):
    next_url = request.args.get('next') or url_for('index')
    if resp is None:
        flash(u'You denied the request to sign in.')
        return redirect(next_url)

    extid = UserExternalId.query.filter_by(service='twitter', userid=resp['user_id']).first()
    if extid is not None:
        extid.username = resp['screen_name']
        extid.oauth_token = resp['oauth_token']
        extid.oauth_token_secret = resp['oauth_token_secret']
        db.session.commit()
        login_internal(extid.user)
        session['userid_twitter'] = resp['user_id']
        flash('You have logged in as %s' % resp['screen_name'])
    else:
        user = register_internal(None, resp['screen_name'], None)
        extid = UserExternalId(user = user,
                               service = 'twitter',
                               userid = resp['user_id'],
                               username = resp['screen_name'],
                               oauth_token = resp['oauth_token'],
                               oauth_token_secret = resp['oauth_token_secret'])
        db.session.add(extid)
        db.session.commit()
        login_internal(user)
        session['userid_twitter'] = resp['user_id']
        flash('You have logged in as %s. This is your first time here' % resp['screen_name'])

    return redirect(next_url)


# --- OAuth server routes -----------------------------------------------------

def oauth_auth_403(reason):
    """
    Returns 403 errors for /auth
    """
    return render_template('oauth403.html', reason=reason), 403


def oauth_make_auth_code(client, scope, redirect_uri):
    """
    Make an auth code for a given client. Caller must commit
    the database session for this to work.
    """
    authcode = AuthCode(user=g.user, client=client, scope=scope, redirect_uri=redirect_uri)
    authcode.code = newsecret()
    db.session.add(authcode)
    return authcode.code


def oauth_auth_success(redirect_uri, state, code):
    """
    Commit session and redirect to OAuth redirect URI
    """
    db.session.commit()
    if state is None:
        return redirect(make_redirect_url(redirect_uri, code=code), code=302)
    else:
        return redirect(make_redirect_url(redirect_uri, code=code, state=state), code=302)


def oauth_auth_error(redirect_uri, state, error, error_description=None, error_uri=None):
    """
    Auth request resulted in an error. Return to client.
    """
    params = {'error': error}
    if state is not None:
        params['state'] = state
    if error_description is not None:
        params['error_description'] = error_description
    if error_uri is not None:
        params['error_uri'] = error_uri
    return redirect(make_redirect_url(redirect_uri, **params), code=302)


@app.route('/auth', methods=['GET', 'POST'])
@requires_login
def oauth_authorize():
    """
    OAuth2 server -- authorization endpoint
    """
    form = AuthorizeForm()

    response_type = request.args.get('response_type')
    client_id = request.args.get('client_id')
    redirect_uri = request.args.get('redirect_uri')
    scope = request.args.get('scope', u'').split(u' ')
    state = request.args.get('state')

    # Validation 1.1: Client_id present
    if not client_id:
        if redirect_uri:
            return oauth_auth_error(redirect_uri, state, 'invalid_request', "client_id missing")
        else:
            return oauth_auth_403("Missing client_id")
    # Validation 1.2: Client exists
    client = Client.query.filter_by(key=client_id).first()
    if not client:
        if redirect_uri:
            return oauth_auth_error(redirect_uri, state, 'unauthorized_client')
        else:
            return oauth_auth_403("Unknown client_id")

    # Validation 1.3: Is the client active?
    if not client.active:
        return oauth_auth_error(redirect_uri, state, 'unauthorized_client')

    # Validation 1.4: Cross-check redirection_uri
    if not redirect_uri:
        redirect_uri = client.redirect_uri
    elif redirect_uri != client.redirect_uri:
        if urlparse.urlsplit(redirect_uri).hostname != urlparse.urlsplit(client.redirect_uri).hostname:
            return oauth_auth_error(redirect_uri, state, 'invalid_request', "Redirect URI hostname doesn't match")

    # Validation 2.1: Is response_type present?
    if not response_type:
        return oauth_auth_error(redirect_uri, state, 'invalid_request', "response_type missing")
    # Validation 2.2: Is response_type acceptable?
    if response_type not in [u'code']:
        return oauth_auth_error(redirect_uri, state, 'unsupported_response_type')

    # Validation 3.1: Scope present?
    if not scope:
        return oauth_auth_error(redirect_uri, state, 'invalid_request', "Scope not specified")
    if scope != [u'id']:
        # TODO: Implement support for multiple scopes
        return oauth_auth_error(redirect_uri, state, 'invalid_scope')

    # Validations complete. Now ask user for permission
    # If the client is trusted (LastUser feature, not in OAuth2 spec), don't ask user.
    # The client does not get access to any data here -- they still have to authenticate to /token.
    if request.method == 'GET' and client.trusted:
        # Return auth token. No need for user confirmation
        return oauth_auth_success(redirect_uri, state, oauth_make_auth_code(client, scope, redirect_uri))

    # Ask user. validate_on_submit() only validates if request.method == 'POST'
    if form.validate_on_submit():
        if 'accept' in request.form:
            # User said yes. Return an auth code to the client
            return oauth_auth_success(redirect_uri, state, oauth_make_auth_code(client, scope, redirect_uri))
        elif 'deny' in request.form:
            # User said no. Return "access_denied" error (OAuth2 spec)
            return oauth_auth_error(redirect_uri, state, 'access_denied')
        # else: shouldn't happen, so just show the form again

    # GET request or POST with invalid CSRF
    return render_template('authorize.html',
        form=form,
        client=client,
        redirect_uri=redirect_uri,
        scope=scope, # TODO: Show friendly message
        state=state, # TODO: merge this into redirect_uri
        )


def oauth_token_error(error, error_description=None, error_uri=None):
    params = {'error': error}
    if error_description is not None:
        params['error_description'] = error_description
    if error_uri is not None:
        params['error_uri'] = error_uri
    response = jsonify(**params)
    response.status_code = 400
    return response


def oauth_make_token(user, client, scope):
    token = AuthToken(user=user, client=client, scope=scope)
    token.token = newid()
    token.refresh_token = newid()
    token.secret = newsecret()
    db.session.add(token)
    return token


def oauth_token_success(token, **params):
    params['access_token'] = token.token
    params['token_type'] = token.token_type
    params['scope'] = u' '.join(token.scope)
    if token.validity:
        params['expires_in'] = token.validity
        params['refresh_token'] = token.refresh_token
    response = jsonify(**params)
    response.headers['Cache-Control'] = 'no-store'
    db.session.commit()
    return response


@app.route('/token', methods=['POST'])
def oauth_token():
    """
    OAuth2 server -- token endpoint
    """
    # Always required parameters
    # TODO: Support other forms of client authentication
    grant_type = request.form.get('grant_type')
    client_id = request.form.get('client_id')
    client_secret = request.form.get('client_secret')
    scope = request.form.get('scope', u'').split(u' ')
    # if grant_type == 'authorization_code' (POST)
    code = request.form.get('code')
    redirect_uri = request.form.get('redirect_uri')
    # if grant_type == 'password' (GET)
    username = request.form.get('username')
    password = request.form.get('password')

    # Validations 1: Required parameters
    if not grant_type or not client_id or not client_secret:
        return oauth_token_error('invalid_request')
    # grant_type == 'refresh_token' is not supported. All tokens are permanent unless revoked
    if grant_type not in ['authorization_code', 'client_credentials', 'password']:
        return oauth_token_error('unsupported_grant_type')

    # Validations 2: client
    client = Client.query.filter_by(key=client_id).first()
    if not client or not client.active:
        return oauth_token_error('invalid_client', "Unknown client_id")
    if client_secret != client.secret:
        return oauth_token_error('invalid_client', "client_secret mismatch")
    if grant_type == 'password' and not client.trusted:
        return oauth_token_error('unauthorized_client', "Client not trusted for password grant_type")

    if grant_type == 'authorization_code':
        # Validations 3: auth code
        authcode = AuthCode.query.filter_by(code=code, client=client).first()
        if not authcode:
            return oauth_token_error('invalid_grant', "Unknown auth code")
        if authcode.datetime < (datetime.utcnow()-timedelta(minutes=1)): # XXX: Time limit: 1 minute
            return oauth_token_error('invalid_grant', "Expired auth code")
        # Validations 3.1: scope in authcode
        if not scope:
            return oauth_token_error('invalid_scope', "Scope is blank")
        if not set(scope).issubset(set(authcode.scope)):
            raise oauth_token_error('invalid_scope', "Scope expanded")
        else:
            # Scope not provided. Use whatever the authcode allows
            scope = authcode.scope
        if redirect_uri != authcode.redirect_uri:
            return oauth_token_error('invalid_client', "redirect_uri does not match")

        token = oauth_make_token(user=authcode.user, client=client, scope=scope)
        return oauth_token_success(token)

    elif grant_type == 'client_credentials':
        token = oauth_make_token(user=None, client=client, scope=scope)
        return oauth_token_success(token)
    elif grant_type == 'password':
        # Validations 4.1: password grant_type is only for trusted clients
        if not client.trusted:
            # Refuse to untrusted clients
            return oauth_token_error('unauthorized_client', "Client is not trusted for password grant_type")
        # Validations 4.2: Are username and password provided and correct?
        if not username or not password:
            return oauth_token_error('invalid_request', "Username or password not provided")
        user = getuser(username)
        if not user:
            return oauth_token_error('invalid_client', "No such user") # XXX: invalid_client doesn't seem right
        if not user.check_password(password):
            return oauth_token_error('invalid_client', "Password mismatch")

        # All good. Grant access
        token = oauth_make_token(user=user, client=client, scope=scope)
        return oauth_token_success(token)


# --- Error handlers ----------------------------------------------------------

@app.errorhandler(403)
def error_403(e):
    return render_template('403.html'), 403


@app.errorhandler(404)
def error_404(e):
    return render_template('404.html'), 404


@app.errorhandler(500)
def error_500(e):
    return render_template('500.html'), 500


# --- Profile routes ----------------------------------------------------------

@app.route('/profile')
@requires_login
def profile_current():
    pass


@app.route('/profile/edit', methods=['GET', 'POST'])
@requires_login
def profile_edit():
    pass


# Note: This must always be the last route in the app
@app.route('/<profileid>')
def profile(profileid):
    user = User.query.filter_by(username=profileid).first()
    if user is None:
        if len(profileid) == 22:
            user = User.query.filter_by(userid=profileid).first()
        elif len(profileid) == 32:
            useremail = UserEmail.query.filter_by(md5sum=profileid).first()
            if useremail:
                user = useremail.user
    if user is None:
        abort(404)
    if user.profileid() != profileid:
        return redirect(url_for('profile', profileid=user.profileid()), code=301)

    return render_template('profile.html', user=user)


# --- UI Messages -------------------------------------------------------------

for msg in ['MESSAGE_FOOTER']:
    app.config[msg] = Markup(markdown(app.config.get(msg, '')))

# --- Logging -----------------------------------------------------------------

file_handler = logging.FileHandler(app.config['LOGFILE'])
file_handler.setLevel(logging.WARNING)
app.logger.addHandler(file_handler)
if app.config['ADMINS']:
    mail_handler = logging.handlers.SMTPHandler(app.config['MAIL_SERVER'],
        app.config['DEFAULT_MAIL_SENDER'][1],
        app.config['ADMINS'],
        'lastuser failure',
        credentials = (app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD']))
    mail_handler.setLevel(logging.ERROR)
    app.logger.addHandler(mail_handler)


# --- Runtime -----------------------------------------------------------------

if __name__=='__main__':
    db.create_all()
    app.run('0.0.0.0', port=7000, debug=True)
