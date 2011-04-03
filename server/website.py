#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Logging
import logging
# Decorators
from functools import wraps
# Id generation
import uuid
from base64 import b64encode
# Flask and extensions
from flask import (Flask, render_template, g, flash, request, redirect,
                   session, url_for)
from flaskext.sqlalchemy import SQLAlchemy
import flaskext.wtf as wtf
from flaskext.mail import Mail, Message
from flaskext.assets import Environment, Bundle
# Werkzeug, Flask's base library
from werkzeug import generate_password_hash, check_password_hash
# Other
from markdown import markdown


# --- Status codes ------------------------------------------------------------

class EMAIL:
    UNVERIFIED  = 0 # Not verified
    PENDING     = 1 # Pending; verification code sent
    VERIFIED    = 2 # Verified


# --- Globals -----------------------------------------------------------------

app = Flask(__name__)
db = SQLAlchemy(app)
assets = Environment(app)
mail = Mail()


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
            flash(u'You need to be logged in for this page.')
            return redirect(url_for('login', next=request.path))
        return f(*args, **kwargs)
    return decorated_function


def newid():
    """
    Return a new random id that is exactly 22 characters long.
    """
    return b64encode(uuid.uuid4().bytes, altchars=',-').replace('=', '')


# --- Models ------------------------------------------------------------------

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    userid = db.Column(db.String(22), nullable=False, default=newid)
    fullname = db.Column(db.Unicode(80))
    username = db.Column(db.Unicode(80), unique=True, nullable=True)
    pw_hash = db.Column(db.String(80))

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
        return check_password_hash(self.pw_hash, password)

    def __repr__(self):
        return '<User %r>' % (self.username or self.userid)


class UserEmail(db.Model):
    __tablename__ = 'useremail'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relation(User, primaryjoin=user_id == User.id)
    email = db.Column(db.Unicode(80), unique=True, nullable=True)
    primary = db.Column(db.Boolean, nullable=False, default=False)
    status = db.Column(db.Integer, nullable=False, default=EMAIL.UNVERIFIED)


# --- Forms -------------------------------------------------------------------

class LoginForm(wtf.Form):
    username = wtf.TextField('Username or Email', validators=[wtf.Required()])
    password = wtf.PasswordField('Password', validators=[wtf.Required()])

    def getuser(self, name):
        if '@' in name:
            return UserEmail.query.filter_by(email=name).first().user
        else:
            return User.query.filter_by(username=name).first()

    def validate_username(self, field):
        existing = self.getuser(field.data)
        if existing is None:
            raise wtf.ValidationError, "User does not exist"

    def validate_password(self, field):
        user = self.getuser(self.username.data)
        if user is None or not user.check_password(field.data):
            raise wtf.ValidationError, "Invalid password"
        self.user = user


class RegisterForm(wtf.Form):
    fullname = wtf.TextField('Full name', validators=[wtf.Required()])
    email = wtf.html5.EmailField('Email Address', validators=[wtf.Required(), wtf.Email()])
    username = wtf.TextField('Username (optional)')
    password = wtf.PasswordField('Password', validators=[wtf.Required()])
    confirm_password = wtf.PasswordField('Confirm Password',
                          validators=[wtf.Required(), wtf.EqualTo('password')])
    accept_rules = wtf.BooleanField('I accept the terms of service', validators=[wtf.Required()])

    def validate_username(self, field):
        existing = User.query.filter_by(username=field.data).first()
        if existing is not None:
            raise wtf.ValidationError, "That username is taken"

    def validate_email(self, field):
        existing = UserEmail.query.filter_by(email=field.data).first()
        if existing is not None:
            raise wtf.ValidationError, "That email is already registered. Do you want to login?"


# --- Routes ------------------------------------------------------------------

@app.before_request
def lookup_current_user():
    g.user = None
    if 'userid' in session:
        g.user = User.query.filter_by(userid=session['userid']).first()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/favicon.ico')
def favicon():
    return redirect(url_for('static', filename='favicon.ico'), code=301)


@app.route('/login', methods=('GET', 'POST'))
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = form.user
        g.user = user
        session['userid'] = user.userid
        flash('You are now logged in', category='info')
        if 'next' in request.args:
            return redirect(request.args['next'], code=303)
        else:
            return redirect(url_for('index'), code=303)
    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    g.user = None
    del session['userid']
    flash('You are now logged out', category='info')
    if 'next' in request.args:
        return redirect(request.args['next'], code=303)
    else:
        return redirect(url_for('index'), code=303)


@app.route('/register', methods=('GET', 'POST'))
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        user = User()
        form.populate_obj(user)
        useremail = UserEmail(user=user, primary=True, email=form.email.data)
        db.session.add(user)
        db.session.add(useremail)
        db.session.commit()
        g.user = user # Not really required since we're not rendering a page
        session['userid'] = user.userid
        flash('Yay! You are now one of us. Welcome aboard!', category='info')
        if 'next' in request.args:
            return redirect(request.args['next'], code=303)
        else:
            return redirect(url_for('index'), code=303)
    return render_template('register.html', form=form)


# --- Settings ----------------------------------------------------------------

app.config.from_object(__name__)
try:
    app.config.from_object('settings')
except ImportError:
    import sys
    print >> sys.stderr, "Please create a settings.py with the necessary settings. See settings-sample.py."
    print >> sys.stderr, "You may use the site without these settings, but some features may not work."

mail.init_app(app)


# --- Logging -----------------------------------------------------------------

file_handler = logging.FileHandler(app.config['LOGFILE'])
file_handler.setLevel(logging.WARNING)
app.logger.addHandler(file_handler)
if app.config['ADMINS']:
    mail_handler = logging.handlers.SMTPHandler(app.config['MAIL_SERVER'],
        app.config['DEFAULT_MAIL_SENDER'][1],
        app.config['ADMINS'],
        'hasgeek-jobs failure',
        credentials = (app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD']))
    mail_handler.setLevel(logging.ERROR)
    app.logger.addHandler(mail_handler)


# --- Runtime -----------------------------------------------------------------

if __name__=='__main__':
    db.create_all()
    app.run('0.0.0.0', port=7000, debug=True)
