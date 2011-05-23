# -*- coding: utf-8 -*-

from functools import wraps
import urlparse

from flask import g, request, session, flash, redirect, url_for, render_template, Markup, escape

from lastuserapp import app
from lastuserapp.models import db, User


@app.before_request
def lookup_current_user():
    """
    If there's a userid in the session, retrieve the user object and add
    to the request namespace object g.
    """
    g.user = None
    if 'userid' in session:
        g.user = User.query.filter_by(userid=session['userid']).first()


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


def get_next_url(referrer=False, external=False):
    """
    Get the next URL to redirect to. Don't return external URLs unless
    explicitly asked for. This is to protect the site from being an unwitting
    redirector to external URLs.
    """
    next_url = request.args.get('next', '')
    if not external:
        if next_url.startswith('http:') or next_url.startswith('https:') or next_url.startswith('//'):
            # Do the domains match?
            if urlparse.urlsplit(next_url).hostname != urlparse.urlsplit(request.url).hostname:
                next_url = ''
    if referrer:
        return next_url or request.referrer or url_for('index')
    else:
        return next_url or url_for('index')


def login_internal(user):
    g.user = user
    session['userid'] = user.userid


def logout_internal():
    g.user = None
    session.pop('userid', None)
    session.pop('userid_external', None)
    session.permanent = False


def register_internal(username, fullname, password):
    user = User(username=username, fullname=fullname, password=password)
    db.session.add(user)
    return user


def render_form(form, title, message='', formid='form', submit='Submit', ajax=False):
    if request.is_xhr and ajax:
        return render_template('ajaxform.html', form=form, title=title, message=message, formid=formid, submit=submit)
    else:
        return render_template('autoform.html', form=form, title=title, message=message, formid=formid, submit=submit, ajax=ajax)


def render_message(title, message):
    if request.is_xhr:
        return Markup("<p>%s</p>" % escape(message))
    else:
        return render_template('message.html', title=title, message=message)


def render_redirect(url, code=302):
    if request.is_xhr:
        return render_template('redirect.html', url=Markup(url))
    else:
        return redirect(url, code=code)


@app.template_filter('usessl')
def usessl(url):
    """
    Convert a URL to https:// if SSL is enabled in site config
    """
    if not app.config.get('USE_SSL'):
        return url
    if url.startswith('//'): # //www.example.com/path
        return 'https:' + url
    if url.startswith('/'): # /path
        url = os.path.join(request.url_root, url[1:])
    if url.startswith('http:'): # http://www.example.com
        url = 'https:' + url[5:]
    return url


@app.template_filter('nossl')
def usessl(url):
    """
    Convert a URL to http:// if using SSL
    """
    if url.startswith('//'):
        return 'http:' + url
    if url.startswith('/') and request.url.startswith('https:'): # /path and SSL is on
        url = os.path.join(request.url_root, url[1:])
    if url.startswith('https://'):
        return 'http:' + url[6:]
    return url


# The order of these imports is critical.
# index.py must always be first.
# profile.py must always be last

import lastuserapp.views.index
import lastuserapp.views.login
import lastuserapp.views.oauthclient
import lastuserapp.views.openidclient
import lastuserapp.views.oauth
import lastuserapp.views.client
import lastuserapp.views.httperror
import lastuserapp.views.profile
