# -*- coding: utf-8 -*-

from functools import wraps

from urllib import urlencode, quote
from urllib2 import urlopen, URLError
from urlparse import parse_qs
from coaster import valid_username

from flask import request, session, redirect, flash, url_for, json
from flask.ext.oauth import OAuth, OAuthException  # OAuth 1.0a
from httplib import BadStatusLine

from lastuserapp import app
from lastuserapp.models import db, UserExternalId, UserEmail, User
from lastuserapp.views.helpers import get_next_url, login_internal, register_internal
from lastuserapp.utils import get_gravatar_md5sum

# OAuth 1.0a handlers
oauth = OAuth()
twitter = oauth.remote_app('twitter',
    base_url='https://api.twitter.com/1/',
    request_token_url='https://api.twitter.com/oauth/request_token',
    access_token_url='https://api.twitter.com/oauth/access_token',
    authorize_url='https://api.twitter.com/oauth/authenticate',
    consumer_key=app.config.get('OAUTH_TWITTER_KEY'),
    consumer_secret=app.config.get('OAUTH_TWITTER_SECRET'),
)


def get_extid_token(service):
    useridinfo = session.get('userid_external')
    if useridinfo:
        if service != useridinfo.get('service'):
            return None
        extid = UserExternalId.query.filter_by(service=service, userid=useridinfo['userid']).first()
        if extid:
            return {'oauth_token': extid.oauth_token,
                    'oauth_token_secret': extid.oauth_token_secret}
    return None


@twitter.tokengetter
def get_twitter_token():
    return get_extid_token('twitter')


@app.route('/login/twitter')
def login_twitter():
    next_url = get_next_url(referrer=False)
    try:
        return twitter.authorize(callback=url_for('login_twitter_authorized',
            next=next_url))
    except OAuthException, e:
        flash("Twitter login failed: %s" % unicode(e), category="error")
        return redirect(url_for('login'))


def twitter_exception_handler(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except (OAuthException, BadStatusLine), e:
            flash("Twitter login failed: %s" % unicode(e), category="error")
            return redirect(url_for('login'))
    return decorated_function


@app.route('/login/twitter/callback')
@twitter_exception_handler
@twitter.authorized_handler
def login_twitter_authorized(resp):
    next_url = get_next_url()
    if resp is None:
        flash(u'You denied the request to login via Twitter.')
        return redirect(next_url)

    # Try to read more from the user's Twitter profile
    try:
        twinfo = json.loads(urlopen('http://api.twitter.com/1/users/lookup.json?%s' % urlencode({'user_id': resp['user_id']})).read())[0]
        return_url = config_external_id(service='twitter',
                                        service_name='Twitter',
                                        user=None,
                                        userid=resp['user_id'],
                                        username=resp['screen_name'],
                                        fullname=twinfo.get('name', '@' + resp['screen_name']),
                                        avatar=twinfo.get('profile_image_url').replace("normal.", "bigger."),
                                        access_token=resp['oauth_token'],
                                        secret=resp['oauth_token_secret'],
                                        token_type=None,
                                        next_url=next_url)
        if return_url is not None:
            next_url = return_url
    except URLError:
        twinfo = {}

    # Redirect with 303 because users hitting the back button
    # cause invalid/expired token errors from Twitter
    return redirect(next_url, code=303)


# FIXME: Don't place config at module scope
github = {
  'key': app.config.get('OAUTH_GITHUB_KEY'),
  'secret': app.config.get('OAUTH_GITHUB_SECRET'),
  'auth_url': "https://github.com/login/oauth/authorize?client_id=%s&redirect_uri=%s",
  'token_url': "https://github.com/login/oauth/access_token",
  'user_info': "https://api.github.com/user?access_token=%s"
}

# XXX: GitHub has a non-standard OAuth flow, so we can't use the Flask-OAuth library
@app.route('/login/github')
def login_github():
    next_url = get_next_url(referrer=False)
    try:
        return redirect(github['auth_url'] % (github['key'], url_for('login_github_authorized', _external=True, next=quote(next_url))))
    except OAuthException, e:
        flash(u"GitHub login failed: %s" % unicode(e), category="error")
        return redirect(next_url)


@app.route('/login/github/callback')
def login_github_authorized():
    next_url = get_next_url()

    if request.args.get('error'):
        if request.args['error'] == 'user_denied':
            flash(u"You denied the GitHub login request", category='error')
        else:
            flash(u"GitHub login failed", category="error")
        return redirect(next_url, code=303)

    code = request.args.get('code', None)
    params = urlencode({
      'client_id': github['key'],
      'client_secret': github['secret'],
      'code': code
    })

    # Try to read more from the user's Github profile
    try:
        response = urlopen(github['token_url'], params).read()
        respdict = parse_qs(response)
        access_token = respdict['access_token'][0]
        token_type = respdict['token_type'][0]
        ghinfo = json.loads(urlopen(github['user_info'] % access_token).read())
        md5sum = get_gravatar_md5sum(ghinfo['avatar_url'])
        user = None
        if md5sum:
            # Look for an existing user account
            useremail = UserEmail.query.filter_by(md5sum=md5sum).first()
            if useremail:
                user = useremail.user
        return_url = config_external_id(service='github',
                                        service_name='GitHub',
                                        user=user,
                                        userid=ghinfo.get('login'),
                                        username=ghinfo.get('login'),
                                        fullname=ghinfo.get('name'),
                                        avatar=ghinfo.get('avatar_url'),
                                        access_token=access_token,
                                        secret=github['secret'],
                                        token_type=token_type,
                                        next_url=next_url)
        if return_url is not None:
            next_url = return_url
    except URLError, e:
        ghinfo = {}
        flash(u"GitHub login failed" % unicode(e), category="error")

    # As with Twitter, redirect with code 303
    return redirect(next_url, code=303)


def config_external_id(service, service_name, user, userid, username, fullname, avatar, access_token, secret, token_type, next_url):
    session['avatar_url'] = avatar
    extid = UserExternalId.query.filter_by(service=service, userid=userid).first()
    session['userid_external'] = {'service': service, 'userid': userid, 'username': username}

    if extid is not None:
        extid.oauth_token = access_token
        extid.oauth_token_secret = secret
        extid.oauth_token_type = token_type
        extid.username = username  # For twitter: update username if it changed
        db.session.commit()
        login_internal(extid.user)
        flash('You have logged in as %s via %s' % (username, service_name))
        return
    else:
        # If caller wants this id connected to an existing user, do it.
        if not user:
            user = register_internal(None, fullname, None)
        extid = UserExternalId(user=user, service=service, userid=userid, username=username,
                               oauth_token=access_token, oauth_token_secret=secret,
                               oauth_token_type=token_type)
        # If the service provided a username that is valid for LastUser and not already in use, assign
        # it to this user
        if valid_username(username):
            if User.query.filter_by(username=username).first() is None:
                user.username = username
        db.session.add(extid)
        db.session.commit()
        login_internal(user)
        if user:
            flash('You have logged in as %s via %s. This id has been linked to your existing account' % (username, service_name))
        else:
            flash('You have logged in as %s via %s. This is your first time here' % (username, service_name))

        # redirect the user to profile edit page to fill in more details
        return url_for('profile_edit', _external=True, next=next_url)
