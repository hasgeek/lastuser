# -*- coding: utf-8 -*-

from urllib import urlencode
from urllib2 import urlopen, URLError

from flask import request, session, redirect, render_template, flash, url_for, json
from flaskext.oauth import OAuth, OAuthException # OAuth 1.0a

from lastuserapp import app
from lastuserapp.models import db, UserExternalId
from lastuserapp.views import get_next_url, login_internal, register_internal

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
        return redirect(next_url)


@app.route('/login/twitter/callback')
@twitter.authorized_handler
def login_twitter_authorized(resp):
    next_url = get_next_url()
    if resp is None:
        flash(u'You denied the request to login via Twitter.')
        return redirect(next_url)

    # Try to read more from the user's Twitter profile
    try:
        twinfo = json.loads(urlopen('http://api.twitter.com/1/users/lookup.json?%s' % urlencode({'user_id': resp['user_id']})).read())[0]
        return_url = config_external_id('twitter', resp['user_id'], resp['screen_name'], twinfo.get('name', '@'+resp['screen_name']), 
                      twinfo.get('profile_image_url').replace("normal.","bigger."), resp['oauth_token'], resp['oauth_token_secret'], next_url)
        if(return_url is not None):
            next_url = return_url
    except URLError:
        twinfo = {}

    return redirect(next_url)


github = {
  'key': app.config.get('OAUTH_GITHUB_KEY'),
  'secret': app.config.get('OAUTH_GITHUB_SECRET'),
  'auth_url': "https://github.com/login/oauth/authorize?client_id=%s&redirect_uri=%s",
  'token_url': "https://github.com/login/oauth/access_token",
  'user_info': "https://api.github.com/user?access_token=%s"
}

@app.route('/login/github')
def login_github():
    next_url = get_next_url(referrer=False)
    try:
        return redirect(github['auth_url'] % (github['key'], url_for('login_github_authorized', _external=True, next=next_url)))
    except OAuthException, e:
        flash("Github login failed: %s" % unicode(e), category="error")
        return redirect(next_url)


@app.route('/login/github/callback')
def login_github_authorized():
    code = request.args.get('code', None)
    next_url = get_next_url()
    params = urlencode({
      'client_id': github['key'], 
      'client_secret': github['secret'], 
      'code': code
    })
    
    # Try to read more from the user's Github profile
    try:
        response = urlopen(github['token_url'], params).read()
        access_token = response.partition("&")[0].partition("=")[2] # TODO: clean this up & handle any possible errors
        ghinfo = json.loads(urlopen(github['user_info'] % access_token).read())
        return_url = config_external_id('github', ghinfo.get('login'), ghinfo.get('name'), ghinfo.get('name'), 
                      ghinfo.get('avatar_url'), access_token, github['secret'], next_url)
        if(return_url is not None):
            next_url = return_url
    except URLError:
        ghinfo = {}
    
    return redirect(next_url)


def config_external_id(service, userid, username, handle, avatar, access_token, secret, next_url):
    session['avatar_url'] = avatar
    extid = UserExternalId.query.filter_by(service=service, userid=userid).first()
    session['userid_external'] = {'service': service, 'userid': userid, 'username': username}

    if extid is not None:
        extid.oauth_token = access_token
        extid.oauth_token_secret = secret
        #extid.username = username # why setting this ?? ain't the username already in the DB ??
        db.session.commit()
        login_internal(extid.user)
        flash('You have logged in as %s via %s' % (username, service.capitalize()))
        return
    else:
        user = register_internal(userid, handle, None)
        user.username = username.lower()
        extid = UserExternalId(user = user, service = service, userid = userid, username = username,
                               oauth_token = access_token, oauth_token_secret = secret)
        db.session.add(extid)
        db.session.commit()
        login_internal(user)
        flash('You have logged in as %s via %s. This is your first time here, so please fill in a \
              few details about yourself' % (username, service.capitalize()))
        
        # redirect the user to profile edit page to fill in more details
        return url_for('profile_edit', _external=True, next=next_url)

    