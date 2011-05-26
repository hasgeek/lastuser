# -*- coding: utf-8 -*-

from flask import session, redirect, render_template, flash, url_for
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
        extid = UserExternalId.query.filter_by(service, useridinfo['userid']).first()
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

    extid = UserExternalId.query.filter_by(service='twitter', userid=resp['user_id']).first()
    if extid is not None:
        extid.username = resp['screen_name']
        extid.oauth_token = resp['oauth_token']
        extid.oauth_token_secret = resp['oauth_token_secret']
        db.session.commit()
        login_internal(extid.user)
        session['userid_external'] = {'service': 'twitter', 'userid': resp['user_id'], 'username': resp['screen_name']}
        flash('You have logged in as %s via Twitter' % resp['screen_name'])
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
        session['userid_external'] = {'service': 'twitter', 'userid': resp['user_id']}
        flash('You have logged in as %s via Twitter. This is your first time here' % resp['screen_name'])

    return redirect(next_url)
