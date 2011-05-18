# -*- coding: utf-8 -*-

from flask import redirect, session, flash
from flaskext.openid import OpenID

from lastuserapp import app
from lastuserapp.models import db, UserExternalId, UserEmail, UserEmailClaim
from lastuserapp.views import login_internal, register_internal

oid = OpenID(app)


@app.route('/login/google')
@oid.loginhandler
def login_google():
    return oid.try_login('https://www.google.com/accounts/o8/id',
        ask_for=['email', 'fullname', 'nickname'])


@oid.after_login
def login_openid_success(resp):
    """
    Called when OpenID login succeeds
    """
    openid = resp.identity_url
    extid = UserExternalId.query.filter_by(service="openid", userid=openid).first()
    if extid is not None:
        login_internal(extid.user)
        session['userid_external'] = {'service': 'openid', 'userid': openid}
        flash("You are now logged in", category='info')
        return redirect(oid.get_next_url())
    else:
        firsttime = True
        if resp.email:
            useremail = UserEmail.query.filter_by(email=resp.email).first()
            if openid.startswith('https://profiles.google.com/') or openid.startswith('https://www.google.com/accounts/o8/id?id='):
                # Google id. Trust the email address.
                if useremail:
                    # User logged in previously using a different Google OpenID endpoint
                    # Add this new endpoint to the existing user account
                    user = useremail.user
                    firsttime = False
                else:
                    # No previous record for email address, so register a new user
                    user = register_internal(None, resp.fullname or resp.nickname or openid, None)
                    user.add_email(resp.email, primary=True)
            else:
                # Not a Google id. Do not trust an OpenID-provided email address.
                # This must be treated as a claim, not as a confirmed email address.
                # Step 1. Make a new account
                user = register_internal(None, resp.fullname or resp.nickname or openid, None)
                # Step 2. If this email address is not already known, register a claim.
                # If it is an existing registered email address, ignore it. OpenID metadata
                # cannot be trusted; anyone can setup an OpenID server that will allow the user
                # to claim any email address.
                if not useremail:
                    emailclaim = UserEmailClaim(user=user, email=resp.email)
                    db.session.add(emailclaim)
                    send_email_verify_link(emailclaim)
        else:
            # First login and no email address provided. Create a new user account
            user = register_internal(None, resp.fullname or resp.nickname or openid, None)
        # Record this OpenID for the user
        extid = UserExternalId(user = user,
                               service = 'openid',
                               userid = openid,
                               username = None,
                               oauth_token = None,
                               oauth_token_secret = None)
        db.session.add(extid)
        db.session.commit()
        login_internal(user)
        session['userid_external'] = {'service': 'openid', 'userid': openid}
        if firsttime:
            flash("You are now logged in. This is your first time here", category='info')
        else:
            flash("You are now logged in.", category='info')
        return redirect(oid.get_next_url())
