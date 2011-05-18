# -*- coding: utf-8 -*-

from datetime import datetime, timedelta

from flask import g, redirect, request, session, flash, render_template, url_for, abort

from lastuserapp import app
from lastuserapp.openidclient import oid
from lastuserapp.mailclient import send_email_verify_link, send_password_reset_link
from lastuserapp.models import db, User, UserEmailClaim, PasswordResetRequest
from lastuserapp.forms import LoginForm, OpenIdForm, RegisterForm, PasswordResetForm, PasswordResetRequestForm
from lastuserapp.views import get_next_url, login_internal, logout_internal, register_internal


@app.route('/login', methods=['GET', 'POST'])
@oid.loginhandler
def login():
    # If user is already logged in, send them back
    if g.user:
        return redirect(get_next_url(referrer=True), code=303)

    loginform = LoginForm()
    openidform = OpenIdForm(csrf_session_key='csrf_openid')

    if request.method == 'GET':
        openidform.openid.data = 'http://'

    formid = request.form.get('form.id')
    if request.method == 'POST' and formid == 'openid':
        if openidform.validate():
            return oid.try_login(openidform.openid.data,
                ask_for=['email', 'fullname', 'nickname'])
    elif request.method == 'POST' and formid == 'login':
        if loginform.validate():
            user = loginform.user
            login_internal(user)
            if loginform.remember.data:
                session.permanent = True
            else:
                session.permanent = False
            flash('You are now logged in', category='info')
            return redirect(get_next_url(), code=303)
    return render_template('login.html', openidform=openidform, loginform=loginform,
        oiderror=oid.fetch_error(), oidnext=oid.get_next_url())

@app.route('/logout')
def logout():
    logout_internal()
    flash('You are now logged out', category='info')
    return redirect(get_next_url(), code=303)


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
        send_password_reset_link(email=email, user=user, secret=resetreq.reset_code)
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
