# -*- coding: utf-8 -*-

from datetime import datetime, timedelta
import urlparse

from flask import g, redirect, request, session, flash, render_template, url_for, abort, Markup, escape

from lastuserapp import app
from lastuserapp.views.openidclient import oid
from lastuserapp.mailclient import send_email_verify_link, send_password_reset_link
from lastuserapp.models import db, User, UserEmailClaim, PasswordResetRequest, Client
from lastuserapp.forms import LoginForm, OpenIdForm, RegisterForm, PasswordResetForm, PasswordResetRequestForm
from lastuserapp.views import (get_next_url, login_internal, logout_internal, register_internal,
    render_form, render_message, render_redirect)


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
            return render_redirect(get_next_url(), code=303)
    if request.is_xhr and formid == 'login':
        return render_template('forms/loginform.html', loginform=loginform)
    else:
        return render_template('login.html', openidform=openidform, loginform=loginform,
            oiderror=oid.fetch_error(), oidnext=oid.get_next_url())


# TODO: Move this into settings.py
logout_errormsg = "We detected an unauthorized attempt to log you out. "\
            "If you really did intend to logout, please click on the logout link again."

def logout_user():
    """
    User-initiated logout
    """
    if not request.referrer or (urlparse.urlsplit(request.referrer).hostname != urlparse.urlsplit(request.url).hostname):
        # TODO: present a logout form
        flash(logout_errormsg, 'error')
        return redirect(url_for('index'))
    else:
        logout_internal()
        flash('You are now logged out', category='info')
        return redirect(get_next_url())


def logout_client():
    """
    Client-initiated logout
    """
    client = Client.query.filter_by(key=request.args['client_id']).first()
    if client is None:
        # No such client. Possible CSRF. Don't logout and don't send them back
        flash(logout_errormsg, 'error')
        return redirect(url_for('index'))
    if client.trusted:
        # This is a trusted client. Does the referring domain match?
        clienthost = urlparse.urlsplit(client.redirect_uri).hostname
        if request.referrer:
            if clienthost != urlparse.urlsplit(request.referrer).hostname:
                # Doesn't. Don't logout and don't send back
                flash(logout_errormsg, 'error')
                return redirect(url_for('index'))
        # else: no referrer? Either stripped out by browser or a proxy, or this is a direct link.
        # We can't do anything about that, so assume it's a legit case.
        #
        # If there is a next destination, is it in the same domain?
        if 'next' in request.args:
            if clienthost != urlparse.urlsplit(request.args['next']).hostname:
                # Doesn't. Assume CSRF and redirect to index without logout
                flash(logout_errormsg, 'error')
                return redirect(url_for('index'))
        # All good. Log them out and send them back
        logout_internal()
        return redirect(get_next_url(external=True))
    else:
        # We know this client, but it's not trusted. Send back without logout.
        return redirect(get_next_url(external=True))


@app.route('/logout')
def logout():

    # Logout, but protect from CSRF attempts
    if 'client_id' in request.args:
        return logout_client()
    else:
        # If this is not a logout request from a client, check if all is good.
        return logout_user()

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        user = register_internal(None, form.fullname.data, form.password.data)
        if form.username.data:
            user.username = form.username.data
        useremail = UserEmailClaim(user=user, email=form.email.data)
        db.session.add(useremail)
        db.session.commit()
        send_email_verify_link(useremail)
        login_internal(user)
        flash("You are now one of us. Welcome aboard!", category='info')
        if 'next' in request.args:
            return redirect(request.args['next'], code=303)
        else:
            return redirect(url_for('index'), code=303)
    return render_form(form=form, title='Register an account', formid='register', submit='Register')


@app.route('/confirm/<md5sum>/<secret>')
def confirm_email(md5sum, secret):
    emailclaim = UserEmailClaim.query.filter_by(md5sum=md5sum).first()
    if emailclaim is not None:
        # Claim exists
        if emailclaim.verification_code == secret:
            # Verification code matches
            if g.user is None or g.user == emailclaim.user:
                # Not logged in as someone else
                # Claim verified!
                useremail = emailclaim.user.add_email(emailclaim.email, primary=emailclaim.user.email is None)
                db.session.delete(emailclaim)
                db.session.commit()
                return render_message(title="Email address verified",
                    message=Markup("Hello %s! Your email address <code>%s</code> has now been verified." % (
                        escape(emailclaim.user.fullname), escape(useremail.email))))
            else:
                # Logged in as someone else. Abort
                abort(403)
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
        if '@' in username and not username.startswith('@'):
            # They provided an email address. Send reset email to that address
            email = username
        else:
            # Send to their existing address
            # User.email is a UserEmail object
            email = unicode(user.email)
        if not email:
            # They don't have an email address. Maybe they logged in via Twitter
            # and set a local username and password, but no email. Could happen.
            return render_message(title="Reset password", message=Markup(
            """
            We do not have an email address for your account and therefore cannot
            email you a reset link. Please contact
            <a href="mailto:%s">%s</a> for assistance.
            """ % (escape(app.config['SITE_SUPPORT_EMAIL']), escape(app.config['SITE_SUPPORT_EMAIL']))))
        resetreq = PasswordResetRequest(user=user)
        db.session.add(resetreq)
        send_password_reset_link(email=email, user=user, secret=resetreq.reset_code)
        db.session.commit()
        return render_message(title="Reset password", message=Markup(
            u"""
            You were sent an email at <code>%s</code> with a link to reset your password.
            Please check your email. If it doesn’t arrive in a few minutes,
            it may have landed in your spam or junk folder.
            The reset link is valid for 24 hours.
            """ % escape(email)))

    return render_form(form=form, title="Reset password", submit="Send reset code", ajax=True)


@app.route('/reset/<userid>/<secret>', methods=['GET', 'POST'])
def reset_email(userid, secret):
    logout_internal()
    user = User.query.filter_by(userid=userid).first()
    if not user:
        abort(404)
    resetreq = PasswordResetRequest.query.filter_by(user=user, reset_code=secret).first()
    if not resetreq:
        return render_message(title="Invalid reset link",
            message=Markup("The reset link you clicked on is invalid."))
    if resetreq.created_at < datetime.utcnow() - timedelta(days=1):
        # Reset code has expired (> 24 hours). Delete it
        db.session.delete(resetreq)
        db.session.commit()
        return render_message(title="Expired reset link",
            message=Markup("The reset link you clicked on has expired."))

    # Reset code is valid. Now ask user to choose a new password
    form = PasswordResetForm()
    if form.validate_on_submit():
        user.password = form.password.data
        db.session.delete(resetreq)
        db.session.commit()
        return render_message(title="Password reset complete", message=Markup(
            'Your password has been reset. You may now <a href="%s">login</a> with your new password.' % escape(url_for('login'))))
    return render_form(form=form, title="Reset password", formid='reset', submit="Reset password",
        message=Markup('Hello, <strong>%s</strong>. You may now choose a new password.' % user.fullname),
        ajax=True)
