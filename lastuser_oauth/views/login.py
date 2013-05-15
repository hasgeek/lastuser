# -*- coding: utf-8 -*-

from datetime import datetime, timedelta
import urlparse
from openid import oidutil
from flask import g, current_app, redirect, request, flash, render_template, url_for, Markup, escape, abort
from flask.ext.openid import OpenID
from coaster.views import get_next_url, load_model
from baseframe.forms import render_form, render_message, render_redirect

from lastuser_core import login_registry
from lastuser_oauth import lastuser_oauth
from lastuser_oauth.mailclient import send_email_verify_link, send_password_reset_link
from lastuser_core.models import db, User, UserEmailClaim, PasswordResetRequest, Client
from lastuser_oauth.forms import LoginForm, RegisterForm, PasswordResetForm, PasswordResetRequestForm
from lastuser_oauth.views.helpers import login_internal, logout_internal, register_internal, set_loginmethod_cookie

oid = OpenID()


def openid_log(message, level=0):
    if current_app.debug:
        import sys
        print >> sys.stderr, message

oidutil.log = openid_log


@lastuser_oauth.route('/login', methods=['GET', 'POST'])
@oid.loginhandler
def login():
    # If user is already logged in, send them back
    if g.user:
        return redirect(get_next_url(referrer=True), code=303)

    loginform = LoginForm()
    service_forms = {}
    for service, provider in login_registry.items():
        if provider.at_login and provider.form is not None:
            service_forms[service] = provider.get_form()

    loginmethod = None
    if request.method == 'GET':
        loginmethod = request.cookies.get('login')

    formid = request.form.get('form.id')
    if request.method == 'POST' and formid == 'passwordlogin':
        if loginform.validate():
            user = loginform.user
            login_internal(user)
            db.session.commit()
            flash('You are now logged in', category='success')
            return set_loginmethod_cookie(render_redirect(get_next_url(session=True), code=303),
                'password')
    elif request.method == 'POST' and formid in service_forms:
        form = service_forms[formid]['form']
        if form.validate():
            return set_loginmethod_cookie(login_registry[formid].do(form=form), formid)
    elif request.method == 'POST':
        abort(500)
    if request.is_xhr and formid == 'passwordlogin':
        return render_template('forms/loginform.html', loginform=loginform, Markup=Markup)
    else:
        return render_template('login.html', loginform=loginform, lastused=loginmethod,
            service_forms=service_forms, Markup=Markup)


# TODO: Move this into settings.py
logout_errormsg = ("We detected an possibly unauthorized attempt to log you out. "
    "If you really did intend to logout, please click on the logout link again.")


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
        flash('You are now logged out', category='success')
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


@lastuser_oauth.route('/logout')
def logout():

    # Logout, but protect from CSRF attempts
    if 'client_id' in request.args:
        return logout_client()
    else:
        # If this is not a logout request from a client, check if all is good.
        return logout_user()


@lastuser_oauth.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    # Make Recaptcha optional
    if not (current_app.config.get('RECAPTCHA_PUBLIC_KEY') and current_app.config.get('RECAPTCHA_PRIVATE_KEY')):
        del form.recaptcha
    form.fullname.description = current_app.config.get('FULLNAME_REASON')
    form.email.description = current_app.config.get('EMAIL_REASON')
    form.username.description = current_app.config.get('USERNAME_REASON')
    if form.validate_on_submit():
        user = register_internal(None, form.fullname.data, form.password.data)
        user.username = form.username.data or None
        useremail = UserEmailClaim(user=user, email=form.email.data)
        db.session.add(useremail)
        send_email_verify_link(useremail)
        login_internal(user)
        db.session.commit()
        flash("You are now one of us. Welcome aboard!", category='success')
        if 'next' in request.args:
            return redirect(request.args['next'], code=303)
        else:
            return redirect(url_for('index'), code=303)
    return render_form(form=form, title='Create an account', formid='register', submit='Register')


@lastuser_oauth.route('/reset', methods=['GET', 'POST'])
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
            """ % (escape(current_app.config['SITE_SUPPORT_EMAIL']), escape(current_app.config['SITE_SUPPORT_EMAIL']))))
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


# FIXME: Don't modify db on GET. Autosubmit via JS and process on POST
@lastuser_oauth.route('/reset/<userid>/<secret>', methods=['GET', 'POST'])
@load_model(User, {'userid': 'userid'}, 'user', kwargs=True)
def reset_email(user, kwargs):
    resetreq = PasswordResetRequest.query.filter_by(user=user, reset_code=kwargs['secret']).first()
    if not resetreq:
        return render_message(title="Invalid reset link",
            message=Markup("The reset link you clicked on is invalid."))
    if resetreq.created_at < datetime.utcnow() - timedelta(days=1):
        # Reset code has expired (> 24 hours). Delete it
        db.session.delete(resetreq)
        db.session.commit()
        return render_message(title="Expired reset link",
            message=Markup("The reset link you clicked on has expired."))

    # Logout *after* validating the reset request to prevent DoS attacks on the user
    logout_internal()
    # Reset code is valid. Now ask user to choose a new password
    form = PasswordResetForm()
    form.user = user
    if form.validate_on_submit():
        user.password = form.password.data
        db.session.delete(resetreq)
        db.session.commit()
        return render_message(title="Password reset complete", message=Markup(
            'Your password has been reset. You may now <a href="%s">login</a> with your new password.' % escape(url_for('.login'))))
    return render_form(form=form, title="Reset password", formid='reset', submit="Reset password",
        message=Markup('Hello, <strong>%s</strong>. You may now choose a new password.' % user.fullname),
        ajax=True)
