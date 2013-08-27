# -*- coding: utf-8 -*-

from flask import g, flash, render_template, url_for, session, request
from coaster.views import load_model
from baseframe.forms import render_form, render_redirect, render_delete_sqla

from lastuser_core.models import db, UserEmail, UserEmailClaim, UserPhone, UserPhoneClaim
from lastuser_core.signals import user_data_changed
from lastuser_oauth.mailclient import send_email_verify_link
from lastuser_oauth.views.helpers import requires_login
from lastuser_oauth.forms import PasswordResetForm, PasswordChangeForm
from .. import lastuser_ui
from ..forms import NewEmailAddressForm, NewPhoneForm, VerifyPhoneForm
from .sms import send_phone_verify_code


@lastuser_ui.route('/profile')
@requires_login
def profile():
    # TODO: move the avatar in the user model
    return render_template('profile.html', avatar=session['avatar_url'])


@lastuser_ui.route('/profile/password', methods=['GET', 'POST'])
@requires_login
def change_password():
    if g.user.pw_hash is None:
        form = PasswordResetForm()
        del form.username
    else:
        form = PasswordChangeForm()
    if form.validate_on_submit():
        g.user.password = form.password.data
        db.session.commit()
        flash("Your new password has been saved.", category='success')
        return render_redirect(url_for('.profile'), code=303)
    return render_form(form=form, title="Change password", formid="changepassword", submit="Change password", ajax=True)


@lastuser_ui.route('/profile/email/new', methods=['GET', 'POST'])
@requires_login
def add_email():
    form = NewEmailAddressForm()
    if form.validate_on_submit():
        useremail = UserEmailClaim(user=g.user, email=form.email.data)
        db.session.add(useremail)
        db.session.commit()
        send_email_verify_link(useremail)
        flash("We sent you an email to confirm your address.", 'success')
        user_data_changed.send(g.user, changes=['email-claim'])
        return render_redirect(url_for('.profile'), code=303)
    return render_form(form=form, title="Add an email address", formid="email_add", submit="Add email", ajax=True)


@lastuser_ui.route('/profile/email/<md5sum>/remove', methods=['GET', 'POST'])
@requires_login
def remove_email(md5sum):
    useremail = UserEmail.query.filter_by(md5sum=md5sum, user=g.user).first()
    if not useremail:
        useremail = UserEmailClaim.query.filter_by(md5sum=md5sum, user=g.user).first_or_404()
    if isinstance(useremail, UserEmail) and useremail.primary:
        flash("You cannot remove your primary email address", "error")
        return render_redirect(url_for('.profile'), code=303)
    if request.method == 'POST':
        user_data_changed.send(g.user, changes=['email-delete'])
    return render_delete_sqla(useremail, db, title="Confirm removal", message="Remove email address {}?".format(useremail),
        success="You have removed your email address {}.".format(useremail),
        next=url_for('.profile'))


@lastuser_ui.route('/profile/phone/new', methods=['GET', 'POST'])
@requires_login
def add_phone():
    form = NewPhoneForm()
    if form.validate_on_submit():
        userphone = UserPhoneClaim(user=g.user, phone=form.phone.data)
        db.session.add(userphone)
        send_phone_verify_code(userphone)
        db.session.commit()
        flash("We sent a verification code to your phone number.", 'success')
        user_data_changed.send(g.user, changes=['phone-claim'])
        return render_redirect(url_for('.verify_phone', number=userphone.phone), code=303)
    return render_form(form=form, title="Add a phone number", formid="phone_add", submit="Add phone", ajax=True)


@lastuser_ui.route('/profile/phone/<number>/remove', methods=['GET', 'POST'])
@requires_login
def remove_phone(number):
    userphone = UserPhone.query.filter_by(phone=number, user=g.user).first()
    if userphone is None:
        userphone = UserPhoneClaim.query.filter_by(phone=number, user=g.user).first_or_404()
    if request.method == 'POST':
        user_data_changed.send(g.user, changes=['phone-delete'])
    return render_delete_sqla(userphone, db, title="Confirm removal", message="Remove phone number {}?".format(userphone),
        success="You have removed your number {}.".format(userphone),
        next=url_for('.profile'))


@lastuser_ui.route('/profile/phone/<number>/verify', methods=['GET', 'POST'])
@requires_login
@load_model(UserPhoneClaim, {'phone': 'number'}, 'phoneclaim', permission='verify')
def verify_phone(phoneclaim):
    form = VerifyPhoneForm()
    form.phoneclaim = phoneclaim
    if form.validate_on_submit():
        if not g.user.phones:
            primary = True
        else:
            primary = False
        userphone = UserPhone(user=g.user, phone=phoneclaim.phone, gets_text=True, primary=primary)
        db.session.add(userphone)
        db.session.delete(phoneclaim)
        db.session.commit()
        flash("Your phone number has been verified.", 'success')
        user_data_changed.send(g.user, 'phone')
        return render_redirect(url_for('.profile'), code=303)
    return render_form(form=form, title="Verify phone number", formid="phone_verify", submit="Verify", ajax=True)
