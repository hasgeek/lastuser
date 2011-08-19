# -*- coding: utf-8 -*-

from flask import g, request, abort, flash, redirect, render_template, url_for, session

from lastuserapp import app
from lastuserapp.models import db, User, UserEmail, UserEmailClaim, UserPhone, UserPhoneClaim
from lastuserapp.mailclient import send_email_verify_link
from lastuserapp.views import get_next_url, requires_login, render_form, render_redirect, render_delete
from lastuserapp.views.sms import send_phone_verify_code
from lastuserapp.forms import (ProfileForm, PasswordResetForm, PasswordChangeForm, NewEmailAddressForm,
    NewPhoneForm, VerifyPhoneForm)


@app.route('/profile')
@requires_login
def profile():
    # TODO: move the avatar in the user model
    return render_template('profile.html', avatar = session['avatar_url'])


@app.route('/profile/edit', methods=['GET', 'POST'])
@requires_login
def profile_edit():
    form = ProfileForm()
    if request.method == 'GET':
        form.fullname.data = g.user.fullname
        form.username.data = g.user.username
        form.description.data = g.user.description
    elif form.validate_on_submit():
        g.user.fullname = form.fullname.data
        g.user.username = form.username.data or None
        g.user.description = form.description.data
        db.session.commit()

        next_url = get_next_url()
        if(next_url is not None):
            return render_redirect(next_url)
        else:
            flash("Your profile was successfully edited.", category='info')
            return render_redirect(url_for('profile'), code=303)
    return render_form(form, title="Edit profile", formid="profile_edit", submit="Save changes", ajax=True)


@app.route('/profile/password', methods=['GET', 'POST'])
@requires_login
def change_password():
    if g.user.pw_hash is None:
        form = PasswordResetForm()
    else:
        form = PasswordChangeForm()
    if form.validate_on_submit():
        g.user.password = form.password.data
        db.session.commit()
        flash("Your new password has been saved.", category='info')
        return render_redirect(url_for('profile'), code=303)
    return render_form(form=form, title="Change password", formid="changepassword", submit="Change password", ajax=True)


@app.route('/profile/email/new', methods=['GET', 'POST'])
@requires_login
def add_email():
    form = NewEmailAddressForm()
    if form.validate_on_submit():
        useremail = UserEmailClaim(user=g.user, email=form.email.data)
        db.session.add(useremail)
        db.session.commit()
        send_email_verify_link(useremail)
        flash("We sent you an email to confirm your address.", "info")
        return render_redirect(url_for('profile'), code=303)
    return render_form(form=form, title="Add an email address", formid="email_add", submit="Add email", ajax=True)

@app.route('/profile/email/<md5sum>/remove', methods=['GET', 'POST'])
@requires_login
def remove_email(md5sum):
    useremail = UserEmail.query.filter_by(md5sum=md5sum, user=g.user).first()
    if not useremail:
        useremail = UserEmailClaim.query.filter_by(md5sum=md5sum, user=g.user).first()
        if not useremail:
            abort(404)
    if useremail.primary:
        flash("You cannot remove your primary email address", "error")
        return render_redirect(url_for('profile'), code=303)
    return render_delete(useremail, title="Confirm removal", message="Remove email address %s?" % useremail,
        success="You have removed your email address %s." % useremail,
        next=url_for('profile'))


@app.route('/profile/phone/new', methods=['GET', 'POST'])
@requires_login
def add_phone():
    form = NewPhoneForm()
    if form.validate_on_submit():
        userphone = UserPhoneClaim(user=g.user, phone=form.phone.data)
        db.session.add(userphone)
        send_phone_verify_code(userphone)
        db.session.commit()
        flash("We sent a verification code to your phone number.", "info")
        return render_redirect(url_for('verify_phone', number=userphone.phone), code=303)
    return render_form(form=form, title="Add a phone number", formid="phone_add", submit="Add phone", ajax=True)


@app.route('/profile/phone/<number>/remove', methods=['GET', 'POST'])
@requires_login
def remove_phone(number):
    userphone = UserPhone.query.filter_by(phone=number, user=g.user).first()
    if userphone is None:
        userphone = UserPhoneClaim.query.filter_by(phone=number, user=g.user).first()
    return render_delete(userphone, title="Confirm removal", message="Remove phone number %s?" % userphone,
        success="You have removed your number %s." % userphone,
        next=url_for('profile'))


@app.route('/profile/phone/<number>/verify', methods=['GET', 'POST'])
@requires_login
def verify_phone(number):
    form = VerifyPhoneForm()
    phoneclaim = UserPhoneClaim.query.filter_by(phone=number).first()
    if not phoneclaim:
        abort(404)
    if phoneclaim.user != g.user:
        abort(403)
    form.phoneclaim = phoneclaim
    if form.validate_on_submit():
        if not g.user.phones:
            primary=True
        else:
            primary=False
        userphone = UserPhone(user=g.user, phone=phoneclaim.phone, gets_text=True, primary=primary)
        db.session.add(userphone)
        db.session.delete(phoneclaim)
        db.session.commit()
        flash("Your phone number has been verified.", "info")
        return render_redirect(url_for('profile'), code=303)
    return render_form(form=form, title="Verify phone number", formid="phone_verify", submit="Verify", ajax=True)
