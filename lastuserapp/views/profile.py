# -*- coding: utf-8 -*-

from flask import g, flash, render_template, url_for, session, Markup, escape
from coaster.views import get_next_url, load_model
from baseframe.forms import render_form, render_redirect, render_delete_sqla, render_message

from lastuserapp import app
from lastuserapp.models import db, UserEmail, UserEmailClaim, UserPhone, UserPhoneClaim
from lastuserapp.mailclient import send_email_verify_link
from lastuserapp.views.helpers import requires_login
from lastuserapp.views.sms import send_phone_verify_code
from lastuserapp.forms import (ProfileForm, PasswordResetForm, PasswordChangeForm, NewEmailAddressForm,
    NewPhoneForm, VerifyPhoneForm)


@app.route('/profile')
@requires_login
def profile():
    # TODO: move the avatar in the user model
    return render_template('profile.html', avatar=session['avatar_url'])


@app.route('/profile/edit', methods=['GET', 'POST'], defaults={'newprofile': False}, endpoint='profile_edit')
@app.route('/profile/new', methods=['GET', 'POST'], defaults={'newprofile': True}, endpoint='profile_new')
@requires_login
def profile_edit(newprofile=False):
    form = ProfileForm(obj=g.user)
    form.fullname.description = app.config.get('FULLNAME_REASON')
    form.email.description = app.config.get('EMAIL_REASON')
    form.username.description = app.config.get('USERNAME_REASON')
    form.description.description = app.config.get('BIO_REASON')
    form.timezone.description = app.config.get('TIMEZONE_REASON')
    if g.user.email or newprofile is False:
        del form.email

    if form.validate_on_submit():
        # Can't auto-populate here because user.email is read-only
        g.user.fullname = form.fullname.data
        g.user.username = form.username.data
        g.user.description = form.description.data
        g.user.timezone = form.timezone.data

        if newprofile and not g.user.email:
            useremail = UserEmailClaim(user=g.user, email=form.email.data)
            db.session.add(useremail)
            send_email_verify_link(useremail)
            db.session.commit()
            flash("Your profile has been updated. We sent you an email to confirm your address", category='success')
        else:
            db.session.commit()
            flash("Your profile has been updated.", category='success')

        if newprofile:
            return render_redirect(get_next_url(), code=303)
        else:
            return render_redirect(url_for('profile'), code=303)
    if newprofile:
        return render_form(form, title="Update profile", formid="profile_new", submit="Continue",
            message=u"Hello, %s. Please spare a minute to fill out your profile." % g.user.fullname,
            ajax=True)
    else:
        return render_form(form, title="Edit profile", formid="profile_edit", submit="Save changes", ajax=True)


@requires_login
def profile_new():
    form = ProfileForm(obj=g.user)
    form.fullname.description = app.config.get('FULLNAME_REASON')
    form.email.description = app.config.get('EMAIL_REASON')
    form.username.description = app.config.get('USERNAME_REASON')
    form.description.description = app.config.get('BIO_REASON')
    form.timezone.description = app.config.get('TIMEZONE_REASON')
    if g.user.email:
        del form.email
    if form.validate_on_submit():
        # Can't auto-populate here because user.email is read-only
        g.user.fullname = form.fullname.data
        g.user.username = form.username.data
        g.user.description = form.description.data
        g.user.timezone = form.timezone.data
        if not g.user.email:
            useremail = UserEmailClaim(user=g.user, email=form.email.data)
            db.session.add(useremail)
            db.session.commit()
            send_email_verify_link(useremail)
            flash("Your profile was successfully updated. We sent you an email to confirm your address", category='success')
        else:
            db.session.commit()
            flash("Your profile was successfully updated.", category='success')

        return render_redirect(get_next_url(), code=303)
    return render_form(form, title="Update profile", formid="profile_new", submit="Continue",
        message=u"Hello, %s. Please spare a minute to fill out your profile." % g.user.fullname,
        ajax=True)


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
        flash("Your new password has been saved.", category='success')
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
        flash("We sent you an email to confirm your address.", 'success')
        return render_redirect(url_for('profile'), code=303)
    return render_form(form=form, title="Add an email address", formid="email_add", submit="Add email", ajax=True)


@app.route('/profile/email/<md5sum>/remove', methods=['GET', 'POST'])
@requires_login
def remove_email(md5sum):
    useremail = UserEmail.query.filter_by(md5sum=md5sum, user=g.user).first()
    if not useremail:
        useremail = UserEmailClaim.query.filter_by(md5sum=md5sum, user=g.user).first_or_404()
    if isinstance(useremail, UserEmail) and useremail.primary:
        flash("You cannot remove your primary email address", "error")
        return render_redirect(url_for('profile'), code=303)
    return render_delete_sqla(useremail, db, title="Confirm removal", message="Remove email address %s?" % useremail,
        success="You have removed your email address %s." % useremail,
        next=url_for('profile'))


@app.route('/confirm/<md5sum>/<secret>')
@requires_login
def confirm_email(md5sum, secret):
    emailclaim = UserEmailClaim.query.filter_by(md5sum=md5sum, verification_code=secret).first()
    if emailclaim is not None:
        if 'verify' in emailclaim.permissions(g.user):
            existing = UserEmail.query.filter_by(email=emailclaim.email).first()
            if existing is not None:
                claimed_email = emailclaim.email
                claimed_user = emailclaim.user
                db.session.delete(emailclaim)
                db.session.commit()
                if claimed_user != g.user:
                    return render_message(title="Email address already claimed",
                        message=Markup(
                            "The email address <code>%s</code> has already been verified by another user." % escape(claimed_email)))
                else:
                    return render_message(title="Email address already verified",
                        message=Markup("Hello %s! Your email address <code>%s</code> has already been verified." % (
                            escape(claimed_user.fullname), escape(claimed_email))))

            useremail = emailclaim.user.add_email(emailclaim.email.lower(), primary=emailclaim.user.email is None)
            db.session.delete(emailclaim)
            for claim in UserEmailClaim.query.filter_by(email=useremail.email).all():
                db.session.delete(claim)
            db.session.commit()
            return render_message(title="Email address verified",
                message=Markup("Hello %s! Your email address <code>%s</code> has now been verified." % (
                    escape(emailclaim.user.fullname), escape(useremail.email))))
        else:
            return render_message(
                title="That was not for you",
                message=u"You’ve opened an email verification link that was meant for another user. "
                    u"If you are managing multiple accounts, please login with the correct account "
                    u"and open the link again.",
                code=403)
    else:
        return render_message(
            title="Expired confirmation link",
            message="The confirmation link you clicked on is either invalid or has expired.",
            code=404)


@app.route('/profile/phone/new', methods=['GET', 'POST'])
@requires_login
def add_phone():
    form = NewPhoneForm()
    if form.validate_on_submit():
        userphone = UserPhoneClaim(user=g.user, phone=form.phone.data)
        db.session.add(userphone)
        send_phone_verify_code(userphone)
        db.session.commit()
        flash("We sent a verification code to your phone number.", 'success')
        return render_redirect(url_for('verify_phone', number=userphone.phone), code=303)
    return render_form(form=form, title="Add a phone number", formid="phone_add", submit="Add phone", ajax=True)


@app.route('/profile/phone/<number>/remove', methods=['GET', 'POST'])
@requires_login
def remove_phone(number):
    userphone = UserPhone.query.filter_by(phone=number, user=g.user).first()
    if userphone is None:
        userphone = UserPhoneClaim.query.filter_by(phone=number, user=g.user).first_or_404()
    return render_delete_sqla(userphone, db, title="Confirm removal", message="Remove phone number %s?" % userphone,
        success="You have removed your number %s." % userphone,
        next=url_for('profile'))


@app.route('/profile/phone/<number>/verify', methods=['GET', 'POST'])
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
        return render_redirect(url_for('profile'), code=303)
    return render_form(form=form, title="Verify phone number", formid="phone_verify", submit="Verify", ajax=True)
