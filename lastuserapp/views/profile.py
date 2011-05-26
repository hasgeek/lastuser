# -*- coding: utf-8 -*-

from flask import g, request, abort, flash, redirect, render_template, url_for

from lastuserapp import app
from lastuserapp.models import db, User, UserEmailClaim
from lastuserapp.mailclient import send_email_verify_link
from lastuserapp.views import requires_login, render_form, render_redirect
from lastuserapp.forms import ProfileForm, PasswordResetForm, PasswordChangeForm, NewEmailAddressForm


@app.route('/profile')
@requires_login
def profile_current():
    return render_template('profile_current.html')


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
        g.user.username = form.username.data
        g.user.description = form.description.data
        db.session.commit()
        flash("Your profile was successfully edited.", category='info')
        return render_redirect(url_for('profile_current'), code=303)
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
        return render_redirect(url_for('profile_current'), code=303)
    return render_form(form=form, title="Change password", formid="changepassword", submit="Change password", ajax=True)


@app.route('/profile/addemail', methods=['GET', 'POST'])
@requires_login
def add_email():
    form = NewEmailAddressForm()
    if form.validate_on_submit():
        useremail = UserEmailClaim(user=g.user, email=form.email.data)
        db.session.add(useremail)
        db.session.commit()
        send_email_verify_link(useremail)
        flash("We sent you an email to confirm your address.", "info")
        return render_redirect(url_for('profile_current'), code=303)
    return render_form(form=form, title="Add an email address", formid="email_add", submit="Add email", ajax=True)


# Note: This must always be the last route in the app
@app.route('/<profileid>')
def profile(profileid):
    user = User.query.filter_by(username=profileid).first()
    if user is None:
        if len(profileid) == 22:
            user = User.query.filter_by(userid=profileid).first()
        elif len(profileid) == 32:
            useremail = UserEmail.query.filter_by(md5sum=profileid).first()
            if useremail:
                user = useremail.user
    if user is None:
        abort(404)
    if user.profileid() != profileid:
        return redirect(url_for('profile', profileid=user.profileid()), code=301)

    return render_template('profile.html', user=user)
