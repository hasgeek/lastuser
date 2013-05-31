# -*- coding: utf-8 -*-

from flask import g, current_app, flash, url_for, Markup, escape
from coaster.views import get_next_url
from baseframe.forms import render_form, render_redirect, render_message

from lastuser_core.models import db, UserEmail, UserEmailClaim
from .. import lastuser_oauth
from ..mailclient import send_email_verify_link
from ..forms import ProfileForm
from .helpers import requires_login


@lastuser_oauth.route('/profile/edit', methods=['GET', 'POST'], defaults={'newprofile': False}, endpoint='profile_edit')
@lastuser_oauth.route('/profile/new', methods=['GET', 'POST'], defaults={'newprofile': True}, endpoint='profile_new')
@requires_login
def profile_edit(newprofile=False):
    form = ProfileForm(obj=g.user)
    form.fullname.description = current_app.config.get('FULLNAME_REASON')
    form.email.description = current_app.config.get('EMAIL_REASON')
    form.username.description = current_app.config.get('USERNAME_REASON')
    form.description.description = current_app.config.get('BIO_REASON')
    form.timezone.description = current_app.config.get('TIMEZONE_REASON')
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


@lastuser_oauth.route('/confirm/<md5sum>/<secret>')
@requires_login
def confirm_email(md5sum, secret):
    emailclaim = UserEmailClaim.query.filter_by(md5sum=md5sum, verification_code=secret).first()
    if emailclaim is not None:
        if 'verify' in emailclaim.permissions(g.user):
            existing = UserEmail.query.filter(UserEmail.email.in_([emailclaim.email, emailclaim.email.lower()])).first()
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
            for claim in UserEmailClaim.query.filter(UserEmailClaim.email.in_([useremail.email, useremail.email.lower()])).all():
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
