# -*- coding: utf-8 -*-

from flask import Markup, current_app, escape, flash, url_for

from baseframe import _
from baseframe.forms import render_form, render_message, render_redirect
from coaster.auth import current_auth
from coaster.views import get_next_url
from lastuser_core.models import UserEmail, UserEmailClaim, db
from lastuser_core.signals import user_data_changed

from .. import lastuser_oauth
from ..forms import ProfileForm
from ..mailclient import send_email_verify_link
from .helpers import requires_login


@lastuser_oauth.route(
    '/account/edit',
    methods=['GET', 'POST'],
    defaults={'newprofile': False},
    endpoint='account_edit',
)
@lastuser_oauth.route(
    '/account/new',
    methods=['GET', 'POST'],
    defaults={'newprofile': True},
    endpoint='account_new',
)
@requires_login
def account_edit(newprofile=False):
    form = ProfileForm(obj=current_auth.user)
    form.edit_user = current_auth.user
    form.fullname.description = current_app.config.get('FULLNAME_REASON')
    form.email.description = current_app.config.get('EMAIL_REASON')
    form.username.description = current_app.config.get('USERNAME_REASON')
    form.timezone.description = current_app.config.get('TIMEZONE_REASON')
    if current_auth.user.email or newprofile is False:
        del form.email

    if form.validate_on_submit():
        # Can't auto-populate here because user.email is read-only
        current_auth.user.fullname = form.fullname.data
        current_auth.user.username = form.username.data
        current_auth.user.timezone = form.timezone.data

        if newprofile and not current_auth.user.email:
            useremail = UserEmailClaim.get(
                user=current_auth.user, email=form.email.data
            )
            if useremail is None:
                useremail = UserEmailClaim(
                    user=current_auth.user, email=form.email.data
                )
                db.session.add(useremail)
            send_email_verify_link(useremail)
            db.session.commit()
            user_data_changed.send(
                current_auth.user, changes=['profile', 'email-claim']
            )
            flash(
                _(
                    "Your profile has been updated. We sent you an email to confirm your address"
                ),
                category='success',
            )
        else:
            db.session.commit()
            user_data_changed.send(current_auth.user, changes=['profile'])
            flash(_("Your profile has been updated"), category='success')

        if newprofile:
            return render_redirect(get_next_url(), code=303)
        else:
            return render_redirect(url_for('account'), code=303)
    if newprofile:
        return render_form(
            form,
            title=_("Update profile"),
            formid='account_new',
            submit=_("Continue"),
            message=Markup(
                _(
                    u"Hello, <strong>{fullname}</strong>. Please spare a minute to fill out your profile"
                ).format(fullname=escape(current_auth.user.fullname))
            ),
            ajax=True,
        )
    else:
        return render_form(
            form,
            title=_("Edit profile"),
            formid='account_edit',
            submit=_("Save changes"),
            ajax=True,
        )


# FIXME: Don't modify db on GET. Autosubmit via JS and process on POST
@lastuser_oauth.route('/confirm/<md5sum>/<secret>')
@requires_login
def confirm_email(md5sum, secret):
    emailclaim = UserEmailClaim.query.filter_by(
        md5sum=md5sum, verification_code=secret
    ).first()
    if emailclaim is not None:
        if 'verify' in emailclaim.permissions(current_auth.user):
            existing = UserEmail.query.filter(
                UserEmail.email.in_([emailclaim.email, emailclaim.email.lower()])
            ).first()
            if existing is not None:
                claimed_email = emailclaim.email
                claimed_user = emailclaim.user
                db.session.delete(emailclaim)
                db.session.commit()
                if claimed_user != current_auth.user:
                    return render_message(
                        title=_("Email address already claimed"),
                        message=Markup(
                            _(
                                u"The email address <code>{email}</code> has already been verified by another user"
                            ).format(email=escape(claimed_email))
                        ),
                    )
                else:
                    return render_message(
                        title=_("Email address already verified"),
                        message=Markup(
                            _(
                                u"Hello <strong>{fullname}</strong>! "
                                u"Your email address <code>{email}</code> has already been verified"
                            ).format(
                                fullname=escape(claimed_user.fullname),
                                email=escape(claimed_email),
                            )
                        ),
                    )

            useremail = emailclaim.user.add_email(
                emailclaim.email,
                primary=emailclaim.user.email is None,
                type=emailclaim.type,
                private=emailclaim.private,
            )
            db.session.delete(emailclaim)
            for claim in UserEmailClaim.query.filter(
                UserEmailClaim.email.in_([useremail.email, useremail.email.lower()])
            ).all():
                db.session.delete(claim)
            db.session.commit()
            user_data_changed.send(current_auth.user, changes=['email'])
            return render_message(
                title=_("Email address verified"),
                message=Markup(
                    _(
                        u"Hello <strong>{fullname}</strong>! "
                        u"Your email address <code>{email}</code> has now been verified"
                    ).format(
                        fullname=escape(emailclaim.user.fullname),
                        email=escape(useremail.email),
                    )
                ),
            )
        else:
            return render_message(
                title=_("This was not for you"),
                message=_(
                    u"You’ve opened an email verification link that was meant for another user. "
                    u"If you are managing multiple accounts, please login with the correct account "
                    u"and open the link again"
                ),
                code=403,
            )
    else:
        return render_message(
            title=_("Expired confirmation link"),
            message=_(
                u"The confirmation link you clicked on is either invalid or has expired"
            ),
            code=404,
        )
