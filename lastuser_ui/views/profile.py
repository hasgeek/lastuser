# -*- coding: utf-8 -*-

from flask import flash, render_template, url_for, request, redirect
from coaster.auth import current_auth
from coaster.views import load_model
from baseframe import _
from baseframe.forms import render_form, render_redirect, render_delete_sqla
from lastuser_core import login_registry
from lastuser_core.models import db, UserEmail, UserEmailClaim, UserPhone, UserPhoneClaim, UserExternalId
from lastuser_core.signals import user_data_changed
from lastuser_oauth.mailclient import send_email_verify_link
from lastuser_oauth.views.helpers import requires_login
from lastuser_oauth.forms import PasswordResetForm, PasswordChangeForm
from .. import lastuser_ui
from ..forms import NewEmailAddressForm, EmailPrimaryForm, VerifyEmailForm, NewPhoneForm, VerifyPhoneForm
from .sms import send_phone_verify_code


@lastuser_ui.route('/profile', defaults={'path': None})
@lastuser_ui.route('/profile/<path:path>')
@requires_login
def profile(path=None):
    if path is not None:
        return redirect('/account/%s' % path)
    else:
        return redirect('/account')


@lastuser_ui.route('/account')
@requires_login
def account():
    primary_email_form = EmailPrimaryForm()
    service_forms = {}
    for service, provider in login_registry.items():
        if provider.at_login and provider.form is not None:
            service_forms[service] = provider.get_form()
    return render_template('account.html.jinja2', primary_email_form=primary_email_form,
        service_forms=service_forms, login_registry=login_registry)


@lastuser_ui.route('/account/password', methods=['GET', 'POST'])
@requires_login
def change_password():
    if not current_auth.user.pw_hash:
        form = PasswordResetForm()
        form.edit_user = current_auth.user
        del form.username
    else:
        form = PasswordChangeForm()
        form.edit_user = current_auth.user
    if form.validate_on_submit():
        current_auth.user.password = form.password.data
        db.session.commit()
        flash(_("Your new password has been saved"), category='success')
        return render_redirect(url_for('.profile'), code=303)
    return render_form(form=form, title=_("Change password"), formid='changepassword',
        submit=_("Change password"), ajax=True)


@lastuser_ui.route('/account/email/new', methods=['GET', 'POST'])
@requires_login
def add_email():
    form = NewEmailAddressForm()
    if form.validate_on_submit():
        useremail = UserEmailClaim.get(user=current_auth.user, email=form.email.data)
        if useremail is None:
            useremail = UserEmailClaim(user=current_auth.user, email=form.email.data, type=form.type.data)
            db.session.add(useremail)
            db.session.commit()
        send_email_verify_link(useremail)
        flash(_("We sent you an email to confirm your address"), 'success')
        user_data_changed.send(current_auth.user, changes=['email-claim'])
        return render_redirect(url_for('.profile'), code=303)
    return render_form(form=form, title=_("Add an email address"), formid='email_add',
        submit=_("Add email"), ajax=True)


@lastuser_ui.route('/account/email/makeprimary', methods=['POST'])
@requires_login
def make_email_primary():
    form = EmailPrimaryForm()
    if form.validate_on_submit():
        useremail = UserEmail.query.filter_by(email=form.email.data, user=current_auth.user).first()
        if useremail is not None and isinstance(useremail, UserEmail):
            if useremail.primary:
                flash(_("This is already your primary email address"), 'danger')
            else:
                current_auth.user.primary_email = useremail
                db.session.commit()
                user_data_changed.send(current_auth.user, changes=['email-update-primary'])
                flash(_(u"Your primary email address has been updated").format(email=useremail.email), 'success')
        else:
            flash(_("No such email address is linked to this user account"), 'danger')
    else:
            flash(_("Please select an email address"), 'danger')
    return render_redirect(url_for('.profile'), code=303)


@lastuser_ui.route('/account/email/<md5sum>/remove', methods=['GET', 'POST'])
@requires_login
def remove_email(md5sum):
    useremail = UserEmail.query.filter_by(md5sum=md5sum, user=current_auth.user).first()
    if not useremail:
        useremail = UserEmailClaim.query.filter_by(md5sum=md5sum, user=current_auth.user).first_or_404()
    if isinstance(useremail, UserEmail) and useremail.primary:
        flash(_("You cannot remove your primary email address"), 'danger')
        return render_redirect(url_for('.profile'), code=303)
    if request.method == 'POST':
        # FIXME: Confirm validation success
        user_data_changed.send(current_auth.user, changes=['email-delete'])
    return render_delete_sqla(useremail, db, title=_(u"Confirm removal"),
        message=_(u"Remove email address {email} from your account?").format(email=useremail.email),
        success=_(u"You have removed your email address {email}").format(email=useremail.email),
        next=url_for('.profile'),
        delete_text=_(u"Remove"))


@lastuser_ui.route('/account/email/<md5sum>/verify', methods=['GET', 'POST'])
@requires_login
def verify_email(md5sum):
    useremail = UserEmail.query.filter_by(md5sum=md5sum, user=current_auth.user).first()
    if useremail:
        flash(_("This email address is already verified"), 'danger')
        return render_redirect(url_for('.profile'), code=303)

    emailclaim = UserEmailClaim.query.filter_by(md5sum=md5sum, user=current_auth.user).first_or_404()
    verify_form = VerifyEmailForm()
    if verify_form.validate_on_submit():
        send_email_verify_link(emailclaim)
        flash(_(u"The verification email has been sent to this address"), 'success')
        return render_redirect(url_for('.profile'), code=303)
    return render_form(form=verify_form, title=_("Resend the verification email?"),
        message=_("We will resend the verification email to '{email}'".format(email=emailclaim.email)),
        formid="email_verify", submit=_("Send"), cancel_url=url_for('.profile'))


@lastuser_ui.route('/account/phone/new', methods=['GET', 'POST'])
@requires_login
def add_phone():
    form = NewPhoneForm()
    if form.validate_on_submit():
        userphone = UserPhoneClaim.get(user=current_auth.user, phone=form.phone.data)
        if userphone is None:
            userphone = UserPhoneClaim(user=current_auth.user, phone=form.phone.data, type=form.type.data)
            db.session.add(userphone)
        try:
            send_phone_verify_code(userphone)
            db.session.commit()  # Commit after sending because send_phone_verify_code saves the message sent
            flash(_("We sent a verification code to your phone number"), 'success')
            user_data_changed.send(current_auth.user, changes=['phone-claim'])
            return render_redirect(url_for('.verify_phone', number=userphone.phone), code=303)
        except ValueError as e:
            db.session.rollback()
            form.phone.errors.append(unicode(e))
    return render_form(form=form, title=_("Add a phone number"), formid='phone_add',
        submit=_("Add phone"), ajax=True)


@lastuser_ui.route('/account/phone/<number>/remove', methods=['GET', 'POST'])
@requires_login
def remove_phone(number):
    userphone = UserPhone.query.filter_by(phone=number, user=current_auth.user).first()
    if userphone is None:
        userphone = UserPhoneClaim.query.filter_by(phone=number, user=current_auth.user).first_or_404()
    if request.method == 'POST':
        # FIXME: Confirm validation success
        user_data_changed.send(current_auth.user, changes=['phone-delete'])
    return render_delete_sqla(userphone, db, title=_(u"Confirm removal"),
        message=_(u"Remove phone number {phone} from your account?").format(
            phone=userphone.phone),
        success=_(u"You have removed your number {phone}").format(phone=userphone.phone),
        next=url_for('.profile'),
        delete_text=_(u"Remove"))


@lastuser_ui.route('/account/phone/<number>/verify', methods=['GET', 'POST'])
@requires_login
@load_model(UserPhoneClaim, {'phone': 'number'}, 'phoneclaim', permission='verify')
def verify_phone(phoneclaim):
    form = VerifyPhoneForm()
    form.phoneclaim = phoneclaim
    if form.validate_on_submit():
        if UserPhone.get(phoneclaim.phone) is None:
            if not current_auth.user.phones:
                primary = True
            else:
                primary = False
            userphone = UserPhone(user=current_auth.user, phone=phoneclaim.phone, gets_text=True)
            userphone.primary = primary
            db.session.add(userphone)
            db.session.delete(phoneclaim)
            db.session.commit()
            flash(_("Your phone number has been verified"), 'success')
            user_data_changed.send(current_auth.user, changes=['phone'])
            return render_redirect(url_for('.profile'), code=303)
        else:
            db.session.delete(phoneclaim)
            db.session.commit()
            flash(_("This phone number has already been claimed by another user"), 'danger')
    return render_form(form=form, title=_("Verify phone number"), formid='phone_verify',
        submit=_("Verify"), ajax=True)


# Userid is a path here because obsolete OpenID ids are URLs (both direct and via Google)
@lastuser_ui.route('/account/extid/<service>/<path:userid>/remove', methods=['GET', 'POST'])
@requires_login
@load_model(UserExternalId, {'service': 'service', 'userid': 'userid'}, 'extid', permission='delete_extid')
def remove_extid(extid):
    num_extids = len(current_auth.user.externalids)
    has_pw_hash = bool(current_auth.user.pw_hash)
    if not has_pw_hash and num_extids == 1:
        flash(_("You do not have a password set. So you must have at least one external ID enabled."), 'danger')
        return render_redirect(url_for('.profile'), code=303)
    return render_delete_sqla(extid, db, title=_(u"Confirm delete"),
        message=_(u"Remove {service} account ‘{username}’ from your account?").format(service=login_registry[extid.service].title, username=extid.username),
        success=_(u"You have removed the {service} account ‘{username}’").format(service=login_registry[extid.service].title, username=extid.username),
        next=url_for('.profile'),
        delete_text=_(u"Remove"))
