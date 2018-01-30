# -*- coding: utf-8 -*-
from flask import abort, url_for, flash, redirect, session, render_template, request

from coaster.utils import valid_username
from coaster.auth import current_auth
from coaster.views import get_next_url
from baseframe import _
from baseframe.signals import exception_catchall
from lastuser_core import login_registry
from lastuser_core.models import db, getextid, merge_users, User, UserEmail, UserExternalId, UserEmailClaim
from lastuser_core.registry import LoginInitError, LoginCallbackError
from lastuser_core.signals import user_data_changed
from .. import lastuser_oauth
from ..forms.profile import ProfileMergeForm
from ..mailclient import send_email_verify_link
from ..views.helpers import login_internal, register_internal, set_loginmethod_cookie, requires_login


@lastuser_oauth.route('/login/<service>', methods=['GET', 'POST'])
def login_service(service):
    """
    Handle login with a registered service.
    """
    if service not in login_registry:
        abort(404)
    provider = login_registry[service]
    next_url = get_next_url(referrer=False, default=None)
    callback_url = url_for('.login_service_callback', service=service, next=next_url, _external=True)
    try:
        return provider.do(callback_url=callback_url)
    except (LoginInitError, LoginCallbackError) as e:
        msg = _(u"{service} login failed: {error}").format(service=provider.title, error=unicode(e))
        exception_catchall.send(e, message=msg)
        flash(msg, category='danger')
        return redirect(next_url or get_next_url(referrer=True))


@lastuser_oauth.route('/login/<service>/callback', methods=['GET', 'POST'])
def login_service_callback(service):
    """
    Callback handler for a login service.
    """
    if service not in login_registry:
        abort(404)
    provider = login_registry[service]
    try:
        userdata = provider.callback()
    except (LoginInitError, LoginCallbackError) as e:
        msg = _(u"{service} login failed: {error}").format(service=provider.title, error=unicode(e))
        exception_catchall.send(e, message=msg)
        flash(msg, category='danger')
        if current_auth.is_authenticated:
            return redirect(get_next_url(referrer=False))
        else:
            return redirect(url_for('.login'))
    return login_service_postcallback(service, userdata)


def get_user_extid(service, userdata):
    """
    Retrieves a 'user', 'extid' and 'useremail' from the given service and userdata.
    """
    provider = login_registry[service]
    extid = getextid(service=service, userid=userdata['userid'])

    user = None
    useremail = None

    if userdata.get('email'):
        useremail = UserEmail.get(email=userdata['email'])

    if extid is not None:
        user = extid.user
    # It is possible at this time that extid.user and useremail.user are different.
    # We do not handle it here, but in the parent function login_service_postcallback.
    elif useremail is not None and useremail.user is not None:
        user = useremail.user
    else:
        # Cross-check with all other instances of the same LoginProvider (if we don't have a user)
        # This is (for eg) for when we have two Twitter services with different access levels.
        for other_service, other_provider in login_registry.items():
            if other_service != service and other_provider.__class__ == provider.__class__:
                other_extid = getextid(service=other_service, userid=userdata['userid'])
                if other_extid is not None:
                    user = other_extid.user
                    break

    # TODO: Make this work when we have multiple confirmed email addresses available
    return user, extid, useremail


def login_service_postcallback(service, userdata):
    user, extid, useremail = get_user_extid(service, userdata)

    if extid is not None:
        extid.oauth_token = userdata.get('oauth_token')
        extid.oauth_token_secret = userdata.get('oauth_token_secret')
        extid.oauth_token_type = userdata.get('oauth_token_type')
        extid.username = userdata.get('username')
        # TODO: Save refresh token and expiry date where present
        extid.oauth_refresh_token = userdata.get('oauth_refresh_token')
        extid.oauth_expiry_date = userdata.get('oauth_expiry_date')
        extid.oauth_refresh_expiry = userdata.get('oauth_refresh_expiry')  # TODO: Check this
    else:
        # New external id. Register it.
        extid = UserExternalId(
            user=user,  # This may be None right now. Will be handled below
            service=service,
            userid=userdata['userid'],
            username=userdata.get('username'),
            oauth_token=userdata.get('oauth_token'),
            oauth_token_secret=userdata.get('oauth_token_secret'),
            oauth_token_type=userdata.get('oauth_token_type')
            # TODO: Save refresh token
            )
        db.session.add(extid)

    if user is None:
        if current_auth.is_authenticated:
            # Attach this id to currently logged-in user
            user = current_auth.user
            extid.user = user
        else:
            # Register a new user
            user = register_internal(None, userdata.get('fullname'), None)
            extid.user = user
            if userdata.get('username'):
                if valid_username(userdata['username']) and user.is_valid_username(userdata['username']):
                    # Set a username for this user if it's available
                    user.username = userdata['username']
    else:  # This id is attached to a user
        if current_auth.is_authenticated and current_auth.user != user:
            # Woah! Account merger handler required
            # Always confirm with user before doing an account merger
            session['merge_buid'] = user.buid
        elif useremail and useremail.user != user:
            session['merge_buid'] = useremail.user.buid

    # Check for new email addresses
    if userdata.get('email') and not useremail:
        user.add_email(userdata['email'])

    # If there are multiple email addresses, add any that are not already claimed.
    # If they are already claimed by another user, this calls for an account merge
    # request, but we can only merge two users at a time. Ask for a merge if there
    # isn't already one pending
    if userdata.get('emails'):
        for email in userdata['emails']:
            existing = UserEmail.get(email)
            if existing:
                if existing.user != user and 'merge_buid' not in session:
                    session['merge_buid'] = existing.user.buid
            else:
                user.add_email(email)

    if userdata.get('emailclaim'):
        emailclaim = UserEmailClaim(user=user, email=userdata['emailclaim'])
        db.session.add(emailclaim)
        send_email_verify_link(emailclaim)

    # Is the user's fullname missing? Populate it.
    if not user.fullname and userdata.get('fullname'):
        user.fullname = userdata['fullname']

    if not current_auth.is_authenticated:  # If a user isn't already logged in, login now.
        login_internal(user)
        flash(_(u"You have logged in via {service}").format(service=login_registry[service].title), 'success')
    next_url = get_next_url(session=True)

    db.session.commit()

    # Finally: set a login method cookie and send user on their way
    if not current_auth.user.is_profile_complete():
        login_next = url_for('.profile_new', next=next_url)
    else:
        login_next = next_url

    if 'merge_buid' in session:
        return set_loginmethod_cookie(redirect(url_for('.profile_merge', next=login_next), code=303), service)
    else:
        return set_loginmethod_cookie(redirect(login_next, code=303), service)


@lastuser_oauth.route('/profile/merge', methods=['GET', 'POST'])
@requires_login
def profile_merge():
    if 'merge_buid' not in session:
        return redirect(get_next_url(), code=302)
    other_user = User.get(buid=session['merge_buid'])
    if other_user is None:
        session.pop('merge_buid', None)
        return redirect(get_next_url(), code=302)
    form = ProfileMergeForm()
    if form.validate_on_submit():
        if 'merge' in request.form:
            new_user = merge_users(current_auth.user, other_user)
            login_internal(new_user)
            flash(_("Your accounts have been merged"), 'success')
            session.pop('merge_buid', None)
            db.session.commit()
            user_data_changed.send(new_user, changes=['merge'])
            return redirect(get_next_url(), code=303)
        else:
            session.pop('merge_buid', None)
            return redirect(get_next_url(), code=303)
    return render_template('merge.html.jinja2', form=form, user=current_auth.user, other_user=other_user,
        login_registry=login_registry)
