# -*- coding: utf-8 -*-

from flask import abort, flash, render_template, request, url_for

from baseframe import _
from baseframe.forms import render_delete_sqla, render_form, render_redirect
from coaster.auth import current_auth
from coaster.views import load_model, load_models
from lastuser_core.models import (
    Client,
    ClientCredential,
    Team,
    TeamClientPermissions,
    User,
    UserClientPermissions,
    db,
)
from lastuser_oauth.views.helpers import requires_login

from .. import lastuser_ui
from ..forms import (
    ClientCredentialForm,
    PermissionEditForm,
    RegisterClientForm,
    TeamPermissionAssignForm,
    UserPermissionAssignForm,
)

# --- Routes: client apps -----------------------------------------------------


@lastuser_ui.route('/apps')
@requires_login
def client_list():
    if current_auth.is_authenticated:
        return render_template(
            'client_list.html.jinja2',
            clients=Client.query.filter(
                db.or_(
                    Client.user == current_auth.user,
                    Client.org_id.in_(current_auth.user.organizations_owned_ids()),
                )
            )
            .order_by(Client.title)
            .all(),
        )
    else:
        # TODO: Show better UI for non-logged in users
        return render_template('client_list.html.jinja2', clients=[])


@lastuser_ui.route('/apps/all')
def client_list_all():
    return render_template(
        'client_list.html.jinja2', clients=Client.query.order_by(Client.title).all()
    )


def available_client_owners():
    """
    Return a list of possible client owners for the current user.
    """
    choices = []
    choices.append((current_auth.user.buid, current_auth.user.pickername))
    for org in current_auth.user.organizations_owned():
        choices.append((org.buid, org.pickername))
    return choices


@lastuser_ui.route('/apps/new', methods=['GET', 'POST'])
@requires_login
def client_new():
    form = RegisterClientForm(model=Client)
    form.edit_user = current_auth.user
    form.client_owner.choices = available_client_owners()
    if request.method == 'GET':
        form.client_owner.data = current_auth.user.buid

    if form.validate_on_submit():
        client = Client()
        form.populate_obj(client)
        client.user = form.user
        client.org = form.org
        client.trusted = False
        db.session.add(client)
        db.session.commit()
        return render_redirect(url_for('.client_info', key=client.buid), code=303)

    return render_form(
        form=form,
        title=_("Register a new client application"),
        formid='client_new',
        submit=_("Register application"),
        ajax=True,
    )


@lastuser_ui.route('/apps/<key>')
@load_model(Client, {'buid': 'key'}, 'client', permission='view')
def client_info(client):
    if client.user:
        permassignments = UserClientPermissions.query.filter_by(client=client).all()
    else:
        permassignments = TeamClientPermissions.query.filter_by(client=client).all()
    return render_template(
        'client_info.html.jinja2', client=client, permassignments=permassignments
    )


@lastuser_ui.route('/apps/<key>/edit', methods=['GET', 'POST'])
@requires_login
@load_model(Client, {'buid': 'key'}, 'client', permission='edit')
def client_edit(client):
    form = RegisterClientForm(obj=client, model=Client)
    form.edit_user = current_auth.user
    form.client_owner.choices = available_client_owners()
    if request.method == 'GET':
        if client.user:
            form.client_owner.data = client.user.buid
        else:
            form.client_owner.data = client.org.buid

    if form.validate_on_submit():
        if client.user != form.user or client.org != form.org:
            # Ownership has changed. Remove existing permission assignments
            for perm in UserClientPermissions.query.filter_by(client=client).all():
                db.session.delete(perm)
            for perm in TeamClientPermissions.query.filter_by(client=client).all():
                db.session.delete(perm)
            flash(
                _(
                    "This application’s owner has changed, so all previously assigned permissions "
                    "have been revoked"
                ),
                'warning',
            )
        form.populate_obj(client)
        client.user = form.user
        client.org = form.org
        db.session.commit()
        return render_redirect(url_for('.client_info', key=client.buid), code=303)

    return render_form(
        form=form,
        title=_("Edit application"),
        formid='client_edit',
        submit=_("Save changes"),
        ajax=True,
    )


@lastuser_ui.route('/apps/<key>/delete', methods=['GET', 'POST'])
@requires_login
@load_model(Client, {'buid': 'key'}, 'client', permission='delete')
def client_delete(client):
    return render_delete_sqla(
        client,
        db,
        title=_("Confirm delete"),
        message=_("Delete application ‘{title}’? ").format(title=client.title),
        success=_(
            "You have deleted application ‘{title}’ and all its associated resources and permission assignments"
        ).format(title=client.title),
        next=url_for('.client_list'),
    )


# --- Routes: client credentials ----------------------------------------------


@lastuser_ui.route('/apps/<key>/cred', methods=['GET', 'POST'])
@requires_login
@load_model(Client, {'buid': 'key'}, 'client', permission='edit')
def client_cred_new(client):
    form = ClientCredentialForm()
    if request.method == 'GET' and not client.credentials:
        form.title.data = _("Default")
    if form.validate_on_submit():
        cred, secret = ClientCredential.new(client)
        cred.title = form.title.data
        db.session.commit()
        return render_template(
            'client_cred.html.jinja2', name=cred.name, secret=secret, cred=cred
        )
    return render_form(
        form=form,
        title=_("New access key"),
        formid='client_cred',
        submit=_("Create"),
        ajax=False,
    )


@lastuser_ui.route('/apps/<key>/cred/<name>/delete', methods=['GET', 'POST'])
@requires_login
@load_models(
    (Client, {'buid': 'key'}, 'client'),
    (ClientCredential, {'name': 'name', 'client': 'client'}, 'cred'),
    permission='delete',
)
def client_cred_delete(client, cred):
    return render_delete_sqla(
        cred,
        db,
        title=_("Confirm delete"),
        message=_("Delete access key ‘{title}’? ").format(title=cred.title),
        success=_("You have deleted access key ‘{title}’").format(title=cred.title),
        next=url_for('.client_info', key=client.buid),
    )


# --- Routes: client app permissions ------------------------------------------


@lastuser_ui.route('/apps/<key>/perms/new', methods=['GET', 'POST'])
@requires_login
@load_model(Client, {'buid': 'key'}, 'client', permission='assign-permissions')
def permission_user_new(client):
    if client.user:
        form = UserPermissionAssignForm()
    elif client.org:
        form = TeamPermissionAssignForm()
        form.org = client.org
        form.team_id.choices = [(team.buid, team.title) for team in client.org.teams]
    else:
        abort(403)  # This should never happen. Clients always have an owner.
    if form.validate_on_submit():
        perms = set()
        if client.user:
            permassign = UserClientPermissions.query.filter_by(
                user=form.user.data, client=client
            ).first()
            if permassign:
                perms.update(permassign.access_permissions.split())
            else:
                permassign = UserClientPermissions(user=form.user.data, client=client)
                db.session.add(permassign)
        else:
            permassign = TeamClientPermissions.query.filter_by(
                team=form.team, client=client
            ).first()
            if permassign:
                perms.update(permassign.access_permissions.split())
            else:
                permassign = TeamClientPermissions(team=form.team, client=client)
                db.session.add(permassign)
        perms.update(form.perms.data.split())
        permassign.access_permissions = ' '.join(sorted(perms))
        db.session.commit()
        if client.user:
            flash(
                _("Permissions have been assigned to user {pname}").format(
                    pname=form.user.data.pickername
                ),
                'success',
            )
        else:
            flash(
                _("Permissions have been assigned to team ‘{pname}’").format(
                    pname=permassign.team.pickername
                ),
                'success',
            )
        return render_redirect(url_for('.client_info', key=client.buid), code=303)
    return render_form(
        form=form,
        title=_("Assign permissions"),
        formid='perm_assign',
        submit=_("Assign permissions"),
    )


@lastuser_ui.route('/apps/<key>/perms/<buid>/edit', methods=['GET', 'POST'])
@requires_login
@load_model(
    Client, {'buid': 'key'}, 'client', permission='assign-permissions', kwargs=True
)
def permission_user_edit(client, kwargs):
    if client.user:
        user = User.get(buid=kwargs['buid'])
        if not user:
            abort(404)
        permassign = UserClientPermissions.query.filter_by(
            user=user, client=client
        ).first_or_404()
    elif client.org:
        team = Team.get(buid=kwargs['buid'])
        if not team:
            abort(404)
        permassign = TeamClientPermissions.query.filter_by(
            team=team, client=client
        ).first_or_404()
    form = PermissionEditForm()
    if request.method == 'GET':
        if permassign:
            form.perms.data = permassign.access_permissions
    if form.validate_on_submit():
        perms = ' '.join(sorted(form.perms.data.split()))
        if not perms:
            db.session.delete(permassign)
        else:
            permassign.access_permissions = perms
        db.session.commit()
        if perms:
            if client.user:
                flash(
                    _("Permissions have been updated for user {pname}").format(
                        pname=user.pickername
                    ),
                    'success',
                )
            else:
                flash(
                    _("Permissions have been updated for team {title}").format(
                        title=team.title
                    ),
                    'success',
                )
        else:
            if client.user:
                flash(
                    _("All permissions have been revoked for user {pname}").format(
                        pname=user.pickername
                    ),
                    'success',
                )
            else:
                flash(
                    _("All permissions have been revoked for team {title}").format(
                        title=team.title
                    ),
                    'success',
                )
        return render_redirect(url_for('.client_info', key=client.buid), code=303)
    return render_form(
        form=form,
        title=_("Edit permissions"),
        formid='perm_edit',
        submit=_("Save changes"),
        ajax=True,
    )


@lastuser_ui.route('/apps/<key>/perms/<buid>/delete', methods=['GET', 'POST'])
@requires_login
@load_model(
    Client, {'buid': 'key'}, 'client', permission='assign-permissions', kwargs=True
)
def permission_user_delete(client, kwargs):
    if client.user:
        user = User.get(buid=kwargs['buid'])
        if not user:
            abort(404)
        permassign = UserClientPermissions.query.filter_by(
            user=user, client=client
        ).first_or_404()
        return render_delete_sqla(
            permassign,
            db,
            title=_("Confirm delete"),
            message=_(
                "Remove all permissions assigned to user {pname} for app ‘{title}’?"
            ).format(pname=user.pickername, title=client.title),
            success=_("You have revoked permisions for user {pname}").format(
                pname=user.pickername
            ),
            next=url_for('.client_info', key=client.buid),
        )
    else:
        team = Team.get(buid=kwargs['buid'])
        if not team:
            abort(404)
        permassign = TeamClientPermissions.query.filter_by(
            team=team, client=client
        ).first_or_404()
        return render_delete_sqla(
            permassign,
            db,
            title=_("Confirm delete"),
            message=_(
                "Remove all permissions assigned to team ‘{pname}’ for app ‘{title}’?"
            ).format(pname=team.title, title=client.title),
            success=_("You have revoked permisions for team {title}").format(
                title=team.title
            ),
            next=url_for('.client_info', key=client.buid),
        )
