# -*- coding: utf-8 -*-

from flask import request, render_template, url_for, flash, abort
from coaster.auth import current_auth
from coaster.views import load_model, load_models
from baseframe import _
from baseframe.forms import render_form, render_redirect, render_delete_sqla

from lastuser_core.models import (db, User, Client, Organization, Team, Permission, ClientCredential,
    UserClientPermissions, TeamClientPermissions, Resource, ResourceAction, ClientTeamAccess,
    CLIENT_TEAM_ACCESS)
from lastuser_oauth.views.helpers import requires_login
from .. import lastuser_ui
from ..forms import (RegisterClientForm, PermissionForm, UserPermissionAssignForm, ClientCredentialForm,
    TeamPermissionAssignForm, PermissionEditForm, ResourceForm, ResourceActionForm, ClientTeamAccessForm)

# --- Routes: client apps -----------------------------------------------------


@lastuser_ui.route('/apps')
@requires_login
def client_list():
    if current_auth.is_authenticated:
        return render_template('client_list.html.jinja2', clients=Client.query.filter(db.or_(Client.user == current_auth.user,
            Client.org_id.in_(current_auth.user.organizations_owned_ids()))).order_by('title').all())
    else:
        # TODO: Show better UI for non-logged in users
        return render_template('client_list.html.jinja2', clients=[])


@lastuser_ui.route('/apps/all')
def client_list_all():
    return render_template('client_list.html.jinja2', clients=Client.query.order_by('title').all())


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
        return render_redirect(url_for('.client_info', key=client.key), code=303)

    return render_form(form=form, title=_("Register a new client application"),
        formid='client_new', submit=_("Register application"), ajax=True)


@lastuser_ui.route('/apps/<key>')
@load_model(Client, {'key': 'key'}, 'client', permission='view')
def client_info(client):
    if client.user:
        permassignments = UserClientPermissions.query.filter_by(client=client).all()
    else:
        permassignments = TeamClientPermissions.query.filter_by(client=client).all()
    resources = Resource.query.filter_by(client=client).order_by('name').all()
    return render_template('client_info.html.jinja2', client=client,
        permassignments=permassignments,
        resources=resources)


@lastuser_ui.route('/apps/<key>/edit', methods=['GET', 'POST'])
@requires_login
@load_model(Client, {'key': 'key'}, 'client', permission='edit')
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
            flash(_(u"This application’s owner has changed, so all previously assigned permissions "
                "have been revoked"), 'warning')
        form.populate_obj(client)
        client.user = form.user
        client.org = form.org
        if not client.team_access:
            # This client does not have access to teams in organizations. Remove all existing assignments
            for cta in ClientTeamAccess.query.filter_by(client=client).all():
                db.session.delete(cta)
        db.session.commit()
        return render_redirect(url_for('.client_info', key=client.key), code=303)

    return render_form(form=form, title=_("Edit application"), formid='client_edit',
        submit=_("Save changes"), ajax=True)


@lastuser_ui.route('/apps/<key>/delete', methods=['GET', 'POST'])
@requires_login
@load_model(Client, {'key': 'key'}, 'client', permission='delete')
def client_delete(client):
    return render_delete_sqla(client, db, title=_(u"Confirm delete"),
        message=_(u"Delete application ‘{title}’? ").format(title=client.title),
        success=_(u"You have deleted application ‘{title}’ and all its associated resources and permission assignments").format(
            title=client.title),
        next=url_for('.client_list'))


# --- Routes: client credentials ----------------------------------------------

@lastuser_ui.route('/apps/<key>/cred', methods=['GET', 'POST'])
@requires_login
@load_model(Client, {'key': 'key'}, 'client', permission='edit')
def client_cred_new(client):
    form = ClientCredentialForm()
    if request.method == 'GET' and not client.credentials:
        form.title.data = _("Default")
    if form.validate_on_submit():
        cred, secret = ClientCredential.new(client)
        cred.title = form.title.data
        db.session.commit()
        return render_template('client_cred.html.jinja2', name=cred.name, secret=secret, cred=cred)
    return render_form(form=form, title=_("New access key"), formid='client_cred',
        submit=_("Create"), ajax=False)


@lastuser_ui.route('/apps/<key>/cred/<name>/delete', methods=['GET', 'POST'])
@requires_login
@load_models(
    (Client, {'key': 'key'}, 'client'),
    (ClientCredential, {'name': 'name', 'client': 'client'}, 'cred'),
    permission='delete')
def client_cred_delete(client, cred):
    return render_delete_sqla(cred, db, title=_(u"Confirm delete"),
        message=_(u"Delete access key ‘{title}’? ").format(title=cred.title),
        success=_(u"You have deleted access key ‘{title}’").format(title=cred.title),
        next=url_for('.client_info', key=client.key))


# --- Routes: user permissions ------------------------------------------------

@lastuser_ui.route('/perms')
@requires_login
def permission_list():
    allperms = Permission.query.filter_by(allusers=True).order_by('name').all()
    userperms = Permission.query.filter(
        db.or_(Permission.user_id == current_auth.user.id,
               Permission.org_id.in_(current_auth.user.organizations_owned_ids()))
        ).order_by('name').all()
    return render_template('permission_list.html.jinja2', allperms=allperms, userperms=userperms)


@lastuser_ui.route('/perms/new', methods=['GET', 'POST'])
@requires_login
def permission_new():
    form = PermissionForm()
    form.edit_user = current_auth.user
    form.context.choices = available_client_owners()
    if request.method == 'GET':
        form.context.data = current_auth.user.buid
    if form.validate_on_submit():
        perm = Permission()
        form.populate_obj(perm)
        perm.user = form.user
        perm.org = form.org
        perm.allusers = False
        db.session.add(perm)
        db.session.commit()
        flash(_("Your new permission has been defined"), 'success')
        return render_redirect(url_for('.permission_list'), code=303)
    return render_form(form=form, title=_("Define a new permission"), formid='perm_new',
        submit=_("Define new permission"), ajax=True)


@lastuser_ui.route('/perms/<int:id>/edit', methods=['GET', 'POST'])
@requires_login
@load_model(Permission, {'id': 'id'}, 'perm', permission='edit')
def permission_edit(perm):
    form = PermissionForm(obj=perm)
    form.edit_user = current_auth.user
    form.context.choices = available_client_owners()
    if request.method == 'GET':
        if perm.user:
            form.context.data = perm.user.buid
        else:
            form.context.data = perm.org.buid
    if form.validate_on_submit():
        form.populate_obj(perm)
        perm.user = form.user
        perm.org = form.org
        db.session.commit()
        flash(_("Your permission has been saved"), 'success')
        return render_redirect(url_for('.permission_list'), code=303)
    return render_form(form=form, title=_("Edit permission"), formid='perm_edit',
        submit=_("Save changes"), ajax=True)


@lastuser_ui.route('/perms/<int:id>/delete', methods=['GET', 'POST'])
@requires_login
@load_model(Permission, {'id': 'id'}, 'perm', permission='delete')
def permission_delete(perm):
    return render_delete_sqla(perm, db, title=_(u"Confirm delete"), message=_(u"Delete permission ‘{name}’?").format(name=perm.name),
        success=_("Your permission has been deleted"),
        next=url_for('.permission_list'))


# --- Routes: client app permissions ------------------------------------------


@lastuser_ui.route('/apps/<key>/perms/new', methods=['GET', 'POST'])
@requires_login
@load_model(Client, {'key': 'key'}, 'client', permission='assign-permissions')
def permission_user_new(client):
    if client.user:
        available_perms = Permission.query.filter(db.or_(
            Permission.allusers == True,
            Permission.user == current_auth.user)).order_by('name').all()  # NOQA
        form = UserPermissionAssignForm()
    elif client.org:
        available_perms = Permission.query.filter(db.or_(
            Permission.allusers == True,
            Permission.org == client.org)).order_by('name').all()  # NOQA
        form = TeamPermissionAssignForm()
        form.org = client.org
        form.team_id.choices = [(team.buid, team.title) for team in client.org.teams]
    else:
        abort(403)  # This should never happen. Clients always have an owner.
    form.perms.choices = [(ap.name, _(u"{name} – {title}").format(name=ap.name, title=ap.title)) for ap in available_perms]
    if form.validate_on_submit():
        perms = set()
        if client.user:
            permassign = UserClientPermissions.query.filter_by(user=form.user.data, client=client).first()
            if permassign:
                perms.update(permassign.access_permissions.split(u' '))
            else:
                permassign = UserClientPermissions(user=form.user.data, client=client)
                db.session.add(permassign)
        else:
            permassign = TeamClientPermissions.query.filter_by(team=form.team, client=client).first()
            if permassign:
                perms.update(permassign.access_permissions.split(u' '))
            else:
                permassign = TeamClientPermissions(team=form.team, client=client)
                db.session.add(permassign)
        perms.update(form.perms.data)
        permassign.access_permissions = u' '.join(sorted(perms))
        db.session.commit()
        if client.user:
            flash(_(u"Permissions have been assigned to user {pname}").format(pname=form.user.data.pickername), 'success')
        else:
            flash(_(u"Permissions have been assigned to team ‘{pname}’").format(pname=permassign.team.pickername), 'success')
        return render_redirect(url_for('.client_info', key=client.key), code=303)
    return render_form(form=form, title=_("Assign permissions"), formid='perm_assign',
        submit=_("Assign permissions"))


@lastuser_ui.route('/apps/<key>/perms/<buid>/edit', methods=['GET', 'POST'])
@requires_login
@load_model(Client, {'key': 'key'}, 'client', permission='assign-permissions', kwargs=True)
def permission_user_edit(client, kwargs):
    if client.user:
        user = User.get(buid=kwargs['buid'])
        if not user:
            abort(404)
        available_perms = Permission.query.filter(db.or_(
            Permission.allusers == True,
            Permission.user == current_auth.user)).order_by('name').all()  # NOQA
        permassign = UserClientPermissions.query.filter_by(user=user, client=client).first_or_404()
    elif client.org:
        team = Team.get(buid=kwargs['buid'])
        if not team:
            abort(404)
        available_perms = Permission.query.filter(db.or_(
            Permission.allusers == True,
            Permission.org == client.org)).order_by('name').all()  # NOQA
        permassign = TeamClientPermissions.query.filter_by(team=team, client=client).first_or_404()
    form = PermissionEditForm()
    form.perms.choices = [(ap.name, _(u"{name} – {title}").format(name=ap.name, title=ap.title)) for ap in available_perms]
    if request.method == 'GET':
        if permassign:
            form.perms.data = permassign.access_permissions.split(u' ')
    if form.validate_on_submit():
        form.perms.data.sort()
        perms = u' '.join(form.perms.data)
        if not perms:
            db.session.delete(permassign)
        else:
            permassign.access_permissions = perms
        db.session.commit()
        if perms:
            if client.user:
                flash(_(u"Permissions have been updated for user {pname}").format(pname=user.pickername), 'success')
            else:
                flash(_(u"Permissions have been updated for team {title}").format(title=team.title), 'success')
        else:
            if client.user:
                flash(_(u"All permissions have been revoked for user {pname}").format(pname=user.pickername), 'success')
            else:
                flash(_(u"All permissions have been revoked for team {title}").format(title=team.title), 'success')
        return render_redirect(url_for('.client_info', key=client.key), code=303)
    return render_form(form=form, title=_("Edit permissions"), formid='perm_edit', submit=_("Save changes"), ajax=True)


@lastuser_ui.route('/apps/<key>/perms/<buid>/delete', methods=['GET', 'POST'])
@requires_login
@load_model(Client, {'key': 'key'}, 'client', permission='assign-permissions', kwargs=True)
def permission_user_delete(client, kwargs):
    if client.user:
        user = User.get(buid=kwargs['buid'])
        if not user:
            abort(404)
        permassign = UserClientPermissions.query.filter_by(user=user, client=client).first_or_404()
        return render_delete_sqla(permassign, db, title=_(u"Confirm delete"),
            message=_(u"Remove all permissions assigned to user {pname} for app ‘{title}’?").format(
                pname=user.pickername, title=client.title),
            success=_(u"You have revoked permisions for user {pname}").format(pname=user.pickername),
            next=url_for('.client_info', key=client.key))
    else:
        team = Team.get(buid=kwargs['buid'])
        if not team:
            abort(404)
        permassign = TeamClientPermissions.query.filter_by(team=team, client=client).first_or_404()
        return render_delete_sqla(permassign, db, title=_(u"Confirm delete"),
            message=_(u"Remove all permissions assigned to team ‘{pname}’ for app ‘{title}’?").format(
                pname=team.title, title=client.title),
            success=_(u"You have revoked permisions for team {title}").format(title=team.title),
            next=url_for('.client_info', key=client.key))


# --- Routes: client app resources --------------------------------------------

@lastuser_ui.route('/apps/<key>/resources/new', methods=['GET', 'POST'])
@requires_login
@load_model(Client, {'key': 'key'}, 'client', permission='new-resource')
def resource_new(client):
    form = ResourceForm()
    form.client = client
    form.edit_id = None
    if form.validate_on_submit():
        resource = Resource(client=client)
        form.populate_obj(resource)
        db.session.add(resource)
        db.session.commit()
        flash(_("Your new resource has been saved"), 'success')
        return render_redirect(url_for('.client_info', key=client.key), code=303)
    return render_form(form=form, title=_("Define a resource"), formid='resource_new',
        submit=_("Define resource"), ajax=True)


@lastuser_ui.route('/apps/<key>/resources/<int:idr>/edit', methods=['GET', 'POST'])
@requires_login
@load_models(
    (Client, {'key': 'key'}, 'client'),
    (Resource, {'id': 'idr', 'client': 'client'}, 'resource'),
    permission='edit')
def resource_edit(client, resource):
    form = ResourceForm(obj=resource)
    form.client = client
    if form.validate_on_submit():
        form.populate_obj(resource)
        db.session.commit()
        flash(_("Your resource has been edited"), 'success')
        return render_redirect(url_for('.client_info', key=client.key), code=303)
    return render_form(form=form, title=_("Edit resource"), formid='resource_edit',
        submit=_("Save changes"), ajax=True)


@lastuser_ui.route('/apps/<key>/resources/<int:idr>/delete', methods=['GET', 'POST'])
@requires_login
@load_models(
    (Client, {'key': 'key'}, 'client'),
    (Resource, {'id': 'idr', 'client': 'client'}, 'resource'),
    permission='delete')
def resource_delete(client, resource):
    return render_delete_sqla(resource, db, title=_(u"Confirm delete"),
        message=_(u"Delete resource ‘{resource}’ from app ‘{client}’?").format(
            resource=resource.title, client=client.title),
        success=_(u"You have deleted resource ‘{resource}’ on app ‘{client}’").format(
            resource=resource.title, client=client.title),
        next=url_for('.client_info', key=client.key))


# --- Routes: resource actions ------------------------------------------------

@lastuser_ui.route('/apps/<key>/resources/<int:idr>/actions/new', methods=['GET', 'POST'])
@requires_login
@load_models(
    (Client, {'key': 'key'}, 'client'),
    (Resource, {'id': 'idr', 'client': 'client'}, 'resource'),
    permission='new-action')
def resource_action_new(client, resource):
    form = ResourceActionForm()
    form.edit_id = None
    form.edit_resource = resource
    if form.validate_on_submit():
        action = ResourceAction(resource=resource)
        form.populate_obj(action)
        db.session.add(action)
        db.session.commit()
        flash(_("Your new action has been saved"), 'success')
        return render_redirect(url_for('.client_info', key=client.key), code=303)
    return render_form(form=form, title=_("Define an action"), formid='action_new',
        submit=_("Define action"), ajax=True)


@lastuser_ui.route('/apps/<key>/resources/<int:idr>/actions/<int:ida>/edit', methods=['GET', 'POST'])
@requires_login
@load_models(
    (Client, {'key': 'key'}, 'client'),
    (Resource, {'id': 'idr', 'client': 'client'}, 'resource'),
    (ResourceAction, {'id': 'ida', 'resource': 'resource'}, 'action'),
    permission='edit')
def resource_action_edit(client, resource, action):
    form = ResourceActionForm(obj=action)
    form.edit_resource = resource
    if form.validate_on_submit():
        form.populate_obj(action)
        db.session.commit()
        flash(_("Your action has been edited"), 'success')
        return render_redirect(url_for('.client_info', key=client.key), code=303)
    return render_form(form=form, title=_("Edit action"), formid='action_edit',
        submit=_("Save changes"), ajax=True)


@lastuser_ui.route('/apps/<key>/resources/<int:idr>/actions/<int:ida>/delete', methods=['GET', 'POST'])
@requires_login
@load_models(
    (Client, {'key': 'key'}, 'client'),
    (Resource, {'id': 'idr', 'client': 'client'}, 'resource'),
    (ResourceAction, {'id': 'ida', 'resource': 'resource'}, 'action'),
    permission='delete')
def resource_action_delete(client, resource, action):
    return render_delete_sqla(action, db, title=_("Confirm delete"),
        message=_(u"Delete action ‘{action}’ from resource ‘{resource}’ of app ‘{client}’?").format(
            action=action.title, resource=resource.title, client=client.title),
        success=_(u"You have deleted action ‘{action}’ on resource ‘{resource}’ of app ‘{client}’").format(
            action=action.title, resource=resource.title, client=client.title),
        next=url_for('.client_info', key=client.key))


# --- Routes: client team access ----------------------------------------------

@lastuser_ui.route('/apps/<key>/teams', methods=['GET', 'POST'])
@requires_login
@load_model(Client, {'key': 'key'}, 'client')
def client_team_access(client):
    form = ClientTeamAccessForm()
    user_orgs = current_auth.user.organizations_owned()
    form.organizations.choices = [(org.buid, org.title) for org in user_orgs]
    org_selected = [org.buid for org in user_orgs if client in org.clients_with_team_access()]
    if request.method == 'GET':
        form.organizations.data = org_selected
    if form.validate_on_submit():
        org_del = Organization.query.filter(Organization.buid.in_(
            set(org_selected) - set(form.organizations.data))).all()
        org_add = Organization.query.filter(Organization.buid.in_(
            set(form.organizations.data) - set(org_selected))).all()
        cta_del = ClientTeamAccess.query.filter_by(client=client).filter(
            ClientTeamAccess.org_id.in_([org.id for org in org_del])).all()
        for cta in cta_del:
            db.session.delete(cta)
        for org in org_add:
            cta = ClientTeamAccess(org=org, client=client, access_level=CLIENT_TEAM_ACCESS.ALL)
            db.session.add(cta)
        db.session.commit()
        flash(_("You have assigned access to teams in your organizations for this app"), 'success')
        return render_redirect(url_for('.client_info', key=client.key), code=303)
    return render_form(form=form, title=_("Select organizations"), submit=_("Save"), ajax=True)
