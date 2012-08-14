# -*- coding: utf-8 -*-

from flask import g, request, render_template, url_for, flash, abort
from baseframe.forms import render_form, render_redirect, render_delete_sqla

from lastuserapp import app
from lastuserapp.models import (db, User, Client, Organization, Team, Permission,
    UserClientPermissions, TeamClientPermissions, Resource, ResourceAction, ClientTeamAccess,
    CLIENT_TEAM_ACCESS)
from lastuserapp.forms import (RegisterClientForm, PermissionForm, UserPermissionAssignForm,
    TeamPermissionAssignForm, PermissionEditForm, ResourceForm, ResourceActionForm, ClientTeamAccessForm)
from lastuserapp.views.helpers import requires_login

# --- Routes: client apps -----------------------------------------------------


@app.route('/apps')
def client_list():
    if g.user:
        return render_template('client_list.html', clients=Client.query.filter(db.or_(Client.user == g.user,
            Client.org_id.in_(g.user.organizations_owned_ids()))).order_by('title').all())
    else:
        # TODO: Show better UI for non-logged in users
        return render_template('client_list.html', clients=[])


@app.route('/apps/all')
def client_list_all():
    return render_template('client_list.html', clients=Client.query.order_by('title').all())


def available_client_owners():
    """
    Return a list of possible client owners for the current user.
    """
    choices = []
    choices.append((g.user.userid, g.user.pickername))
    for org in g.user.organizations_owned():
        choices.append((org.userid, org.pickername))
    return choices


@app.route('/apps/new', methods=['GET', 'POST'])
@requires_login
def client_new():
    form = RegisterClientForm()
    form.client_owner.choices = available_client_owners()
    if request.method == 'GET':
        form.client_owner.data = g.user.userid

    if form.validate_on_submit():
        client = Client()
        form.populate_obj(client)
        client.user = form.user
        client.org = form.org
        client.trusted = False
        db.session.add(client)
        db.session.commit()
        return render_redirect(url_for('client_info', key=client.key), code=303)

    return render_form(form=form, title="Register a new client application",
        formid="client_new", submit="Register application", ajax=True)


@app.route('/apps/<key>')
def client_info(key):
    client = Client.query.filter_by(key=key).first_or_404()
    if client.user:
        permassignments = UserClientPermissions.query.filter_by(client=client).all()
    else:
        permassignments = TeamClientPermissions.query.filter_by(client=client).all()
    resources = Resource.query.filter_by(client=client).order_by('name').all()
    return render_template('client_info.html', client=client,
        permassignments=permassignments,
        resources=resources)


@app.route('/apps/<key>/edit', methods=['GET', 'POST'])
@requires_login
def client_edit(key):
    client = Client.query.filter_by(key=key).first_or_404()
    if not client.owner_is(g.user):
        abort(403)

    form = RegisterClientForm(obj=client)
    form.edit_obj = client
    form.client_owner.choices = available_client_owners()
    if request.method == 'GET':
        if client.user:
            form.client_owner.data = client.user.userid
        else:
            form.client_owner.data = client.org.userid

    if form.validate_on_submit():
        if client.user != form.user or client.org != form.org:
            # Ownership has changed. Remove existing permission assignments
            for perm in UserClientPermissions.query.filter_by(client=client).all():
                db.session.delete(perm)
            for perm in TeamClientPermissions.query.filter_by(client=client).all():
                db.session.delete(perm)
            flash("This application’s owner has changed, so all previously assigned permissions "
                "have been revoked", "warning")
        form.populate_obj(client)
        client.user = form.user
        client.org = form.org
        if not client.team_access:
            # This client does not have access to teams in organizations. Remove all existing assignments
            for cta in ClientTeamAccess.query.filter_by(client=client).all():
                db.session.delete(cta)
        db.session.commit()
        return render_redirect(url_for('client_info', key=client.key), code=303)

    return render_form(form=form, title="Edit application", formid="client_edit",
        submit="Save changes", ajax=True)


@app.route('/apps/<key>/delete', methods=['GET', 'POST'])
@requires_login
def client_delete(key):
    client = Client.query.filter_by(key=key).first_or_404()
    if not client.owner_is(g.user):
        abort(403)
    return render_delete_sqla(client, db, title="Confirm delete", message="Delete application '%s'? " % client.title,
        success="You have deleted application '%s' and all its associated permissions and resources" % client.title,
        next=url_for('client_list'))


# --- Routes: user permissions ------------------------------------------------


@app.route('/perms')
@requires_login
def permission_list():
    allperms = Permission.query.filter_by(allusers=True).order_by('name').all()
    userperms = Permission.query.filter(
        db.or_(Permission.user_id == g.user.id,
               Permission.org_id.in_(g.user.organizations_owned_ids()))
        ).order_by('name').all()
    return render_template('permission_list.html', allperms=allperms, userperms=userperms)


@app.route('/perms/new', methods=['GET', 'POST'])
@requires_login
def permission_new():
    form = PermissionForm()
    form.context.choices = available_client_owners()
    if request.method == 'GET':
        form.context.data = g.user.userid
    if form.validate_on_submit():
        perm = Permission()
        form.populate_obj(perm)
        perm.user = form.user
        perm.org = form.org
        perm.allusers = False
        db.session.add(perm)
        db.session.commit()
        flash("Your new permission has been defined", "info")
        return render_redirect(url_for('permission_list'), code=303)
    return render_form(form=form, title="Define a new permission", formid="perm_new",
        submit="Define new permission", ajax=True)


@app.route('/perms/<int:id>/edit', methods=['GET', 'POST'])
@requires_login
def permission_edit(id):
    perm = Permission.query.get_or_404(id)
    if not perm.owner_is(g.user):
        abort(403)
    form = PermissionForm(obj=perm)
    form.context.choices = available_client_owners()
    form.edit_obj = perm
    if request.method == 'GET':
        if perm.user:
            form.context.data = perm.user.userid
        else:
            form.context.data = perm.org.userid
    if form.validate_on_submit():
        form.populate_obj(perm)
        perm.user = form.user
        perm.org = form.org
        db.session.commit()
        flash("Your permission has been saved", "info")
        return render_redirect(url_for('permission_list'), code=303)
    return render_form(form=form, title="Edit permission", formid="perm_edit",
        submit="Save changes", ajax=True)


@app.route('/perms/<int:id>/delete', methods=['GET', 'POST'])
@requires_login
def permission_delete(id):
    perm = Permission.query.get_or_404(id)
    if not perm.owner_is(g.user):
        abort(403)
    return render_delete_sqla(perm, db, title="Confirm delete", message="Delete permission %s?" % perm.name,
        success="Your permission has been deleted",
        next=url_for('permission_list'))


# --- Routes: client app permissions ------------------------------------------


@app.route('/apps/<key>/perms/new', methods=['GET', 'POST'])
@requires_login
def permission_user_new(key):
    client = Client.query.filter_by(key=key).first_or_404()
    if not client.owner_is(g.user):
        abort(403)
    if client.user:
        available_perms = Permission.query.filter(db.or_(
            Permission.allusers == True,
            Permission.user == g.user)).order_by('name').all()
        form = UserPermissionAssignForm()
    elif client.org:
        available_perms = Permission.query.filter(db.or_(
            Permission.allusers == True,
            Permission.org == client.org)).order_by('name').all()
        form = TeamPermissionAssignForm()
        form.org = client.org
        form.team_id.choices = [(team.userid, team.title) for team in client.org.teams]
    else:
        abort(403)  # This should never happen. Clients always have an owner.
    form.perms.choices = [(ap.name, u"%s – %s" % (ap.name, ap.title)) for ap in available_perms]
    if form.validate_on_submit():
        perms = set()
        if client.user:
            permassign = UserClientPermissions.query.filter_by(user=form.user, client=client).first()
            if permassign:
                perms.update(permassign.permissions.split(u' '))
            else:
                permassign = UserClientPermissions(user=form.user, client=client)
                db.session.add(permassign)
        else:
            permassign = TeamClientPermissions.query.filter_by(team=form.team, client=client).first()
            if permassign:
                perms.update(permassign.permissions.split(u' '))
            else:
                permassign = TeamClientPermissions(team=form.team, client=client)
                db.session.add(permassign)
        perms.update(form.perms.data)
        permassign.permissions = u' '.join(sorted(perms))
        db.session.commit()
        if client.user:
            flash("Permissions have been assigned to user %s" % form.user.pickername, "info")
        else:
            flash("Permissions have been assigned to team '%s'" % permassign.team.pickername, "info")
        return render_redirect(url_for('client_info', key=key), code=303)
    return render_form(form=form, title="Assign permissions", formid="perm_assign", submit="Assign permissions", ajax=True)


@app.route('/apps/<key>/perms/<userid>/edit', methods=['GET', 'POST'])
@requires_login
def permission_user_edit(key, userid):
    client = Client.query.filter_by(key=key).first_or_404()
    if not client.owner_is(g.user):
        abort(403)
    if client.user:
        user = User.query.filter_by(userid=userid).first_or_404()
        available_perms = Permission.query.filter(db.or_(
            Permission.allusers == True,
            Permission.user == g.user)).order_by('name').all()
        permassign = UserClientPermissions.query.filter_by(user=user, client=client).first_or_404()
    elif client.org:
        team = Team.query.filter_by(userid=userid).first_or_404()
        available_perms = Permission.query.filter(db.or_(
            Permission.allusers == True,
            Permission.org == client.org)).order_by('name').all()
        permassign = TeamClientPermissions.query.filter_by(team=team, client=client).first_or_404()
    form = PermissionEditForm()
    form.perms.choices = [(ap.name, u"%s – %s" % (ap.name, ap.title)) for ap in available_perms]
    if request.method == 'GET':
        if permassign:
            form.perms.data = permassign.permissions.split(u' ')
    if form.validate_on_submit():
        form.perms.data.sort()
        perms = u' '.join(form.perms.data)
        if not perms:
            db.session.delete(permassign)
        else:
            permassign.permissions = perms
        db.session.commit()
        if perms:
            if client.user:
                flash("Permissions have been updated for user %s" % user.pickername, "info")
            else:
                flash("Permissions have been updated for team '%s'" % team.title, "info")
        else:
            if client.user:
                flash("All permissions have been revoked for user %s" % user.pickername, "info")
            else:
                flash("All permissions have been revoked for team '%s'" % team.title, "info")
        return render_redirect(url_for('client_info', key=key), code=303)
    return render_form(form=form, title="Edit permissions", formid="perm_edit", submit="Save changes", ajax=True)


@app.route('/apps/<key>/perms/<userid>/delete', methods=['GET', 'POST'])
@requires_login
def permission_user_delete(key, userid):
    client = Client.query.filter_by(key=key).first_or_404()
    if not client.owner_is(g.user):
        abort(403)
    if client.user:
        user = User.query.filter_by(userid=userid).first_or_404()
        permassign = UserClientPermissions.query.filter_by(user=user, client=client).first_or_404()
        return render_delete_sqla(permassign, db, title="Confirm delete", message="Remove all permissions assigned to user %s for app '%s'?" % (
            (user.pickername), client.title),
            success="You have revoked permisions for user %s" % user.pickername,
            next=url_for('client_info', key=client.key))
    else:
        team = Team.query.filter_by(userid=userid).first_or_404()
        permassign = TeamClientPermissions.query.filter_by(team=team, client=client).first_or_404()
        return render_delete_sqla(permassign, db, title="Confirm delete", message="Remove all permissions assigned to team '%s' for app '%s'?" % (
            (team.title), client.title),
            success="You have revoked permisions for team '%s'" % team.title,
            next=url_for('client_info', key=client.key))


# --- Routes: client app resources --------------------------------------------

@app.route('/apps/<key>/resources/new', methods=['GET', 'POST'])
@requires_login
def resource_new(key):
    client = Client.query.filter_by(key=key).first_or_404()
    if not client.owner_is(g.user):
        abort(403)
    form = ResourceForm()
    form.edit_id = None
    if form.validate_on_submit():
        resource = Resource(client=client)
        form.populate_obj(resource)
        db.session.add(resource)
        db.session.commit()
        flash("Your new resource has been saved", "info")
        return render_redirect(url_for('client_info', key=key), code=303)
    return render_form(form=form, title="Define a resource", formid="resource_new", submit="Define resource", ajax=True)


@app.route('/apps/<key>/resources/<int:idr>/edit', methods=['GET', 'POST'])
@requires_login
def resource_edit(key, idr):
    client = Client.query.filter_by(key=key).first_or_404()
    if not client.owner_is(g.user):
        abort(403)
    resource = Resource.query.get_or_404(idr)
    if resource.client != client:
        abort(403)
    form = ResourceForm()
    form.edit_id = idr
    if request.method == 'GET':
        form.name.data = resource.name
        form.title.data = resource.title
        form.description.data = resource.description
        form.siteresource.data = resource.siteresource
    if form.validate_on_submit():
        form.populate_obj(resource)
        db.session.commit()
        flash("Your resource has been edited", "info")
        return render_redirect(url_for('client_info', key=key), code=303)
    return render_form(form=form, title="Edit resource", formid="resource_edit", submit="Save changes", ajax=True)


@app.route('/apps/<key>/resources/<int:idr>/delete', methods=['GET', 'POST'])
@requires_login
def resource_delete(key, idr):
    client = Client.query.filter_by(key=key).first_or_404()
    if not client.owner_is(g.user):
        abort(403)
    resource = Resource.query.get_or_404(idr)
    if resource.client != client:
        abort(403)
    return render_delete_sqla(resource, db, title="Confirm delete", message="Delete resource '%s' from app '%s'?" % (
        resource.title, client.title),
        success="You have deleted resource '%s' on app '%s'" % (resource.title, client.title),
        next=url_for('client_info', key=client.key))


# --- Routes: resource actions ------------------------------------------------

@app.route('/apps/<key>/resources/<int:idr>/actions/new', methods=['GET', 'POST'])
@requires_login
def resource_action_new(key, idr):
    client = Client.query.filter_by(key=key).first_or_404()
    if not client.owner_is(g.user):
        abort(403)
    resource = Resource.query.get_or_404(idr)
    if resource.client != client:
        abort(403)
    form = ResourceActionForm()
    form.edit_id = None
    form.edit_resource = resource
    if form.validate_on_submit():
        action = ResourceAction(resource=resource)
        form.populate_obj(action)
        db.session.add(action)
        db.session.commit()
        flash("Your new action has been saved", "info")
        return render_redirect(url_for('client_info', key=key), code=303)
    return render_form(form=form, title="Define an action", formid="action_new", submit="Define action", ajax=True)


@app.route('/apps/<key>/resources/<int:idr>/actions/<int:ida>/edit', methods=['GET', 'POST'])
@requires_login
def resource_action_edit(key, idr, ida):
    client = Client.query.filter_by(key=key).first_or_404()
    if not client.owner_is(g.user):
        abort(403)
    resource = Resource.query.get_or_404(idr)
    if resource.client != client:
        abort(404)
    action = ResourceAction.query.get_or_404(ida)
    if action.resource != resource:
        abort(404)
    form = ResourceActionForm()
    form.edit_id = ida
    form.edit_resource = resource
    if request.method == 'GET':
        form.name.data = action.name
        form.title.data = action.title
        form.description.data = action.description
    if form.validate_on_submit():
        form.populate_obj(action)
        db.session.commit()
        flash("Your action has been edited", "info")
        return render_redirect(url_for('client_info', key=key), code=303)
    return render_form(form=form, title="Edit action", formid="action_edit", submit="Save changes", ajax=True)


@app.route('/apps/<key>/resources/<int:idr>/actions/<int:ida>/delete', methods=['GET', 'POST'])
@requires_login
def resource_action_delete(key, idr, ida):
    client = Client.query.filter_by(key=key).first_or_404()
    if not client.owner_is(g.user):
        abort(403)
    resource = Resource.query.get_or_404(idr)
    if resource.client != client:
        abort(403)
    action = ResourceAction.query.get_or_404(ida)
    if action.resource != resource:
        abort(403)
    return render_delete_sqla(action, db, title="Confirm delete",
        message="Delete action '%s' from resource '%s' of app '%s'?" % (
        action.title, resource.title, client.title),
        success="You have deleted action '%s' on resource '%s' of app '%s'" % (action.title, resource.title, client.title),
        next=url_for('client_info', key=client.key))


# --- Routes: client team access ----------------------------------------------

@app.route('/apps/<key>/teams', methods=['GET', 'POST'])
@requires_login
def client_team_access(key):
    client = Client.query.filter_by(key=key).first_or_404()
    form = ClientTeamAccessForm()
    user_orgs = g.user.organizations_owned()
    form.organizations.choices = [(org.userid, org.title) for org in user_orgs]
    org_selected = [org.userid for org in user_orgs if client in org.clients_with_team_access()]
    if request.method == 'GET':
        form.organizations.data = org_selected
    if form.validate_on_submit():
        org_del = Organization.query.filter(Organization.userid.in_(
            set(org_selected) - set(form.organizations.data))).all()
        org_add = Organization.query.filter(Organization.userid.in_(
            set(form.organizations.data) - set(org_selected))).all()
        cta_del = ClientTeamAccess.query.filter_by(client=client).filter(
            ClientTeamAccess.org_id.in_([org.id for org in org_del])).all()
        for cta in cta_del:
            db.session.delete(cta)
        for org in org_add:
            cta = ClientTeamAccess(org=org, client=client, access_level=CLIENT_TEAM_ACCESS.ALL)
            db.session.add(cta)
        db.session.commit()
        flash("You have assigned access to teams in your organizations for this app.", "info")
        return render_redirect(url_for('client_info', key=key), code=303)
    return render_form(form=form, title="Select organizations", submit="Save", ajax=True)
