# -*- coding: utf-8 -*-

from flask import g, request, render_template, redirect, url_for, flash, abort

from lastuserapp import app
from lastuserapp.views import requires_login, render_form, render_message, render_redirect, render_delete
from lastuserapp.models import db, User, Client, Permission, UserClientPermissions, Resource, ResourceAction
from lastuserapp.forms import (RegisterClientForm, PermissionForm, UserPermissionAssignForm,
    UserPermissionEditForm, ResourceForm, ResourceActionForm)

# --- Routes: client apps -----------------------------------------------------

@app.route('/apps')
def client_list():
    if g.user:
        return render_template('client_list.html', clients=Client.query.filter_by(user_id=g.user.id).order_by('title').all())
    else:
        # TODO: Show better UI for non-logged in users
        return render_template('client_list.html', clients=[])

@app.route('/apps/all')
def client_list_all():
    return render_template('client_list.html', clients=Client.query.order_by('title').all())


@app.route('/apps/new', methods=['GET', 'POST'])
@requires_login
def client_new():
    form = RegisterClientForm()

    if form.validate_on_submit():
        client = Client()
        form.populate_obj(client)
        client.user = g.user
        client.trusted = False
        db.session.add(client)
        db.session.commit()
        return render_redirect(url_for('client_info', key=client.key), code=303)

    return render_form(form=form, title="Register a new client application",
        formid="client_new", submit="Register application", ajax=True)


@app.route('/apps/<key>')
def client_info(key):
    client = Client.query.filter_by(key=key).first()
    if not client:
        abort(404)
    permassignments = UserClientPermissions.query.filter_by(client=client).all()
    resources = Resource.query.filter_by(client=client).order_by('name').all()
    return render_template('client_info.html', client=client,
        permassignments=permassignments,
        resources=resources)


@app.route('/apps/<key>/edit', methods=['GET', 'POST'])
@requires_login
def client_edit(key):
    client = Client.query.filter_by(key=key).first()
    if not client:
        abort(404)
    if client.user != g.user:
        abort(403)
    form = RegisterClientForm()
    if request.method == 'GET':
        form.title.data = client.title
        form.description.data = client.description
        form.owner.data = client.owner
        form.website.data = client.website
        form.redirect_uri.data = client.redirect_uri
        form.notification_uri.data = client.notification_uri
        form.resource_uri.data = client.resource_uri
        form.allow_any_login.data = client.allow_any_login

    if form.validate_on_submit():
        form.populate_obj(client)
        db.session.commit()
        return render_redirect(url_for('client_info', key=client.key), code=303)

    return render_form(form=form, title="Edit application", formid="client_edit",
        submit="Save changes", ajax=True)

@app.route('/apps/<key>/delete', methods=['GET', 'POST'])
def client_delete(key):
    client = Client.query.filter_by(key=key).first()
    return render_delete(client, title="Confirm delete", message="Delete application '%s'? " % client.title,
        success="You have deleted application '%s' and all its associated permissions and resources" % client.title,
        next=url_for('client_list'))

# --- Routes: user permissions ------------------------------------------------

@app.route('/perms')
@requires_login
def permission_list():
    allperms = Permission.query.filter_by(allusers=True).order_by('name').all()
    userperms = Permission.query.filter_by(user=g.user).order_by('name').all()
    return render_template('permission_list.html', allperms=allperms, userperms=userperms)


@app.route('/perms/new', methods=['GET', 'POST'])
@requires_login
def permission_new():
    form = PermissionForm()
    if form.validate_on_submit():
        perm = Permission(user=g.user)
        form.populate_obj(perm)
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
    perm = Permission.query.get(id)
    if not perm:
        abort(404)
    form = PermissionForm()
    form.edit_id = id
    if request.method == 'GET':
        form.name.data = perm.name
        form.title.data = perm.title
        form.description.data = perm.description
    if form.validate_on_submit():
        form.populate_obj(perm)
        db.session.commit()
        flash("Your permission has been saved", "info")
        return render_redirect(url_for('permission_list'), code=303)
    return render_form(form=form, title="Edit permission", formid="perm_edit",
        submit="Save changes", ajax=True)


@app.route('/perms/<int:id>/delete', methods=['GET', 'POST'])
@requires_login
def permission_delete(id):
    perm = Permission.query.get(id)
    if not perm:
        abort(404)
    return render_delete(perm, title="Confirm delete", message="Delete permission %s?" % perm.name,
        success="Your permission has been deleted",
        next=url_for('permission_list'))

# --- Routes: client app permissions ------------------------------------------

@app.route('/apps/<key>/perms/new', methods=['GET', 'POST'])
@requires_login
def permission_user_new(key):
    client = Client.query.filter_by(key=key).first()
    if not client:
        abort(404)
    if client.user != g.user:
        abort(403)
    available_perms = Permission.query.filter(db.or_(Permission.allusers == True, Permission.user == g.user)).order_by('name').all()
    form = UserPermissionAssignForm()
    form.perms.choices = [(ap.name, u"%s – %s" % (ap.name, ap.title)) for ap in available_perms]
    if form.validate_on_submit():
        form.perms.data.sort()
        perms = u' '.join(form.perms.data)
        permassign = UserClientPermissions(user=form.user, client=client, permissions=perms)
        db.session.add(permassign)
        db.session.commit()
        flash("Permissions have been assigned to user %s" % form.user.displayname(), "info")
        return render_redirect(url_for('client_info', key=key), code=303)
    return render_form(form=form, title="Assign permissions", formid="perm_assign", submit="Assign permissions", ajax=True)


@app.route('/apps/<key>/perms/<userid>/edit', methods=['GET', 'POST'])
@requires_login
def permission_user_edit(key, userid):
    client = Client.query.filter_by(key=key).first()
    if not client:
        abort(404)
    if client.user != g.user:
        abort(403)
    user = User.query.filter_by(userid=userid).first()
    if not user:
        abort(404)
    available_perms = Permission.query.filter(Permission.allusers == True or Permission.user == g.user).order_by('name').all()
    permassign = UserClientPermissions.query.filter_by(user=user, client=client).first()
    form = UserPermissionEditForm()
    form.perms.choices = [(ap.name, u"%s – %s" % (ap.name, ap.title)) for ap in available_perms]
    if request.method == 'GET':
        if permassign:
            form.perms.data = permassign.permissions.split(u' ')
    if form.validate_on_submit():
        form.perms.data.sort()
        perms = u' '.join(form.perms.data)
        if not perms:
            # No permissions specified. Delete this assignment
            if permassign:
                db.session.delete(permassign)
        elif not permassign:
            permassign = UserClientPermissions(user=user, client=client)
            permassign.permissions = perms
            db.session.add(permassign)
        else:
            permassign.permissions = perms
        db.session.commit()
        if perms:
            flash("Permissions have been updated for user %s" % user.displayname(), "info")
        else:
            flash("All permissions have been revoked for user %s" % user.displayname(), "info")
        return render_redirect(url_for('client_info', key=key), code=303)
    return render_form(form=form, title="Edit permissions", formid="perm_edit", submit="Save changes", ajax=True)


@app.route('/apps/<key>/perms/<userid>/delete', methods=['GET', 'POST'])
@requires_login
def permission_user_delete(key, userid):
    client = Client.query.filter_by(key=key).first()
    if not client:
        abort(404)
    if client.user != g.user:
        abort(403)
    user = User.query.filter_by(userid=userid).first()
    if not user:
        abort(404)
    permassign = UserClientPermissions.query.filter_by(user=user, client=client).first()
    return render_delete(permassign, title="Confirm delete", message="Remove all permissions assigned to user '%s' for app '%s'?" % (
        (user.displayname()), client.title),
        success="You have revoked permisions for user '%s'" % user.displayname(),
        next=url_for('client_info', key=client.key))


# --- Routes: client app resources --------------------------------------------

@app.route('/apps/<key>/resources/new', methods=['GET', 'POST'])
@requires_login
def resource_new(key):
    client = Client.query.filter_by(key=key).first()
    if not client:
        abort(404)
    if client.user != g.user:
        abort(403)
    form = ResourceForm()
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
    client = Client.query.filter_by(key=key).first()
    if not client:
        abort(404)
    if client.user != g.user:
        abort(403)
    resource = Resource.query.get(idr)
    if not resource:
        abort(404)
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
    client = Client.query.filter_by(key=key).first()
    if not client:
        abort(404)
    if client.user != g.user:
        abort(403)
    resource = Resource.query.get(idr)
    return render_delete(resource, title="Confirm delete", message="Delete resource '%s' from app '%s'?" % (
        resource.title, client.title),
        success="You have deleted resource '%s' on app '%s'" % (resource.title, client.title),
        next=url_for('client_info', key=client.key))


# --- Routes: resource actions ------------------------------------------------

@app.route('/apps/<key>/resources/<int:idr>/actions/new', methods=['GET', 'POST'])
@requires_login
def resource_action_new(key, idr):
    client = Client.query.filter_by(key=key).first()
    if not client:
        abort(404)
    if client.user != g.user:
        abort(403)
    resource = Resource.query.get(idr)
    if not resource:
        abort(404)
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
    client = Client.query.filter_by(key=key).first()
    if not client:
        abort(404)
    if client.user != g.user:
        abort(403)
    resource = Resource.query.get(idr)
    if not resource:
        abort(404)
    action = ResourceAction.query.get(ida)
    if not action:
        abort(404)
    form = ResourceActionForm()
    form.edit_id = None
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
    client = Client.query.filter_by(key=key).first()
    if not client:
        abort(404)
    if client.user != g.user:
        abort(403)
    resource = Resource.query.get(idr)
    if not resource:
        abort(404)
    action = ResourceAction.query.get(ida)
    return render_delete(action, title="Confirm delete", message="Delete action '%s' from resource '%s' of app '%s'?" % (
        action.title, resource.title, client.title),
        success="You have deleted action '%s' on resource '%s' of app '%s'" % (action.title, resource.title, client.title),
        next=url_for('client_info', key=client.key))
