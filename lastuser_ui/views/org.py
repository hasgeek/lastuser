# -*- coding: utf-8 -*-

from flask import g, current_app, render_template, url_for, abort, redirect, make_response, request
from baseframe.forms import render_form, render_redirect, render_delete_sqla
from coaster.views import load_model, load_models

from lastuser_core.models import db, Organization, Team, User
from lastuser_oauth.views.helpers import requires_login
from .. import lastuser_ui
from ..forms.org import OrganizationForm, TeamForm

# --- Routes: Organizations ---------------------------------------------------


@lastuser_ui.route('/organizations')
@requires_login
def org_list():
    return render_template('org_list.html', organizations=g.user.organizations_owned())


@lastuser_ui.route('/organizations/new', methods=['GET', 'POST'])
@requires_login
def org_new():
    form = OrganizationForm()
    form.name.description = current_app.config.get('ORG_NAME_REASON')
    form.title.description = current_app.config.get('ORG_TITLE_REASON')
    form.description.description = current_app.config.get('ORG_DESCRIPTION_REASON')
    if form.validate_on_submit():
        org = Organization()
        form.populate_obj(org)
        org.owners.users.append(g.user)
        db.session.add(org)
        db.session.commit()
        return render_redirect(url_for('.org_info', name=org.name), code=303)
    return render_form(form=form, title="New Organization", formid="org_new", submit="Create", ajax=False)


@lastuser_ui.route('/organizations/<name>')
@requires_login
@load_model(Organization, {'name': 'name'}, 'org', permission='view')
def org_info(org):
    return render_template('org_info.html', org=org)


@lastuser_ui.route('/organizations/<name>/edit', methods=['GET', 'POST'])
@requires_login
@load_model(Organization, {'name': 'name'}, 'org', permission='edit')
def org_edit(org):
    form = OrganizationForm(obj=org)
    form.name.description = current_app.config.get('ORG_NAME_REASON')
    form.title.description = current_app.config.get('ORG_TITLE_REASON')
    form.description.description = current_app.config.get('ORG_DESCRIPTION_REASON')
    if form.validate_on_submit():
        form.populate_obj(org)
        db.session.commit()
        return render_redirect(url_for('.org_info', name=org.name), code=303)
    return render_form(form=form, title="New Organization", formid="org_edit", submit="Save", ajax=False)


@lastuser_ui.route('/organizations/<name>/delete', methods=['GET', 'POST'])
@requires_login
@load_model(Organization, {'name': 'name'}, 'org', permission='delete')
def org_delete(org):
    return render_delete_sqla(org, db, title="Confirm delete", message="Delete organization '%s'? " % org.title,
        success="You have deleted organization '%s' and all its associated teams." % org.title,
        next=url_for('.org_list'))


@lastuser_ui.route('/organizations/<name>/teams')
@requires_login
@load_model(Organization, {'name': 'name'}, 'org', permission='view-teams')
def team_list(org):
    # There's no separate teams page at the moment
    return redirect(url_for('.org_info', name=org.name))


@lastuser_ui.route('/organizations/<name>/teams/new', methods=['GET', 'POST'])
@requires_login
@load_model(Organization, {'name': 'name'}, 'org', permission='new-team')
def team_new(org):
    form = TeamForm()
    if form.validate_on_submit():
        team = Team(org=org)
        team.title = form.title.data
        if form.users.data:
            team.users = User.query.filter(User.userid.in_(form.users.data)).all()
        db.session.add(team)
        db.session.commit()
        return render_redirect(url_for('.org_info', name=org.name), code=303)
    return make_response(render_template('edit_team.html', form=form, title=u"Create new team",
        formid='team_new', submit="Create"))


@lastuser_ui.route('/organizations/<name>/teams/<userid>', methods=['GET', 'POST'])
@requires_login
@load_models(
    (Organization, {'name': 'name'}, 'org'),
    (Team, {'org': 'org', 'userid': 'userid'}, 'team'),
    permission='edit'
    )
def team_edit(org, team):
    form = TeamForm(obj=team)
    if request.method == 'GET':
        form.users.data = [u.userid for u in team.users]
    if form.validate_on_submit():
        team.title = form.title.data
        print form.users.data
        print "\n" * 20
        if form.users.data:
            team.users = User.query.filter(User.userid.in_(form.users.data)).all()
        db.session.commit()
        return render_redirect(url_for('.org_info', name=org.name), code=303)
    return make_response(render_template('edit_team.html', form=form, title=u"Edit team: %s" % team.title, formid='team_edit', submit="Save", ajax=False))


@lastuser_ui.route('/organizations/<name>/teams/<userid>/delete', methods=['GET', 'POST'])
@requires_login
@load_models(
    (Organization, {'name': 'name'}, 'org'),
    (Team, {'org': 'org', 'userid': 'userid'}, 'team'),
    permission='delete'
    )
def team_delete(org, team):
    if team == org.owners:
        abort(403)
    return render_delete_sqla(team, db, title=u"Confirm delete", message=u"Delete team '%s'?" % team.title,
        success=u"You have deleted team '%s' from organization '%s'." % (team.title, org.title),
        next=url_for('.org_info', name=org.name))
