# -*- coding: utf-8 -*-

from flask import current_app, render_template, url_for, abort, redirect, request
from baseframe import _
from baseframe.forms import render_form, render_redirect, render_delete_sqla
from coaster.auth import current_auth
from coaster.views import load_model, load_models

from lastuser_core.models import db, Organization, Team
from lastuser_core.signals import org_data_changed, team_data_changed
from lastuser_oauth.views.helpers import requires_login
from .. import lastuser_ui
from ..forms.org import OrganizationForm, TeamForm


# --- Routes: Organizations ---------------------------------------------------

@lastuser_ui.route('/organizations')
@requires_login
def org_list():
    return render_template('org_list.html.jinja2', organizations=current_auth.user.organizations_owned())


@lastuser_ui.route('/organizations/new', methods=['GET', 'POST'])
@requires_login
def org_new():
    form = OrganizationForm()
    form.name.description = current_app.config.get('ORG_NAME_REASON')
    form.title.description = current_app.config.get('ORG_TITLE_REASON')
    if form.validate_on_submit():
        org = Organization()
        form.populate_obj(org)
        if current_auth.is_authenticated not in org.owners.users:
            org.owners.users.append(current_auth.user)
        if current_auth.is_authenticated not in org.members.users:
            org.members.users.append(current_auth.user)
        db.session.add(org)
        db.session.commit()
        org_data_changed.send(org, changes=['new'], user=current_auth.user)
        return render_redirect(url_for('.org_info', name=org.name), code=303)
    return render_form(form=form, title=_("New organization"), formid='org_new', submit=_("Create"), ajax=False)


@lastuser_ui.route('/organizations/<name>')
@requires_login
@load_model(Organization, {'name': 'name'}, 'org', permission='view')
def org_info(org):
    return render_template('org_info.html.jinja2', org=org)


@lastuser_ui.route('/organizations/<name>/edit', methods=['GET', 'POST'])
@requires_login
@load_model(Organization, {'name': 'name'}, 'org', permission='edit')
def org_edit(org):
    form = OrganizationForm(obj=org)
    form.name.description = current_app.config.get('ORG_NAME_REASON')
    form.title.description = current_app.config.get('ORG_TITLE_REASON')
    if form.validate_on_submit():
        form.populate_obj(org)
        db.session.commit()
        org_data_changed.send(org, changes=['edit'], user=current_auth.user)
        return render_redirect(url_for('.org_info', name=org.name), code=303)
    return render_form(form=form, title=_("Edit organization"), formid='org_edit', submit=_("Save"), ajax=False)


@lastuser_ui.route('/organizations/<name>/delete', methods=['GET', 'POST'])
@requires_login
@load_model(Organization, {'name': 'name'}, 'org', permission='delete')
def org_delete(org):
    if request.method == 'POST':
        # FIXME: Find a better way to do this
        org_data_changed.send(org, changes=['delete'], user=current_auth.user)
    return render_delete_sqla(org, db, title=_(u"Confirm delete"),
        message=_(u"Delete organization ‘{title}’? ").format(
            title=org.title),
        success=_(u"You have deleted organization ‘{title}’ and all its associated teams").format(title=org.title),
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
        db.session.add(team)
        form.populate_obj(team)
        db.session.commit()
        team_data_changed.send(team, changes=['new'], user=current_auth.user)
        return render_redirect(url_for('.org_info', name=org.name), code=303)
    return render_form(form=form, title=_(u"Create new team"),
        formid='team_new', submit=_("Create"))


@lastuser_ui.route('/organizations/<name>/teams/<buid>', methods=['GET', 'POST'])
@requires_login
@load_models(
    (Organization, {'name': 'name'}, 'org'),
    (Team, {'org': 'org', 'buid': 'buid'}, 'team'),
    permission='edit'
    )
def team_edit(org, team):
    form = TeamForm(obj=team)
    if form.validate_on_submit():
        form.populate_obj(team)
        db.session.commit()
        team_data_changed.send(team, changes=['edit'], user=current_auth.user)
        return render_redirect(url_for('.org_info', name=org.name), code=303)
    return render_form(form=form,
        title=_(u"Edit team: {title}").format(title=team.title),
        formid='team_edit', submit=_("Save"), ajax=False)


@lastuser_ui.route('/organizations/<name>/teams/<buid>/delete', methods=['GET', 'POST'])
@requires_login
@load_models(
    (Organization, {'name': 'name'}, 'org'),
    (Team, {'org': 'org', 'buid': 'buid'}, 'team'),
    permission='delete'
    )
def team_delete(org, team):
    if team == org.owners or team == org.members:
        abort(403)
    if request.method == 'POST':
        team_data_changed.send(team, changes=['delete'], user=current_auth.user)
    return render_delete_sqla(team, db, title=_(u"Confirm delete"), message=_(u"Delete team {title}?").format(title=team.title),
        success=_(u"You have deleted team ‘{team}’ from organization ‘{org}’").format(team=team.title, org=org.title),
        next=url_for('.org_info', name=org.name))
