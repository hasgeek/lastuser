# -*- coding: utf-8 -*-

from flask import abort, current_app, redirect, render_template, request, url_for

from baseframe import _
from baseframe.forms import render_delete_sqla, render_form, render_redirect

from coaster.auth import current_auth
from coaster.views import ModelView, UrlForView, requires_permission, route

from lastuser_core.models import Organization, Team, db
from lastuser_core.signals import org_data_changed, team_data_changed

from lastuser_oauth.views.helpers import requires_login

from .. import lastuser_ui
from ..forms.org import OrganizationForm, TeamForm


# --- Routes: Organizations ---------------------------------------------------


@route('/organizations')
class OrgView(UrlForView, ModelView):
    __decorators__ = [requires_login]
    model = Organization
    route_model_map = {'name': 'name'}  # Map <name> in URL to attribute `name`, for `url_for` automation

    def loader(self, name=None):
        if name:
            obj = Organization.get(name=name)
            if not obj:
                abort(404)
            return obj

    @route('')
    def index(self):
        return render_template('org_list.html.jinja2', organizations=current_auth.user.organizations_owned())

    @route('new', methods=['GET', 'POST'])
    def new(self):
        form = OrganizationForm()
        form.name.description = current_app.config.get('ORG_NAME_REASON')
        form.title.description = current_app.config.get('ORG_TITLE_REASON')
        if form.validate_on_submit():
            org = Organization()
            form.populate_obj(org)
            if current_auth.user not in org.owners.users:
                org.owners.users.append(current_auth.user)
            if current_auth.user not in org.members.users:
                org.members.users.append(current_auth.user)
            db.session.add(org)
            db.session.commit()
            org_data_changed.send(org, changes=['new'], user=current_auth.user)
            return render_redirect(org.url_for('view'), code=303)
        return render_form(form=form, title=_("New organization"), formid='org_new', submit=_("Create"), ajax=False)

    @route('<name>')
    @requires_permission('view')
    def view(self):
        return render_template('org_info.html.jinja2', org=self.obj)

    @route('<name>/edit', methods=['GET', 'POST'])
    @requires_permission('edit')
    def edit(self):
        form = OrganizationForm(obj=self.obj)
        form.name.description = current_app.config.get('ORG_NAME_REASON')
        form.title.description = current_app.config.get('ORG_TITLE_REASON')
        if form.validate_on_submit():
            form.populate_obj(self.obj)
            db.session.commit()
            org_data_changed.send(self.obj, changes=['edit'], user=current_auth.user)
            return render_redirect(self.obj.url_for('view'), code=303)
        return render_form(form=form, title=_("Edit organization"), formid='org_edit', submit=_("Save"), ajax=False)

    @route('<name>/delete', methods=['GET', 'POST'])
    @requires_permission('delete')
    def delete(self):
        if request.method == 'POST':
            # FIXME: Find a better way to do this
            org_data_changed.send(self.obj, changes=['delete'], user=current_auth.user)
        return render_delete_sqla(
            self.obj, db, title=_(u"Confirm delete"),
            message=_(u"Delete organization ‘{title}’? ").format(
                title=self.obj.title),
            success=_(u"You have deleted organization ‘{title}’ and all its associated teams").format(
                title=self.obj.title),
            next=url_for('.OrgView_index'))

    @route('<name>/teams')
    @requires_permission('view-teams')
    def teams(self):
        # There's no separate teams page at the moment
        return redirect(self.obj.url_for('view'))

    @route('<name>/teams/new', methods=['GET', 'POST'])
    @requires_permission('new-team')
    def new_team(self):
        form = TeamForm()
        if form.validate_on_submit():
            team = Team(org=self.obj)
            db.session.add(team)
            form.populate_obj(team)
            db.session.commit()
            team_data_changed.send(team, changes=['new'], user=current_auth.user)
            return render_redirect(self.obj.url_for('view'), code=303)
        return render_form(
            form=form, title=_(u"Create new team"),
            formid='new_team', submit=_("Create"))


OrgView.init_app(lastuser_ui)


@route('/organizations/<name>/teams/<buid>')
class TeamView(UrlForView, ModelView):
    __decorators__ = [requires_login]
    model = Team
    route_model_map = {  # Map <name> and <buid> in URLs to model attributes, for `url_for` automation
        'name': 'org.name',
        'buid': 'buid'
    }

    def loader(self, name, buid):
        obj = Team.get(buid=buid, with_parent=True)
        if not obj or obj.org.name != name:
            abort(404)
        return obj

    @route('', methods=['GET', 'POST'])
    @requires_permission('edit')
    def edit(self):
        form = TeamForm(obj=self.obj)
        if form.validate_on_submit():
            form.populate_obj(self.obj)
            db.session.commit()
            team_data_changed.send(self.obj, changes=['edit'], user=current_auth.user)
            return render_redirect(self.obj.org.url_for(), code=303)
        return render_form(
            form=form,
            title=_(u"Edit team: {title}").format(title=self.obj.title),
            formid='team_edit', submit=_("Save"), ajax=False)

    @route('delete', methods=['GET', 'POST'])
    @requires_permission('delete')
    def delete(self):
        if self.obj == self.obj.org.owners or self.obj == self.obj.org.members:
            abort(403)
        if request.method == 'POST':
            team_data_changed.send(self.obj, changes=['delete'], user=current_auth.user)
        return render_delete_sqla(
            self.obj, db,
            title=_(u"Confirm delete"),
            message=_(u"Delete team {title}?").format(title=self.obj.title),
            success=_(u"You have deleted team ‘{team}’ from organization ‘{org}’").format(
                team=self.obj.title, org=self.obj.org.title),
            next=self.obj.org.url_for())


TeamView.init_app(lastuser_ui)
