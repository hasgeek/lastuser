# -*- coding: utf-8 -*-

from flask import g, render_template, url_for, abort, redirect
from baseframe.forms import render_form, render_redirect, render_delete_sqla

from lastuserapp import app
from lastuserapp.views.helpers import requires_login
from lastuserapp.forms.org import OrganizationForm, TeamForm
from lastuserapp.models import db, Organization, Team

# --- Routes: Organizations ---------------------------------------------------


@app.route('/organizations')
@requires_login
def org_list():
    return render_template('org_list.html', organizations=g.user.organizations_owned())


@app.route('/organizations/new', methods=['GET', 'POST'])
@requires_login
def org_new():
    form = OrganizationForm()
    form.edit_obj = None
    if form.validate_on_submit():
        org = Organization()
        form.populate_obj(org)
        org.owners.users.append(g.user)
        db.session.add(org)
        db.session.commit()
        return render_redirect(url_for('org_info', name=org.name), code=303)
    return render_form(form=form, title="New Organization", formid="org_new", submit="Create", ajax=False)


@app.route('/organizations/<name>')
@requires_login
def org_info(name):
    org = Organization.query.filter_by(name=name).first_or_404()
    if g.user not in org.owners.users:
        abort(403)
    return render_template('org_info.html', org=org)


@app.route('/organizations/<name>/edit', methods=['GET', 'POST'])
@requires_login
def org_edit(name):
    org = Organization.query.filter_by(name=name).first_or_404()
    if g.user not in org.owners.users:
        abort(403)
    form = OrganizationForm(obj=org)
    form.edit_obj = org
    if form.validate_on_submit():
        form.populate_obj(org)
        db.session.commit()
        return render_redirect(url_for('org_info', name=org.name), code=303)
    return render_form(form=form, title="New Organization", formid="org_edit", submit="Save", ajax=False)


@app.route('/organizations/<name>/delete', methods=['GET', 'POST'])
@requires_login
def org_delete(name):
    org = Organization.query.filter_by(name=name).first_or_404()
    if g.user not in org.owners.users:
        abort(403)
    return render_delete_sqla(org, db, title="Confirm delete", message="Delete organization '%s'? " % org.title,
        success="You have deleted organization '%s' and all its associated teams." % org.title,
        next=url_for('org_list'))


@app.route('/organizations/<name>/teams')
@requires_login
def team_list(name):
    org = Organization.query.filter_by(name=name).first_or_404()
    if g.user not in org.owners.users:
        abort(403)
    # There's no separate teams page at the moment
    return redirect(url_for('org_info', name=org.name))


@app.route('/organizations/<name>/teams/new', methods=['GET', 'POST'])
@requires_login
def team_new(name):
    org = Organization.query.filter_by(name=name).first_or_404()
    if g.user not in org.owners.users:
        abort(403)
    form = TeamForm()
    if form.validate_on_submit():
        team = Team(org=org)
        form.populate_obj(team)
        db.session.add(team)
        db.session.commit()
        return render_redirect(url_for('org_info', name=org.name), code=303)
    return render_form(form=form, title=u"Create new team", formid='team_new', submit="Create", ajax=False)


@app.route('/organizations/<name>/teams/<userid>', methods=['GET', 'POST'])
@requires_login
def team_edit(name, userid):
    org = Organization.query.filter_by(name=name).first_or_404()
    if g.user not in org.owners.users:
        abort(403)
    team = Team.query.filter_by(org=org, userid=userid).first_or_404()
    form = TeamForm(obj=team)
    form.edit_obj = team
    if form.validate_on_submit():
        form.populate_obj(team)
        db.session.commit()
        return render_redirect(url_for('org_info', name=org.name), code=303)
    return render_form(form=form, title=u"Edit team: %s" % team.title, formid='team_edit', submit="Save", ajax=False)


@app.route('/organizations/<name>/teams/<userid>/delete', methods=['GET', 'POST'])
@requires_login
def team_delete(name, userid):
    org = Organization.query.filter_by(name=name).first_or_404()
    if g.user not in org.owners.users:
        abort(403)
    team = Team.query.filter_by(org=org, userid=userid).first_or_404()
    if team == org.owners:
        abort(403)
    return render_delete_sqla(team, db, title=u"Confirm delete", message=u"Delete team '%s'?" % team.title,
        success=u"You have deleted team '%s' from organization '%s'." % (team.title, org.title),
        next=url_for('org_info', name=org.name))
