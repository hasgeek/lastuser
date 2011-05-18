# -*- coding: utf-8 -*-

from flask import g, request, render_template, redirect, url_for

from lastuserapp import app
from lastuserapp.views import requires_login
from lastuserapp.models import db, Client
from lastuserapp.forms import RegisterClientForm


@app.route('/apps')
def client_list():
    return render_template('client_list.html', clients=Client.query.all())


@app.route('/apps/new', methods=['GET', 'POST'])
@requires_login
def client_new():
    form = RegisterClientForm()
    if request.method == 'GET':
        # First load of page. Set defaults.
        form.readonly.data = True
        form.allow_any_login.data = True

    if form.validate_on_submit():
        client = Client()
        form.populate_obj(client)
        client.user = g.user
        client.trusted = False
        db.session.add(client)
        db.session.commit()
        return redirect(url_for('client_info', key=client.key), code=303)
    return render_template('client_edit.html', form=form)


@app.route('/apps/<key>')
def client_info(key):
    client = Client.query.filter_by(key=key).first()
    if not client:
        abort(404)
    return render_template('client_info.html', client=client)

@app.route('/apps/<key>/edit', methods=['GET', 'POST'])
def client_edit(key):
    client = Client.query.filter_by(key=key).first()
    if not client:
        abort(404)
    if client.user != g.user:
        abort(403)
    form = RegisterClientForm()
    form.title.data = client.title
    form.description.data = client.description
    form.owner.data = client.owner
    form.website.data = client.website
    form.redirect_uri.data = client.redirect_uri
    form.service_uri.data = client.service_uri
    form.readonly.data = client.readonly
    if form.validate_on_submit():
        form.populate_obj(client)
        db.session.commit()
        return redirect(url_for('client_info', key=client.key), code=303)
    return render_template('client_edit.html', form=form, edit=True)
