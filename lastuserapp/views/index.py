# -*- coding: utf-8 -*-

from flask import redirect, url_for, render_template

from lastuserapp import app


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/favicon.ico')
def favicon():
    return redirect(url_for('static', filename='img/favicon.ico'), code=301)


@app.route('/robots.txt')
def robots():
    return Response("Disallow: /auth/*\n"
                    "Disallow: /token/*\n"
                    "",
                    content_type = 'text/plain; charset=utf-8')
