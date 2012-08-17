# -*- coding: utf-8 -*-

from flask import render_template, Response

from lastuserapp import app


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/robots.txt')
def robots():
    return Response("Disallow: /auth/*\n"
                    "Disallow: /token/*\n"
                    "",
                    content_type='text/plain; charset=utf-8')
