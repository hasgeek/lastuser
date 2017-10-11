# -*- coding: utf-8 -*-

from flask import render_template

from .. import lastuser_ui


@lastuser_ui.route('/')
def index():
    return render_template('index.html.jinja2')
