# -*- coding: utf-8 -*-

from flask import Blueprint

lastuser_ui = Blueprint(
    'lastuser_ui',
    __name__,
    static_folder='static',
    static_url_path='/static/ui',
    template_folder='templates',
)

from . import forms, views  # NOQA # isort:skip
