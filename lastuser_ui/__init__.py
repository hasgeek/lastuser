# -*- coding: utf-8 -*-

from flask import Blueprint
from flask_assets import Bundle

lastuser_ui = Blueprint('lastuser_ui', __name__,
    static_folder='static',
    static_url_path='/static/ui',
    template_folder='templates')

lastuser_ui_css = Bundle('lastuser_ui/css/app.css')


from . import forms, views  # NOQA
