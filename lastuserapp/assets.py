# -*- coding: utf-8 -*-

from flaskext.assets import Environment, Bundle
from lastuserapp import app

assets = Environment(app)

# --- Assets ------------------------------------------------------------------

js = Bundle('js/libs/jquery-1.5.1.min.js',
            'js/libs/jquery.form.js',
            'js/scripts.js',
            filters='jsmin', output='js/packed.js')

assets.register('js_all', js)
