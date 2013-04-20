#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
reload(sys)
sys.setdefaultencoding('utf-8')

from lastuserapp import app, init_for
from lastuser_core.models import db

init_for('dev')
db.create_all()
app.run('0.0.0.0', port=7000, debug=True)
