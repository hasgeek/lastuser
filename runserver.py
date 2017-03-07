#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
reload(sys)
sys.setdefaultencoding('utf-8')

from lastuserapp import app, init_for

init_for('dev')
app.run('0.0.0.0', 7000, debug=True)
