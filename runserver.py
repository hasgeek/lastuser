#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
reload(sys)
sys.setdefaultencoding('utf-8')

from os import environ
environ['LASTUSER_ENV'] = 'dev'

from lastuserapp import app
from lastuserapp.models import db

db.create_all()
app.run('0.0.0.0', port=7000, debug=True)
