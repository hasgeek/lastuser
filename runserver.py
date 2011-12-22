#!/usr/bin/env python
# -*- coding: utf-8 -*-

from lastuserapp import app
from lastuserapp.models import db

if __name__=='__main__':
    db.create_all()
    app.run('0.0.0.0', port=7000, debug=True)
