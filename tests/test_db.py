# -*- coding: utf-8 -*-

import unittest
from lastuserapp import app, db, init_for
from .fixtures import make_fixtures


class TestDatabaseFixture(unittest.TestCase):
    def setUp(self):
        init_for('testing')
        app.config['TESTING'] = True
        db.app = app
        db.create_all()
        self.db = db
        make_fixtures()

    def tearDown(self):
        # http://stackoverflow.com/questions/12014824/sql-alchemy-relationship-loader-leaves-a-lock-on-table
        self.db.session.commit()
        self.db.drop_all()
