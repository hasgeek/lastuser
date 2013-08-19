# -*- coding: utf-8 -*-

import unittest
from lastuserapp import app, db, init_for
from .fixtures import make_fixtures

class LastuserTest(unittest.TestCase):
    def setUp(self):
        init_for('testing')
        app.config['TESTING'] = True
        db.app = app
        db.create_all()
        self.db = db
        make_fixtures()

    def test_noop(self):
        pass

    def tearDown(self):
        self.db.drop_all()