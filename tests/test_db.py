# -*- coding: utf-8 -*-

import unittest
from lastuserapp import app, db, init_for
from .fixtures import make_fixtures

class LastuserTest(unittest.TestCase):
    def setUp(self):
        with app.test_request_context():
            init_for('testing')
            app.config['TESTING'] = True
            db.create_all()
            self.db = db
            make_fixtures()

    def test_noop(self):
        pass

    def tearDown(self):
        self.db.drop_all()