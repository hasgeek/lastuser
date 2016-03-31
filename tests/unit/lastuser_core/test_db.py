# -*- coding: utf-8 -*-

import unittest
from lastuserapp import app, db, init_for
from .fixtures import Fixtures


class TestDatabaseFixture(unittest.TestCase):
    @classmethod
    def setUpClass(self):
        """
        Initialize a test DB and call to make fixtures.
        """
        init_for('testing')
        self.app = app
        db.create_all()
        self.fixtures = Fixtures()
        self.fixtures.make_fixtures()
        self.fixtures.test_client = app.test_client()

    @classmethod
    def tearDownClass(self):
        """
        Remove test session and tables.
        """
        db.session.rollback()
        db.drop_all()
        db.session.remove()
