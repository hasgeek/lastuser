# -*- coding: utf-8 -*-

import unittest
from lastuserapp import app, db
from .fixtures import Fixtures


class TestDatabaseFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """
        Initialize a test DB and call to make fixtures.
        """
        cls.app = app
        db.create_all()
        cls.fixtures = Fixtures()
        cls.fixtures.make_fixtures()
        cls.fixtures.test_client = app.test_client()

    @classmethod
    def tearDownClass(cls):
        """
        Remove test session and tables.
        """
        db.drop_all()
        db.session.remove()

    def tearDown(self):
        db.session.rollback()
