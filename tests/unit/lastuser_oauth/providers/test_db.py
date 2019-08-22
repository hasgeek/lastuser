# -*- coding: utf-8 -*-

import unittest

from lastuserapp import app, db

from .fixtures import Fixtures


class TestDatabaseFixture(unittest.TestCase):
    def setUp(self):
        """
        Initialize a test DB and call to make fixtures.

        """
        self.ctx = app.test_request_context()
        self.ctx.push()
        self.app = app
        db.create_all()
        self.client = app.test_client()
        self.fixtures = Fixtures()
        self.fixtures.make_fixtures()

    def tearDown(self):
        """
        Remove test session and tables.
        """
        db.session.rollback()
        db.drop_all()
        db.session.remove()
        self.ctx.pop()
