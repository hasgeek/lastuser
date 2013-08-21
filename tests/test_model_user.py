# -*- coding: utf-8 -*-

import unittest
from lastuserapp import app, db, init_for
import lastuser_core.models as models
from .test_db import TestDatabaseFixture


class TestSMSModel(TestDatabaseFixture):
    def setUp(self):
        super(TestSMSModel, self).setUp()
        
    def test_transaction_id(self):
        msg = models.SMSMessage.find_by_transaction_id('1' * 40)
        self.assetTrue(msg != None)

    def tearDown(self):
        super(TestClientModel, self).tearDown()


class TestClientModel(TestDatabaseFixture):
    def setUp(self):
        super(TestClientModel, self).setUp()
        self.user = models.User.find(username=u"user1")
        self.create_fixtures()

    def create_fixtures(self):
        # Add permission to the client
        client = models.Client.find(user=self.user)
        permission = models.UserClientPermissions(user=self.user, client=client)
        permission.permissions = u"admin"
        db.session.add(client)
        db.session.commit()
        
    def test_get_all_clients(self):
        clients = models.Client.get_all_clients(user=self.user)
        self.assertTrue(len(clients) == 1)

    def test_get_all_lastuser_clients(self):
        self.assertTrue(len(models.Client.get_all_lastuser_clients()) == 1)

    def tearDown(self):
        super(TestClientModel, self).tearDown()
