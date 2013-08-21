# -*- coding: utf-8 -*-

import unittest
from lastuserapp import app, db, init_for
import lastuser_core.models as models
from .test_db import TestDatabaseFixture


"""class TestSMS(TestDatabaseFixture):
    def setUp(self):
        super(TestSMS, self).setUp()
        print "TestSMSModel - setup"
        
    def test_transaction_id(self):
        val = '1' * 40
        msg = models.SMSMessage.find_by_transaction_id('1' * 40)
        self.assetEquals(msg.transaction_id, val)

    def tearDown(self):
        super(TestSMS, self).tearDown()


class TestClient(TestDatabaseFixture):
    def setUp(self):
        super(TestClient, self).setUp()
        self.user = models.User.find(username=u"user1")
        print "TestClientModel - setup"

    def test_get_all_clients(self):
        print "all clients"
        clients = models.Client.get_all_clients(user=self.user)
        self.assertTrue(len(clients) == 1)
        print "exit all clients"

    def test_get_all_lastuser_clients(self):
        print "all lastuser"
        self.assertTrue(len(models.Client.get_all_lastuser_clients()) == 1)

    def tearDown(self):
        super(TestClient, self).tearDown()
"""
class TestUserClientPermissions(TestDatabaseFixture):
    def setUp(self):
        super(TestUserClientPermissions, self).setUp()
        self.user = models.User.find(username=u"user1")
        self.create_fixtures()
        print "TestUserClientPermissionsModel - setup"

    def create_fixtures(self):
        # Add permission to the client
        client = models.Client.find(user=self.user)
        permission = models.UserClientPermissions(user=self.user, client=client)
        permission.permissions = u"admin"
        db.session.add(client)
        db.session.commit()

    def test_get_all_user_permissions(self):
        client = models.Client.find(user=self.user)
        perms = models.UserClientPermissions.find_all(client=client)
        self.assertEquals(len(perms), 1)

    def tearDown(self):
        super(TestUserClientPermissions, self).tearDown()
