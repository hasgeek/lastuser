# -*- coding: utf-8 -*-

from lastuserapp import db
import lastuser_core.models as models
from .test_db import TestDatabaseFixture


class TestSMS(TestDatabaseFixture):
    def setUp(self):
        super(TestSMS, self).setUp()
        
    def test_transaction_id(self):
        val = u"1" * 40
        msg = models.SMSMessage.find_by_transaction_id(val)
        self.assertEquals(msg.transaction_id, val)


class TestClient(TestDatabaseFixture):
    def setUp(self):
        super(TestClient, self).setUp()
        self.user = models.User.find(username=u"user1")

    def test_get_all_clients(self):
        clients = models.Client.get_all_clients(user=self.user)
        self.assertTrue(len(clients) == 1)

    def test_get_all_lastuser_clients(self):
        self.assertTrue(len(models.Client.get_all_lastuser_clients()) == 1)


class TestUserClientPermissions(TestDatabaseFixture):
    def setUp(self):
        super(TestUserClientPermissions, self).setUp()
        self.user = models.User.find(username=u"user1")
        self.create_fixtures()

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

class TestTeamClientPermissions(TestDatabaseFixture):
    pass
