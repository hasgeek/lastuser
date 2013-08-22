# -*- coding: utf-8 -*-

from lastuserapp import db
import lastuser_core.models as models
from .test_db import TestDatabaseFixture


class TestClient(TestDatabaseFixture):
    def setUp(self):
        super(TestClient, self).setUp()
        self.user = models.User.find(username=u"user1")

    def test_get_all_clients(self):
        clients = models.Client.get_all_clients(user=self.user)
        self.assertIs(len(clients), 1)

    def test_get_all_lastuser_clients(self):
        self.assertIs(len(models.Client.get_all_lastuser_clients()), 1)


class TestUserClientPermissions(TestDatabaseFixture):
    def setUp(self):
        super(TestUserClientPermissions, self).setUp()
        self.user = models.User.find(username=u"user1")
        self.create_fixtures()

    def create_fixtures(self):
        # Add permission to the client
        client = models.Client.find(user=self.user)
        self.permission = models.UserClientPermissions(user=self.user, client=client)
        self.permission.permissions = u"admin"
        db.session.add(self.permission)
        db.session.commit()

    def test_find_all(self):
        client = models.Client.find(user=self.user)
        perms = models.UserClientPermissions.find_all(client=client, user=self.user)
        self.assertIs(perms[0], self.permission)
        self.assertIs(models.UserClientPermissions.find(client=client, user=self.user, first_or_404=True), self.permission)


class TestTeamClientPermissions(TestDatabaseFixture):
    def setUp(self):
        super(TestTeamClientPermissions, self).setUp()
        self.user = models.User.find(username=u"user1")
        self.client = models.Client.find(user=self.user)
        self.create_fixtures()

    def create_fixtures(self):
        self.org = models.Organization(title=u"test", name=u"Test")
        self.org.owners.users.append(self.user)
        db.session.add(self.org)
        self.team = models.Team(userid=self.user.userid, title=u"developers", org=self.org)
        db.session.add(self.team)
        self.team_client_permission = models.TeamClientPermissions(team=self.team, client=self.client, access_permissions=u"admin")
        db.session.add(self.team_client_permission)
        db.session.commit()

    def test_find_all(self):
        perms = models.TeamClientPermissions.find_all(client=self.client)
        self.assertIs(perms[0], self.team_client_permission)
        perms = models.TeamClientPermissions.find_all(client=self.client, team=self.team)
        self.assertIs(perms[0], self.team_client_permission)
        self.assertIs(models.TeamClientPermissions.find(client=self.client, first_or_404=True), self.team_client_permission)


class TestResource(TestDatabaseFixture):
    def setUp(self):
        super(TestResource, self).setUp()
        self.user = models.User.find(username=u"user1")
        self.client = models.Client.find(user=self.user)
        self.create_fixtures()

    def create_fixtures(self):
        resource = models.Resource(name=u"resource", title=u"Resource", client=self.client)
        db.session.add(resource)
        db.session.commit()

    def test_find_all(self):
        resources = models.Resource.find_all(client=self.client, order_by=u"name")
        self.assertIs(len(resources), 2)
        self.assertEquals(resources[0].name, u"resource")


class TestClientTeamAccess(TestDatabaseFixture):
    def setUp(self):
        super(TestClientTeamAccess, self).setUp()
        self.user = models.User.find(username=u"user1")
        self.client = models.Client.find(user=self.user)
        self.client.team_access = True
        db.session.commit()
        self.create_fixtures()

    def create_fixtures(self):
        self.org = models.Organization(title=u"test", name=u"Test")
        self.org.owners.users.append(self.user)
        db.session.add(self.org)
        self.team = models.Team(userid=self.user.userid, title=u"developers", org=self.org)
        db.session.add(self.team)
        self.team_client_permission = models.TeamClientPermissions(team=self.team, client=self.client, access_permissions=u"admin")
        db.session.add(self.team_client_permission)
        self.client_team_access = models.ClientTeamAccess(org=self.org, client=self.client, access_level=models.CLIENT_TEAM_ACCESS.ALL)
        db.session.add(self.client_team_access)
        db.session.commit()

    def test_find_all(self):
        self.assertIs(models.ClientTeamAccess.find_all(client=self.client)[0], self.client_team_access)


class TestPermission(TestDatabaseFixture):
    def setUp(self):
        super(TestPermission, self).setUp()
        self.user = models.User.find(username=u"user1")
        self.create_fixtures()

    def create_fixtures(self):
        self.org = models.Organization(title=u"test", name=u"Test")
        self.org.owners.users.append(self.user)
        db.session.add(self.org)
        self.permission = models.Permission(user=self.user, org=self.org, name=u"admin", title=u"admin", allusers=True)
        db.session.add(self.permission)
        db.session.commit()

    def test_get_all_permissions(self):
        permissions = models.Permission.get_all_permissions(user=self.user)
        self.assertIs(permissions[0].title, self.permission.title)
        permissions = models.Permission.get_all_permissions_for_user(user=self.user)
        self.assertIs(permissions[0].title, self.permission.title)
        permissions = models.Permission.get_all_permissions_for_org(org=self.org)
        self.assertIs(permissions[0].title, self.permission.title)
