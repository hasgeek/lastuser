# -*- coding: utf-8 -*-

from lastuserapp import db
import lastuser_core.models as models
from .test_db import TestDatabaseFixture


class TestClient(TestDatabaseFixture):
    def setUp(self):
        super(TestClient, self).setUp()
        self.user = models.User.query.filter_by(username=u"user1").first()

    def test_all_clients(self):
        clients = models.Client.all_clients(user=self.user)
        self.assertIs(len(clients), 1)

    def test_all_lastuser_clients(self):
        self.assertIs(len(models.Client.all_lastuser_clients()), 1)


class TestUserClientPermissions(TestDatabaseFixture):
    def setUp(self):
        super(TestUserClientPermissions, self).setUp()
        self.user = models.User.query.filter_by(username=u"user1").first()
        self.create_fixtures()

    def create_fixtures(self):
        # Add permission to the client
        client = models.Client.query.filter_by(user=self.user).first()
        self.permission = models.UserClientPermissions(user=self.user, client=client)
        self.permission.permissions = u"admin"
        db.session.add(self.permission)
        db.session.commit()

    def test_all_permissions(self):
        client = models.Client.query.filter_by(user=self.user).first()
        perms = models.UserClientPermissions.all_permissions(client=client, user=self.user)
        self.assertIs(perms[0], self.permission)
        self.assertIs(models.UserClientPermissions.permission_or_404(client=client, user=self.user), self.permission)


class TestTeamClientPermissions(TestDatabaseFixture):
    def setUp(self):
        super(TestTeamClientPermissions, self).setUp()
        self.user = models.User.query.filter_by(username=u"user1").first()
        self.client = models.Client.query.filter_by(user=self.user).first()
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

    def test_permissions(self):
        perms = self.client.team_permissions
        self.assertIs(perms[0], self.team_client_permission)
        perms = models.TeamClientPermissions.all_permissions(client=self.client, team=self.team)
        self.assertIs(perms[0], self.team_client_permission)
        self.assertIs(models.TeamClientPermissions.permission_or_404(client=self.client), self.team_client_permission)


class TestResource(TestDatabaseFixture):
    def setUp(self):
        super(TestResource, self).setUp()
        self.user = models.User.query.filter_by(username=u"user1").first()
        self.client = models.Client.query.filter_by(user=self.user).first()
        self.create_fixtures()

    def create_fixtures(self):
        resource = models.Resource(name=u"resource", title=u"Resource", client=self.client)
        db.session.add(resource)
        db.session.commit()

    def test_find_all(self):
        resources = self.client.resources
        self.assertIs(len(resources), 2)
        self.assertEquals(resources[1].name, u"resource")


class TestClientTeamAccess(TestDatabaseFixture):
    def setUp(self):
        super(TestClientTeamAccess, self).setUp()
        self.user = models.User.query.filter_by(username=u"user1").first()
        self.client = models.Client.query.filter_by(user=self.user).first()
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
        self.assertIs(self.client.org_team_access[0], self.client_team_access)


class TestPermission(TestDatabaseFixture):
    def setUp(self):
        super(TestPermission, self).setUp()
        self.user = models.User.query.filter_by(username=u"user1").first()
        self.create_fixtures()

    def create_fixtures(self):
        self.org = models.Organization(title=u"test", name=u"Test")
        self.org.owners.users.append(self.user)
        db.session.add(self.org)
        self.permission = models.Permission(user=self.user, org=self.org, name=u"admin", title=u"admin", allusers=True)
        db.session.add(self.permission)
        db.session.commit()

    def test_get_all_permissions(self):
        permissions = models.Permission.all_permissions(user=self.user)
        self.assertIs(permissions[0].title, self.permission.title)
        permissions = models.Permission.all_permissions_for_user(user=self.user)
        self.assertIs(permissions[0].title, self.permission.title)
        permissions = models.Permission.all_permissions_for_org(org=self.org)
        self.assertIs(permissions[0].title, self.permission.title)
