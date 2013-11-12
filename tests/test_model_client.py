# -*- coding: utf-8 -*-

from lastuserapp import db
import lastuser_core.models as models
from .test_db import TestDatabaseFixture


class TestClient(TestDatabaseFixture):
    def setUp(self):
        super(TestClient, self).setUp()
        self.user = models.User.query.filter_by(username=u"user1").first()


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
