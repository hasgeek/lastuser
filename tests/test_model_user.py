# -*- coding: utf-8 -*-

from werkzeug.exceptions import NotFound
from lastuserapp import db
import lastuser_core.models as models
from .test_db import TestDatabaseFixture


class TestUser(TestDatabaseFixture):
    def setUp(self):
        super(TestUser, self).setUp()
        self.user = models.User.find(username=u"user1")
        self.create_fixtures()

    def create_fixtures(self):
        pass

    def test_find(self):
        #This should rise 404
        with self.assertRaises(NotFound):
            models.User.find(userid=u"s"*22, first_or_404=True)


class TestTeam(TestDatabaseFixture):
    def setUp(self):
        super(TestTeam, self).setUp()
        self.user = models.User.find(username=u"user1")
        self.create_fixtures()

    def create_fixtures(self):
        self.org = models.Organization(title=u"title", name=u"Test")
        self.org.owners.users.append(self.user)
        db.session.add(self.org)
        self.team = models.Team(userid=self.user.userid, title=u"developers", org=self.org)
        db.session.add(self.team)
        db.session.commit()

    def test_find(self):
        self.assertIs(models.Team.find(userid=self.user.userid, org=self.org, first_or_404=True), self.team)


class TestOrganization(TestDatabaseFixture):
    def setUp(self):
        super(TestOrganization, self).setUp()
        self.user = models.User.find(username=u"user1")
        self.client = models.Client.find(user=self.user)
        self.create_fixtures()

    def create_fixtures(self):
        self.org = models.Organization(title=u"test", name=u"Test")
        self.org.owners.users.append(self.user)
        self.org1 = models.Organization(title=u"test1", name=u"Test1")
        self.org1.owners.users.append(self.user)
        self.client_team_access = models.ClientTeamAccess(org=self.org, client=self.client, access_level=models.CLIENT_TEAM_ACCESS.ALL)
        self.client_team_access1 = models.ClientTeamAccess(org=self.org1, client=self.client, access_level=models.CLIENT_TEAM_ACCESS.ALL)
        db.session.add_all([self.org, self.org1, self.client_team_access, self.client_team_access1])
        db.session.commit()

    def test_exclude(self):
        self.assertIs(models.Organization.exclude(user=self.user, client=self.client, org_userids=[self.org1.userid])[0], self.org)
