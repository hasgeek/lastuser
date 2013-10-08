# -*- coding: utf-8 -*-

from lastuserapp import db
import lastuser_core.models as models
from .test_db import TestDatabaseFixture


class TestTeam(TestDatabaseFixture):
    def setUp(self):
        super(TestTeam, self).setUp()
        self.user = models.User.query.filter_by(username=u"user1").first()
        self.create_fixtures()

    def create_fixtures(self):
        self.org = models.Organization(title=u"title", name=u"Test")
        self.org.owners.users.append(self.user)
        db.session.add(self.org)
        self.team = models.Team(userid=self.user.userid, title=u"developers", org=self.org)
        db.session.add(self.team)
        db.session.commit()


class TestOrganization(TestDatabaseFixture):
    def setUp(self):
        super(TestOrganization, self).setUp()
        self.user = models.User.query.filter_by(username=u"user1").first()
        self.client = models.Client.query.filter_by(user=self.user).first()
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
