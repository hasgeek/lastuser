# -*- coding: utf-8 -*-

from lastuserapp import db
import lastuser_core.models as models
from .test_db import TestDatabaseFixture


class TestTeam(TestDatabaseFixture):

    def test_team_get(self):
        """
        Test for retrieving a Team with matching userid.
        """
        dachshunds = self.fixtures.dachshunds
        dachshunds_userid = dachshunds.userid
        result_with_userid = models.Team.get(userid=dachshunds_userid)
        result_without_userid = models.Team.get()
        self.assertIsNone(result_without_userid)

    def test_team_pickername(self):
        """
        Test for verifying team's pickername
        """
        dachshunds = self.fixtures.dachshunds
        title = dachshunds.title
        pickername = dachshunds.pickername
        self.assertIsInstance(pickername, unicode)
        self.assertEqual(title, pickername)

    def test_team_permissions(self):
        """
        Test for retrieving permissions for owner of a team
        """
        crusoe = self.fixtures.crusoe
        dachshunds = self.fixtures.dachshunds
        permissions_expected = ['edit', 'delete']
        result = dachshunds.permissions(crusoe)
        self.assertIsInstance(result, set)
        permissions_received = []
        for each in result:
            permissions_received.append(each)
        self.assertItemsEqual(permissions_expected, permissions_received)

    # def test_team_migrate_user(self):
    #     """
    #     Test for migrating an old user to newuser in a team (when merging user account takes place)
    #     """
    #     TODO: implement this
