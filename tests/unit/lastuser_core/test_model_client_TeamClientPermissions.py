from lastuserapp import db
import lastuser_core.models as models
from .test_db import TestDatabaseFixture
import fixtures


class TestTeamClientPermissions(TestDatabaseFixture):

    def test_teamclientpermissions(self):
        """Test for verifying creation of TeamClientPermissions' instance"""
        # team, client, access_permissions
        access_permissions = u'siteadmin'
        client = self.fixtures.client
        dachshunds = self.fixtures.dachshunds
        result = models.TeamClientPermissions(access_permissions=access_permissions, client=client, team=dachshunds)
        self.assertIsInstance(result, models.TeamClientPermissions)
        self.assertEqual(result.client, client)
        self.assertEqual(result.team, dachshunds)
        self.assertEqual(result.access_permissions, access_permissions)

    def test_teamclientpermissions_pickername(self):
        """Test for retreiving pickername on TeamClientPermissions instance"""
        dachshunds = self.fixtures.dachshunds
        team_client_permission = self.fixtures.team_client_permission
        self.assertEqual(team_client_permission.pickername, dachshunds.title)

    def test_teamclientpermissions_userid(self):
        """Test for retreving userid of a TeamClientPermissions instance """
        dachshunds = self.fixtures.dachshunds
        team_client_permission = self.fixtures.team_client_permission
        self.assertEqual(team_client_permission.userid, dachshunds.userid)
