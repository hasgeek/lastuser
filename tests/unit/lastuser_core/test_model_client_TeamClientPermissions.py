# -*- coding: utf-8 -*-

import lastuser_core.models as models

from .test_db import TestDatabaseFixture


class TestTeamClientPermissions(TestDatabaseFixture):
    def test_teamclientpermissions(self):
        """Test for verifying creation of TeamClientPermissions' instance"""
        result = models.AuthClientTeamPermissions()
        self.assertIsInstance(result, models.AuthClientTeamPermissions)

    def test_teamclientpermissions_pickername(self):
        """Test for retreiving pickername on TeamClientPermissions instance"""
        dachshunds = self.fixtures.dachshunds
        team_client_permission = self.fixtures.auth_client_team_permissions
        self.assertEqual(team_client_permission.pickername, dachshunds.title)

    def test_teamclientpermissions_budi(self):
        """Test for retreving buid of a TeamClientPermissions instance """
        dachshunds = self.fixtures.dachshunds
        team_client_permission = self.fixtures.auth_client_team_permissions
        self.assertEqual(team_client_permission.buid, dachshunds.buid)
