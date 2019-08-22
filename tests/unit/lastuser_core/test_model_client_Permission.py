# -*- coding: utf-8 -*-

from lastuserapp import db
import lastuser_core.models as models

from .test_db import TestDatabaseFixture


class TestPermission(TestDatabaseFixture):
    def test_permission_get(self):
        """
        Test for retrieving a Permission instance given it's name and owner (user or org) or if it's available to all users.
        """
        # scenario 1: when allusers is False
        specialdachs = self.fixtures.specialdachs
        netizens = models.Permission(
            name=u"netizens", title=u"Netizens", org=specialdachs, allusers=True
        )
        db.session.add(netizens)
        db.session.commit()

        # scenario 1 + neither user or org is given
        with self.assertRaises(TypeError):
            models.Permission.get(name=netizens.name, allusers=False)

        # scenario 1 + only user is given
        crusoe = self.fixtures.crusoe
        bdfl = self.fixtures.bdfl
        self.assertIsNotNone(models.Permission.get(name=bdfl.name, user=crusoe))

        # scenario 1 + only org is given
        result2 = models.Permission.get(name=netizens.name, org=specialdachs)
        self.assertIsInstance(result2, models.Permission)
        self.assertEqual(result2, netizens)

        # scenario 2: when allusers is True
        result3 = models.Permission.get(name=netizens.name, allusers=True)
        self.assertIsInstance(result3, models.Permission)
        self.assertEqual(result3, netizens)

    def test_permission_owner_is(self):
        """
        Test for retrieving owner of a Permission object
        """
        crusoe = self.fixtures.crusoe
        oakley = self.fixtures.oakley
        bdfl = self.fixtures.bdfl
        valid_owner_query = bdfl.owner_is(crusoe)
        invalid_owner_query = bdfl.owner_is(oakley)
        self.assertTrue(valid_owner_query)
        self.assertFalse(invalid_owner_query)

    def test_permission_owner(self):
        """
        Test for retrieving the owner of a Permission instance
        """
        crusoe = self.fixtures.crusoe
        bdfl = self.fixtures.bdfl
        get_owner_by_user = bdfl.owner
        self.assertEqual(get_owner_by_user, crusoe)
        specialdachs = self.fixtures.specialdachs
        permission_name = u"netizens"
        netizens = models.Permission(
            name=permission_name, title=u"Netizens", allusers=True, org=specialdachs
        )
        db.session.add(netizens)
        db.session.commit()
        get_owner_by_org = netizens.owner
        self.assertEqual(get_owner_by_org, specialdachs)

    def test_permission_permissions(self):
        """
        Test for adding permissions to Permission instance
        given a user is its owner.
        """
        crusoe = self.fixtures.crusoe
        bdfl = self.fixtures.bdfl
        permissions_expected_to_be_added = ['edit', 'delete']
        result = bdfl.permissions(crusoe)
        self.assertIsInstance(result, set)
        permissions_received = []
        for each in result:
            permissions_received.append(each)
        self.assertItemsEqual(permissions_expected_to_be_added, permissions_received)
