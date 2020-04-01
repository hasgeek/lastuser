# -*- coding: utf-8 -*-

from lastuserapp import db
import lastuser_core.models as models

from .test_db import TestDatabaseFixture


class TestUserClientPermissions(TestDatabaseFixture):
    def test_userclientpermissions(self):
        """
        Test for verifying creation of UserClientPermissions instance
        """
        gustav = models.User(username='gustav')
        auth_client = self.fixtures.auth_client
        access_permissions = 'siteadmin'
        result = models.AuthClientUserPermissions(
            user=gustav, auth_client=auth_client, access_permissions=access_permissions
        )
        db.session.add(result)
        db.session.commit()
        self.assertIsInstance(result, models.AuthClientUserPermissions)

    def test_userclientpermissions_migrate_user(self):
        """
        Test for migrating users and transfering their
        client permissions
        """
        # scenario 1: when *only* olduser has UserClientPermissions instance
        old_crusoe = self.fixtures.crusoe
        new_crusoe = models.User(username='chef-crusoe')
        models.AuthClientUserPermissions.migrate_user(old_crusoe, new_crusoe)
        for each in new_crusoe.client_permissions:
            self.assertIsInstance(each, models.AuthClientUserPermissions)
        self.assertEqual(new_crusoe.client_permissions[0].user, new_crusoe)

        # scenario 2: when *both* olduser and newuser have UserClientPermissions instances
        old_oakley = self.fixtures.oakley
        auth_client = self.fixtures.auth_client
        access_permissions_old_oakley = 'siteadmin'
        access_permissions_new_oakley = 'siteeditor'
        old_oakley_userclientperms = models.AuthClientUserPermissions(
            user=old_oakley,
            auth_client=auth_client,
            access_permissions=access_permissions_old_oakley,
        )
        new_oakley = models.User(username='oakley-the-stud')
        new_oakley_userclientperms = models.AuthClientUserPermissions(
            user=new_oakley,
            auth_client=auth_client,
            access_permissions=access_permissions_new_oakley,
        )
        db.session.add(old_oakley_userclientperms)
        db.session.add(new_oakley_userclientperms)
        db.session.commit()
        models.AuthClientUserPermissions.migrate_user(old_oakley, new_oakley)
        result = new_oakley.client_permissions[0]
        for each in new_oakley.client_permissions:
            self.assertIsInstance(each, models.AuthClientUserPermissions)
        received_access_permissions = str(result.access_permissions)
        expected_access_permissions = " ".join(
            [access_permissions_old_oakley, access_permissions_new_oakley]
        )
        self.assertEqual(expected_access_permissions, received_access_permissions)

    def test_userclientpermissions_pickername(self):
        """
        Test for UserClientPermissions' pickername
        """
        finnick = models.User(username='finnick', fullname="Finnick Odair")
        district4 = models.AuthClient(title="District 4")
        access_permissions = 'siteadmin'
        result = models.AuthClientUserPermissions(
            user=finnick, auth_client=district4, access_permissions=access_permissions
        )
        self.assertEqual(result.pickername, finnick.pickername)

    def test_userclientpermissions_buid(self):
        """
        Test for UserClientPermissions' buid
        """
        beetee = models.User(username='beetee', fullname="Beetee")
        district3 = models.AuthClient(title='District 3')
        access_permissions = 'siteadmin'
        result = models.AuthClientUserPermissions(
            user=beetee, auth_client=district3, access_permissions=access_permissions
        )
        self.assertEqual(result.buid, beetee.buid)
