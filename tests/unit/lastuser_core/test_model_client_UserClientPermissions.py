# -*- coding: utf-8 -*-

from lastuserapp import db
import lastuser_core.models as models
from .test_db import TestDatabaseFixture


class TestUserClientPermissions(TestDatabaseFixture):

    def test_UserClientPermissions(self):
        """
        Test for verifying creation of UserClientPermissions instance
        """
        gustav = models.User(username=u'gustav')
        client = self.fixtures.client
        access_permissions = u'siteadmin'
        result = models.UserClientPermissions(user=gustav, client=client, access_permissions=access_permissions)
        db.session.add(result)
        db.session.commit()
        self.assertIsInstance(result, models.UserClientPermissions)

    def test_UserClientPermissions_migrate_user(self):
        """
        Test for migrating users and transfering their
        client permissions
        """
        # scenario 1: when *only* olduser has UserClientPermissions instance
        old_crusoe = self.fixtures.crusoe
        new_crusoe = models.User(username=u'chef-crusoe')
        models.UserClientPermissions.migrate_user(old_crusoe, new_crusoe)
        for each in new_crusoe.client_permissions:
            self.assertIsInstance(each, models.UserClientPermissions)
        self.assertEqual(new_crusoe.client_permissions[0].user, new_crusoe)

        # scenario 2: when *both* olduser and newuser have UserClientPermissions instances
        old_oakley = self.fixtures.oakley
        client = self.fixtures.client
        access_permissions_old_oakley = u'siteadmin'
        access_permissions_new_oakley = u'siteeditor'
        old_oakley_userclientperms = models.UserClientPermissions(user=old_oakley, client=client, access_permissions=access_permissions_old_oakley)
        new_oakley = models.User(username=u'oakley-the-stud')
        new_oakley_userclientperms = models.UserClientPermissions(user=new_oakley, client=client, access_permissions=access_permissions_new_oakley)
        db.session.add(old_oakley_userclientperms)
        db.session.add(new_oakley_userclientperms)
        db.session.commit()
        models.UserClientPermissions.migrate_user(old_oakley, new_oakley)
        result = new_oakley.client_permissions[0]
        for each in new_oakley.client_permissions:
            self.assertIsInstance(each, models.UserClientPermissions)
        received_access_permissions = str(result.access_permissions)
        expected_access_permissions = " ".join([access_permissions_old_oakley, access_permissions_new_oakley])
        self.assertEqual(expected_access_permissions, received_access_permissions)

    def test_userclientpermissions_pickername(self):
        """
        Test for UserClientPermissions' pickername
        """
        finnick = models.User(username=u'finnick', fullname=u"Finnick Odair")
        district4 = models.Client(title=u"District 4")
        access_permissions = u'siteadmin'
        result = models.UserClientPermissions(user=finnick, client=district4, access_permissions=access_permissions)
        self.assertEqual(result.pickername, finnick.pickername)

    def test_userclientpermissions_buid(self):
        """
        Test for UserClientPermissions' buid
        """
        beetee = models.User(username=u'beetee', fullname=u"Beetee")
        district3 = models.Client(title=u'District 3')
        access_permissions = u'siteadmin'
        result = models.UserClientPermissions(user=beetee, client=district3, access_permissions=access_permissions)
        self.assertEqual(result.buid, beetee.buid)
