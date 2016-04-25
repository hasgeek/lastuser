# -*- coding: utf-8 -*-

from lastuserapp import db
import lastuser_core.models as models
from .test_db import TestDatabaseFixture
from sqlalchemy.ext.associationproxy import _AssociationList

class TestUserOldId(TestDatabaseFixture):

    def test_useroldid_get(self):
        """
        Test for verifying creation and retrieval of UserOldId instance
        """
        crusoe = self.fixtures.crusoe
        batdog = models.User(username=u"batdog", fullname=u"Batdog")
        db.session.add(batdog)
        db.session.commit()
        merged = models.merge_users(crusoe, batdog)
        query_for_olduser = models.UserOldId.get(batdog.userid)
        self.assertIsInstance(query_for_olduser, models.UserOldId)
        self.assertEqual(query_for_olduser.olduser, batdog)
