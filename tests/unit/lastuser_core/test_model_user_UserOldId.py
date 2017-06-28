# -*- coding: utf-8 -*-

from lastuserapp import db
import lastuser_core.models as models
from .test_db import TestDatabaseFixture


class TestUserOldId(TestDatabaseFixture):
    def setUp(self):
        """
        setUp for testing UserOldId model
        """
        super(TestUserOldId, self).setUp()

    def test_UserOldId_get(self):
        """
        Test for verifying creation and retrieval of UserOldId instance
        """
        crusoe = self.fixtures.crusoe
        batdog = models.User(username=u"batdog", fullname=u"Batdog")
        db.session.add(batdog)
        db.session.commit()
        merged = models.merge_users(crusoe, batdog)
        if merged == crusoe:
            other = batdog
        else:
            other = crusoe
        query_for_olduser = models.UserOldId.get(other.userid)
        self.assertIsInstance(query_for_olduser, models.UserOldId)
        self.assertEqual(query_for_olduser.olduser, other)
