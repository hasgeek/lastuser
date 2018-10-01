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
        bathound = models.User(username=u"bathound", fullname=u"Bathound")
        db.session.add(bathound)
        db.session.commit()
        merged = models.merge_users(crusoe, bathound)
        if merged == crusoe:
            other = bathound
        else:
            other = crusoe
        query_for_olduser = models.UserOldId.get(other.uuid)
        self.assertIsInstance(query_for_olduser, models.UserOldId)
        self.assertEqual(query_for_olduser.olduser, other)
