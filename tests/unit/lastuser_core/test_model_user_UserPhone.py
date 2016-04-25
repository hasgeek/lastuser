# -*- coding: utf-8 -*-

from lastuserapp import db
import lastuser_core.models as models
from .test_db import TestDatabaseFixture

class TestUserPhone(TestDatabaseFixture):

    def test_userphone(self):
        """
        Test for verifying creationg of UserPhone instance
        """
        phone = u"+987645321"
        result = models.UserPhone(phone=phone)
        self.assertIsInstance(result, models.UserPhone)

    def test_userphone_get(self):
        """
        Test for verifying UserPhone's get given a phone number
        """
        crusoe = self.fixtures.crusoe
        phone = u'+8080808080'
        result = models.UserPhone.get(phone)
        self.assertIsInstance(result, models.UserPhone)
        self.assertEqual(result.owner, crusoe)
        self.assertEqual(result.phone, phone)

    def test_userphone_unicode(self):
        """
        Test for verifying whether UserPhone's unicode method returns
        phone number in unicode
        """
        phone = u'+8080808080'
        result = unicode(models.UserPhone(phone))
        self.assertIsInstance(result, unicode)
        self.assertEqual(result, phone)

    # def test_userphone_phone(self):
    #     """
    #     Test for verifying UserPhone's phone property
    #     """
    #     TODO: Implement this
