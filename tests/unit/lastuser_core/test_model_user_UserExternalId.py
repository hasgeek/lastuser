# -*- coding: utf-8 -*-

from lastuserapp import db
import lastuser_core.models as models
from .test_db import TestDatabaseFixture
from os import environ

class TestUserExternalId(TestDatabaseFixture):

    def test_userexternalid(self):
        """
        Test for creating an instance of UserExternalId
        """
        crusoe = self.fixtures.crusoe
        service = u'google'
        oauth_token = u'196461869-pPh2cPTnlqGHcJBcyQ4CR407d1j5LY4OdbhNQuvX'
        oauth_token_type = u'Bearer'
        result = models.UserExternalId(service=service, user=crusoe, userid=crusoe.email.email, username=crusoe.email.email, oauth_token=oauth_token, oauth_token_type=oauth_token_type)
        self.assertIsInstance(result, models.UserExternalId)

    def test_userexternalid_get(self):
        """
        Test for retrieving a UserExternalId instance given a
        serverice and userid or username
        """
        service = u'twitter'
        # scenario 1: when neither userid nor username is passed
        with self.assertRaises(TypeError):
            models.UserExternalId.get(service)

        crusoe = self.fixtures.crusoe
        oauth_token = environ.get('TWITTER_OAUTH_TOKEN')
        oauth_token_type = u'Bearer'
        externalid = models.UserExternalId(service=service, user=crusoe, userid=crusoe.email.email, username=crusoe.email.email, oauth_token=oauth_token, oauth_token_type=oauth_token_type)
        db.session.add(externalid)
        db.session.commit()

        # scenario 2: when userid is passed
        get_by_userid = models.UserExternalId.get(service=service, userid=crusoe.email.email)
        self.assertIsInstance(get_by_userid, models.UserExternalId)

        # scenario 3: when username is passed
        get_by_username = models.UserExternalId.get(service=service, username=crusoe.email.email)
        self.assertIsInstance(get_by_username, models.UserExternalId)
