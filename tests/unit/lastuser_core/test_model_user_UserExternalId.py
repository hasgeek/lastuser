# -*- coding: utf-8 -*-

from __future__ import unicode_literals

from os import environ

from lastuserapp import db
import lastuser_core.models as models

from .test_db import TestDatabaseFixture


class TestUserExternalId(TestDatabaseFixture):
    def test_userexternalid(self):
        """
        Test for creating an instance of UserExternalId
        """
        crusoe = self.fixtures.crusoe
        service = 'google'
        oauth_token = '196461869-pPh2cPTnlqGHcJBcyQ4CR407d1j5LY4OdbhNQuvX'  # NOQA: S105
        oauth_token_type = 'Bearer'  # NOQA: S105
        result = models.UserExternalId(
            service=service,
            user=crusoe,
            userid=crusoe.email.email,
            username=crusoe.email.email,
            oauth_token=oauth_token,
            oauth_token_type=oauth_token_type,
        )
        self.assertIsInstance(result, models.UserExternalId)
        assert '<UserExternalId {service}:{username} of {user}>'.format(
            service=service, username=crusoe.email.email, user=repr(crusoe)[1:-1]
        ) in repr(result)

    def test_userexternalid_get(self):
        """
        Test for retrieving a UserExternalId instance given a
        serverice and userid or username
        """
        service = 'twitter'
        # scenario 1: when neither userid nor username is passed
        with self.assertRaises(TypeError):
            models.UserExternalId.get(service)

        crusoe = self.fixtures.crusoe
        oauth_token = environ.get('TWITTER_OAUTH_TOKEN')
        oauth_token_type = 'Bearer'  # NOQA: S105
        externalid = models.UserExternalId(
            service=service,
            user=crusoe,
            userid=crusoe.email.email,
            username=crusoe.email.email,
            oauth_token=oauth_token,
            oauth_token_type=oauth_token_type,
        )
        db.session.add(externalid)
        db.session.commit()
        # scenario 2: when userid is passed
        get_by_userid = models.UserExternalId.get(
            service=service, userid=crusoe.email.email
        )
        self.assertIsInstance(get_by_userid, models.UserExternalId)
        assert '<UserExternalId {service}:{username} of {user}>'.format(
            service=service, username=crusoe.email.email, user=repr(crusoe)[1:-1]
        ) in repr(get_by_userid)
        # scenario 3: when username is passed
        get_by_username = models.UserExternalId.get(
            service=service, username=crusoe.email.email
        )
        self.assertIsInstance(get_by_username, models.UserExternalId)
        assert '<UserExternalId {service}:{username} of {user}>'.format(
            service=service, username=crusoe.email.email, user=repr(crusoe)[1:-1]
        ) in repr(get_by_username)
