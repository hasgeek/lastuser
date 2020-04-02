# -*- coding: utf-8 -*-

from lastuserapp import db
import lastuser_core.models as models

from .test_db import TestDatabaseFixture


class TestAuthCode(TestDatabaseFixture):
    def test_authcode_init(self):
        """Test to verify creation of AuthCode instance"""
        crusoe = self.fixtures.crusoe
        auth_client = self.fixtures.auth_client
        auth_code = models.AuthCode(
            user=crusoe,
            auth_client=auth_client,
            redirect_uri='http://batdogadventures.com/fun',
            scope='id',
        )
        # code redirect_uri, used
        db.session.add(auth_code)
        db.session.commit()
        result = models.AuthCode.all_for(user=crusoe).one_or_none()
        self.assertIsInstance(result, models.AuthCode)
        self.assertEqual(result.auth_client, auth_client)
        self.assertEqual(result.user, crusoe)

    def test_authcode_is_valid(self):
        """Test to verify if a AuthCode instance is valid"""
        oakley = self.fixtures.oakley
        auth_client = self.fixtures.auth_client
        auth_code = models.AuthCode(
            user=oakley,
            auth_client=auth_client,
            used=True,
            redirect_uri='http://batdogadventures.com/fun',
            scope='email',
        )
        db.session.add(auth_code)
        db.session.commit()

        # Scenario 1: When code has not been used
        unused_code_status = models.AuthCode.all_for(user=oakley).one().is_valid()
        self.assertFalse(unused_code_status)

        # Scenario 2: When code has been used
        auth_code.used = False
        db.session.commit()
        used_code_status = models.AuthCode.all_for(user=oakley).one().is_valid()
        self.assertTrue(used_code_status)
