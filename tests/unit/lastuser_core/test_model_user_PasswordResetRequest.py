# -*- coding: utf-8 -*-

from lastuserapp import db
import lastuser_core.models as models
from .test_db import TestDatabaseFixture

class TestPasswordResetRequest(TestDatabaseFixture):

    def test_passwordresetrequest_init(self):
        """
        Test for checking PasswordResetRequest's instance creation
        """
        crusoe_email = self.fixtures.crusoe.email.email
        result = models.PasswordResetRequest()
        self.assertIsInstance(result, models.PasswordResetRequest)
        self.assertTrue(hasattr(result, 'reset_code'))
