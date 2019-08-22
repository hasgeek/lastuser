# -*- coding: utf-8 -*-

import lastuser_core.models as models

from .test_db import TestDatabaseFixture


class TestPasswordResetRequest(TestDatabaseFixture):
    def setUp(self):
        """
        setUp for testing PasswordResetRequest
        """
        super(TestPasswordResetRequest, self).setUp()

    def test_passwordresetrequest_init(self):
        """
        Test for checking PasswordResetRequest's instance creation
        """
        result = models.PasswordResetRequest()
        self.assertIsInstance(result, models.PasswordResetRequest)
        self.assertTrue(hasattr(result, 'reset_code'))
