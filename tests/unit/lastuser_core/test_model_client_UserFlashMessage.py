from lastuserapp import db
import lastuser_core.models as models
from .test_db import TestDatabaseFixture
from datetime import datetime, timedelta

class TestUserFlashMessage(TestDatabaseFixture):

    def test_userflashmessage(self):
        """Test to verify creation of UserFlashMessage instance"""
        message='You have logged in as crusoe via Twitter'
        category='info'
        crusoe = self.fixtures.crusoe
        result = models.UserFlashMessage(user=crusoe, category=category, message=message)
        self.assertIsInstance(result, models.UserFlashMessage)
        self.assertEqual(result.user, crusoe)
        self.assertEqual(result.message, message)
        self.assertEqual(result.category, category)
