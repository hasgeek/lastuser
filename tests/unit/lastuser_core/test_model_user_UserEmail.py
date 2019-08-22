# -*- coding: utf-8 -*-

from coaster.utils import md5sum
import lastuser_core.models as models

from .test_db import TestDatabaseFixture


class TestUserEmail(TestDatabaseFixture):
    def test_useremail(self):
        """
        Test for verifying creation of UserEmail object
        """
        oakley = self.fixtures.oakley
        email_domain = u'batdog.ca'
        oakley_new_email = models.user.UserEmail(
            email=u'oakley@' + email_domain, user=oakley
        )
        self.assertIsInstance(oakley_new_email, models.user.UserEmail)
        self.assertTrue(hasattr(oakley_new_email, '_email'))
        self.assertTrue(hasattr(oakley_new_email, 'md5sum'))
        self.assertTrue(hasattr(oakley_new_email, 'domain'))
        self.assertEqual(oakley_new_email.domain, email_domain)

    def test_useremail_get(self):
        """
        Test for verifying UserEmail's get that should return a UserEmail object with matching email or md5sum
        """
        crusoe = self.fixtures.crusoe
        email = crusoe.email.email
        email_md5 = md5sum(email)
        # scenario 1: when both email and md5sum are not passed
        with self.assertRaises(TypeError):
            models.UserEmail.get()

        # scenario 2: when email is passed
        get_by_email = models.UserEmail.get(email=email)
        self.assertIsInstance(get_by_email, models.UserEmail)
        self.assertEqual(get_by_email.user, crusoe)

        # scenario 3: when md5sum is passed
        get_by_md5sum = models.UserEmail.get(md5sum=email_md5)
        self.assertIsInstance(get_by_md5sum, models.UserEmail)
        self.assertEqual(get_by_md5sum.user, crusoe)

    def test_useremail_unicode(self):
        """
        Test for verifying email is returned in unicode format
        """
        crusoe = self.fixtures.crusoe
        email = crusoe.email.email
        result = unicode(models.UserEmail(email=email))
        self.assertIsInstance(result, unicode)
        assert email in result

    def test_useremail_email(self):
        """
        Test for verifying UserEmail instance's email property
        """
        oakley = self.fixtures.oakley
        email = u'oakley@batdogs.ca'
        oakley_new_email = models.UserEmail(email=email, user=oakley)
        result = oakley_new_email.email
        self.assertIsInstance(result, unicode)
        self.assertEqual(email, result)
