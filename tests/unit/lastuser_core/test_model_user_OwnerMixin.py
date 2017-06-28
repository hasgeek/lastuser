# -*- coding: utf-8 -*-

import lastuser_core.models as models
from .test_db import TestDatabaseFixture


class TestUser(TestDatabaseFixture):

    def test_ownermixin_owner(self):
        """Test to verify setting of owner property on any OwnerMixin inherited instance"""
        crusoe = self.fixtures.crusoe
        # scenario 1: check owner of existing UserEmail instance
        crusoe_email = self.fixtures.crusoe_email
        self.assertEqual(crusoe_email.owner, crusoe)

        # scenario 2: check owner when owner is org
        client = self.fixtures.client
        batdog = self.fixtures.batdog
        dachshunds = self.fixtures.dachshunds
        self.assertEqual(client.owner, batdog)

        # scenaio 3: check owner when new UserEmailClaim instance
        spock = models.User(username=u'spock')
        spock_email_claim = models.UserEmailClaim(email=u'spock@startrek.co.uk', user=spock)
        self.assertEqual(spock_email_claim.owner, spock)

        # scenario 4: set user as owner on some OwnerMixin inherited instance
        spock_phone = models.UserPhoneClaim(phone=u'+9112345678', user=spock)
        spock_phone.owner = spock
        self.assertEqual(spock_phone.owner, spock)

        # scenario 5: set organization as owner on some OwnerMixin inherited instance
        spock_phone.owner = batdog
        self.assertEqual(spock_phone.owner, batdog)

        # scenario 6: set Team as owner on some OwnerMixin inherited instance
        spock_phone.owner = dachshunds
        self.assertEqual(spock_phone.owner, dachshunds)

        # scenario 7: when owner not insance of User, organization or Team
        with self.assertRaises(ValueError):
            spock_phone.owner = client
