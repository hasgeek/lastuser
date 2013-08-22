# -*- coding: utf-8 -*-
import lastuser_core.models as models
from .test_db import TestDatabaseFixture


class TestSMS(TestDatabaseFixture):
    def setUp(self):
        super(TestSMS, self).setUp()

    def test_transaction_id(self):
        val = u"1" * 40
        msg = models.SMSMessage.find_by_transaction_id(val)
        self.assertEquals(msg.transaction_id, val)
