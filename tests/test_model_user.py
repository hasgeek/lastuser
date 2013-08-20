# -*- coding: utf-8 -*-

import unittest
from lastuserapp import app, db, init_for
import lastuser_core.models as models
from .test_db import TestDatabaseFixture


class TestUserModel(TestDatabaseFixture):
    def setUp(self):
        super(TestUserModel, self).setUp()
        
    def test_transaction_id(self):
        msg = models.SMSMessage.find_by_transaction_id('1' * 40)
        self.assetTrue(msg != None)

    def tearDown(self):
        super(TestUserModel, self).tearDown()
