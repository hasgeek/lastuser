# -*- coding: utf-8 -*-

import lastuser_core.models as models
from .test_db import TestDatabaseFixture


class TestSMS(TestDatabaseFixture):
    def setUp(self):
        super(TestSMS, self).setUp()
