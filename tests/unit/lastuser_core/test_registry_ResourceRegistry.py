# -*- coding: utf-8 -*-

from collections import OrderedDict

from lastuser_core import registry

from .test_db import TestDatabaseFixture


class TestResourceRegistry(TestDatabaseFixture):
    def test_resourceregistry(self):
        """Test for verifying creation of ResourceRegistry instance"""
        result = registry.ResourceRegistry()
        self.assertIsInstance(result, OrderedDict)
