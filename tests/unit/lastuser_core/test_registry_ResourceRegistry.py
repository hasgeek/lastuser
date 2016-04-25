from lastuserapp import db
from lastuser_core import registry
from .test_db import TestDatabaseFixture
try:
    from collections import OrderedDict
except ImportError:
    from ordereddict import OrderedDict

class TestResourceRegistry(TestDatabaseFixture):

    def test_resourceregistry(self):
        """Test for verifying creation of ResourceRegistry instance"""
        result = registry.ResourceRegistry()
        self.assertIsInstance(result, OrderedDict)
