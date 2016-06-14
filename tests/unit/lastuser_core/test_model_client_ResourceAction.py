# -*- coding: utf-8 -*-

from lastuserapp import db
import lastuser_core.models as models
from .test_db import TestDatabaseFixture

class TestResourceAction(TestDatabaseFixture):

    def test_resourceaction(self):
        """Test for creation of ResourceAction instance"""
        title=u'Party!'
        name=u'party'
        description=u'Weiner dog parties!'
        resource = self.fixtures.resource
        result = models.ResourceAction(name=name, title=title, resource=resource, description=description)
        self.assertEqual(result.name, name)
        self.assertEqual(result.resource, resource)
        self.assertEqual(result.title, title)
        self.assertEqual(result.description, result.description)

    def test_resourceaction_permissions(self):
        """
        Test for adding permissions to a resource if the client which is attached
        to the resource is it's owner
        """
        crusoe = self.fixtures.crusoe
        resource = self.fixtures.resource
        resource_action = self.fixtures.resource_action
        expected_permissions = ['edit', 'delete']
        received_permissions = resource_action.permissions(crusoe)
        self.assertIsInstance(received_permissions, set)
        self.assertItemsEqual(received_permissions, expected_permissions)

    def test_resourceaction_get(self):
        """
        Test for retrieving a ResourceAction instance given a name and resource.
        """
        resource = self.fixtures.resource
        name = u'read'
        result = models.ResourceAction.get(name, resource)
        self.assertIsInstance(result, models.ResourceAction)
        self.assertEqual(result.name, name)
