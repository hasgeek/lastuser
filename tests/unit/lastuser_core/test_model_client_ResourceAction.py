# -*- coding: utf-8 -*-

import lastuser_core.models as models

from .test_db import TestDatabaseFixture


class TestResourceAction(TestDatabaseFixture):
    def setUp(self):
        """
        setUp for testing ResourceAction model
        """
        super(TestResourceAction, self).setUp()

    def test_resourceaction_permissions(self):
        """
        Test for adding permissions to a resource if the client which is attached
        to the resource is it's owner
        """
        crusoe = self.fixtures.crusoe
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
        resource_action = self.fixtures.resource_action
        result = models.ResourceAction.get(resource_action.name, resource)
        self.assertIsInstance(result, models.ResourceAction)
        self.assertEqual(result, resource_action)
