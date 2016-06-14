# -*- coding: utf-8 -*-

from lastuserapp import db
import lastuser_core.models as models
from .test_db import TestDatabaseFixture
import fixtures


class TestResource(TestDatabaseFixture):

    def test_resource(self):
        """Test for creation of Resource instance"""
        name = u"woodlands"
        client = self.fixtures.client
        title = u"Woodlands"
        description = u'The great woodlands of Ontario'
        restricted = False
        result = models.Resource(name=name, title=title, description=description, client=client, siteresource=True)
        self.assertEqual(result.name, name)
        self.assertEqual(result.title, title)
        self.assertEqual(result.description, description)
        self.assertEqual(result.client, client)
        self.assertTrue(result.siteresource)
        self.assertFalse(result.restricted)

    def test_resource_get(self):
        """Test for retrieving a Resource given a name"""
        # scenario 3: if namespace given
        name = u'test_resource'
        client = self.fixtures.client
        namespace = client.namespace
        # scenario 1: if both client and namespace not given
        with self.assertRaises(TypeError):
            models.Resource.get(name=name)
        # scenario 2: if client given
        query_with_name_client = models.Resource.get(name=name, client=client)
        self.assertIsInstance(query_with_name_client, models.Resource)
        self.assertEqual(query_with_name_client.name, name)
        # scenario 3: if namespace given
        query_with_name_namespace = models.Resource.get(name=name, namespace=namespace)
        self.assertIsInstance(query_with_name_client, models.Resource)
        self.assertEqual(query_with_name_client.name, name)

    def test_resource_permissions(self):
        """Test for adding and retreiving permissions on a Resource instance"""
        crusoe = self.fixtures.crusoe
        resource = self.fixtures.resource
        client = self.fixtures.client
        # permissions method checks if client attached to Resource is owned by user
        permissions_received = []
        result = resource.permissions(crusoe)
        permissions_expected = ['edit', 'delete', 'new-action']
        existing_perms = client.permissions(crusoe)
        permissions_to_be_checked_against = list(existing_perms | set(permissions_expected))
        self.assertIsInstance(result, set)
        self.assertItemsEqual(result, permissions_to_be_checked_against)

    def test_resource_get_action(self):
        """
        Test for retreiving a ResourceAction on this Resource given a action name
        """
        resource = self.fixtures.resource
        name = u'read'
        result = resource.get_action(u'read')
        self.assertIsInstance(result, models.ResourceAction)
        self.assertEqual(result.name, name)
