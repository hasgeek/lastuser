# -*- coding: utf-8 -*-

import lastuser_core.models as models

from .test_db import TestDatabaseFixture


class TestClientCredential(TestDatabaseFixture):
    def setUp(self):
        """
        setUp for testing ClientCredential model
        """
        super(TestClientCredential, self).setUp()

    def test_clientcredential_new(self):
        """
        Test for ClientCredential model's new()
        """
        client = self.fixtures.client
        credentials = models.ClientCredential.new(client)
        self.assertIsInstance(credentials, tuple)
        # self.assertEqual(credentials[0].client_id, client.id)
        self.assertIsInstance(credentials[0], models.ClientCredential)
        client_secret = credentials[0].secret_hash
        self.assertTrue(client_secret.startswith('sha256$'))

    def test_clientcredential_get(self):
        """
        Test for ClientCredential model's get()
        """
        client = self.fixtures.client
        credentials = models.ClientCredential.new(client)
        name = credentials[0].name
        get_credentials = models.ClientCredential.get(name)
        self.assertIsInstance(get_credentials, models.ClientCredential)
        self.assertEqual(credentials[0], get_credentials)

    def test_clientcredential_secret_is(self):
        """
        Test for checking if clientcredential's secret is a SHA256 string (64 characters) prepended with 'sha256$'
        """
        client = self.fixtures.client
        credentials = models.ClientCredential.new(client)
        self.assertTrue(
            models.ClientCredential.secret_is(credentials[0], credentials[1])
        )
        self.assertEqual(len(credentials[1]), 44)
