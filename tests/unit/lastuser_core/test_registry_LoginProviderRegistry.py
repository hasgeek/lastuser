# -*- coding: utf-8 -*-

import unittest

from lastuser_core import login_registry
from lastuser_core.registry import LoginProviderRegistry
from lastuserapp import app


class TestLoginProviderRegistry(unittest.TestCase):
    def test_loginproviderregistry(self):
        """
        Test for verifying creation of LoginProviderRegistry
        instance.
        """
        # A LoginProviderRegistry instance is created (based on
        # configuration provided) when init_for is called during
        # creation of app instance. To test and verify this correctly
        # we temporarily do not use the app instance available globally
        # and construct app instance separately
        expected_login_providers = []
        if app.config.get('OAUTH_TWITTER_KEY') and app.config.get(
            'OAUTH_TWITTER_SECRET'
        ):
            expected_login_providers.append('twitter')
        if app.config.get('OAUTH_GOOGLE_KEY') and app.config.get('OAUTH_GOOGLE_SECRET'):
            expected_login_providers.append('google')
        if app.config.get('OAUTH_LINKEDIN_KEY') and app.config.get(
            'OAUTH_LINKEDIN_SECRET'
        ):
            expected_login_providers.append('linkedin')
        if app.config.get('OAUTH_GITHUB_KEY') and app.config.get('OAUTH_GITHUB_SECRET'):
            expected_login_providers.append('github')
        self.assertIsInstance(login_registry, LoginProviderRegistry)
        self.assertItemsEqual(expected_login_providers, login_registry.keys())
