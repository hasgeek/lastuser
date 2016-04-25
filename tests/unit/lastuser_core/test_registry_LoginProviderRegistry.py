
from lastuserapp import db, app, init_for
from lastuser_core import login_registry
from lastuser_core.registry import LoginProviderRegistry
import unittest


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
        init_for('testing')
        if app.config.get('OAUTH_TWITTER_KEY') and app.config.get('OAUTH_TWITTER_SECRET'):
            expected_login_providers.append('twitter')
        if app.config.get('OAUTH_GOOGLE_KEY') and app.config.get('OAUTH_GOOGLE_SECRET'):
            expected_login_providers.append('google')
        if app.config.get('OAUTH_LINKEDIN_KEY') and app.config.get('OAUTH_LINKEDIN_SECRET'):
            expected_login_providers.append('linkedin')
        if app.config.get('OAUTH_GITHUB_KEY') and app.config.get('OAUTH_GITHUB_SECRET'):
            expected_login_providers.append('github')
        expected_login_providers.append('openid')
        self.assertIsInstance(login_registry, LoginProviderRegistry)
        self.assertItemsEqual(expected_login_providers, login_registry.keys())

    def test_loginproviderregistry_at_username_services(self):
        """
        Test for retrieving list of services that use @username addressing
        """
        init_for('testing')
        expected_services = ['twitter', 'github']
        recieved_services = []
        for key,value in login_registry.items():
            if hasattr(value, 'at_username'):
                if value.at_username:
                    recieved_services.append(key)
        self.assertItemsEqual(expected_services, recieved_services)
