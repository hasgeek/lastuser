from lastuserapp import db, login_registry
from lastuser_oauth.providers import *
from .test_db import TestDatabaseFixture

class TestGithubProvider(TestDatabaseFixture):
    def setUp(self):
        """
        setUp for testing Provider: Github
        """
        super(TestGithubProvider, self).setUp()
