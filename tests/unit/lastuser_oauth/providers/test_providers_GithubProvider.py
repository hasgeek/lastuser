# -*- coding: utf-8 -*-

from .test_db import TestDatabaseFixture


class TestGithubProvider(TestDatabaseFixture):
    def setUp(self):
        """
        setUp for testing Provider: Github
        """
        super(TestGithubProvider, self).setUp()
