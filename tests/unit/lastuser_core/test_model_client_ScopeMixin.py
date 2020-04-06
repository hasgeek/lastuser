# -*- coding: utf-8 -*-

from lastuserapp import db
import lastuser_core.models as models

from .test_db import TestDatabaseFixture


class TestScopeMixin(TestDatabaseFixture):
    def test_scopemixin__scope(self):
        """
        Test to retrieve scope on an ScopeMixin inherited class instance via _scope method
        """
        scope = 'id'
        bellatrix = models.User(username='bellatrix', fullname='Bellatrix Lestrange')
        auth_client = self.fixtures.auth_client
        bellatrix_token = models.AuthToken(
            auth_client=auth_client, user=bellatrix, scope=scope, validity=0
        )
        db.session.add_all([bellatrix, bellatrix_token])
        db.session.commit()
        self.assertEqual(bellatrix_token._scope, scope)

    def test_scopemixin_scope(self):
        """Test to retrieve scope on an ScopeMixin inherited class instance via scope method"""
        scope = 'tricks'
        ginny = models.User(username='ginny', fullname='Ginny Weasley')
        auth_client = self.fixtures.auth_client
        ginny_token = models.AuthToken(
            auth_client=auth_client, user=ginny, scope=scope, validity=0
        )
        db.session.add_all([ginny, ginny_token])
        db.session.commit()
        self.assertEqual(ginny_token.scope, (scope,))

    def test_scopemixin__scope_get(self):
        """Test to retrieve scope with __scope_get on an AuthToken instance """
        scope = ['teams', 'email', 'id']
        khal = models.User(username='khal', fullname='Khal Drogo')
        auth_client = self.fixtures.auth_client
        khal_token = models.AuthToken(
            auth_client=auth_client, user=khal, scope=scope, validity=0
        )
        db.session.add_all([khal, khal_token])
        db.session.commit()
        self.assertEqual(khal_token._scope_get(), tuple(sorted(scope)))

    def test_scopemixin__scope_set(self):
        """Test to set scope with __scope_set on an AuthToken instance"""
        """Test to retrieve scope with __scope_get on an AuthToken instance """
        scope = ['teams', 'wars', 'alliances']
        sansa = models.User(username='sansa', fullname='Sansa Stark')
        auth_client = self.fixtures.auth_client
        sansa_token = models.AuthToken(auth_client=auth_client, user=sansa, validity=0)
        sansa_token._scope_set(scope)
        db.session.add_all([sansa, sansa_token])
        db.session.commit()
        self.assertEqual(sansa_token._scope_get(), tuple(sorted(scope)))

    def test_scopemixin_add_scope(self):
        """
        Test for adding scope to a ScopeMixin inherited class instance
        """
        scope1 = 'spells'
        scope2 = 'charms'
        neville = models.User(username='neville', fullname='Neville Longbottom')
        auth_client = self.fixtures.auth_client
        neville_token = models.AuthToken(
            auth_client=auth_client, user=neville, validity=0, scope=scope1
        )
        db.session.add_all([neville, neville_token])
        neville_token.add_scope(scope2)
        self.assertEqual(neville_token.scope, (scope2, scope1))
