# -*- coding: utf-8 -*-

from lastuserapp import db
import lastuser_core.models as models

from .test_db import TestDatabaseFixture


class TestScopeMixin(TestDatabaseFixture):
    def test_scopemixin__scope(self):
        """
        Test to retrieve scope on an ScopeMixin inherited class instance via _scope method
        """
        scope = u'id'
        bellatrix = models.User(username=u'bellatrix', fullname=u'Bellatrix Lestrange')
        client = self.fixtures.client
        bellatrix_token = models.AuthToken(
            client=client, user=bellatrix, scope=scope, validity=0
        )
        db.session.add_all([bellatrix, bellatrix_token])
        db.session.commit()
        self.assertEqual(bellatrix_token._scope, scope)

    def test_scopemixin_scope(self):
        """Test to retrieve scope on an ScopeMixin inherited class instance via scope method"""
        scope = u'tricks'
        ginny = models.User(username=u'ginny', fullname=u'Ginny Weasley')
        client = self.fixtures.client
        ginny_token = models.AuthToken(
            client=client, user=ginny, scope=scope, validity=0
        )
        db.session.add_all([ginny, ginny_token])
        db.session.commit()
        self.assertEqual(ginny_token.scope, (scope,))

    def test_scopemixin__scope_get(self):
        """Test to retrieve scope with __scope_get on an AuthToken instance """
        scope = [u'teams', u'email', u'id']
        khal = models.User(username=u'khal', fullname=u'Khal Drogo')
        client = self.fixtures.client
        khal_token = models.AuthToken(client=client, user=khal, scope=scope, validity=0)
        db.session.add_all([khal, khal_token])
        db.session.commit()
        self.assertEqual(khal_token._scope_get(), tuple(sorted(scope)))

    def test_scopemixin__scope_set(self):
        """Test to set scope with __scope_set on an AuthToken instance"""
        """Test to retrieve scope with __scope_get on an AuthToken instance """
        scope = [u'teams', u'wars', u'alliances']
        sansa = models.User(username=u'sansa', fullname=u'Sansa Stark')
        client = self.fixtures.client
        sansa_token = models.AuthToken(client=client, user=sansa, validity=0)
        sansa_token._scope_set(scope)
        db.session.add_all([sansa, sansa_token])
        db.session.commit()
        self.assertEqual(sansa_token._scope_get(), tuple(sorted(scope)))

    def test_scopemixin_add_scope(self):
        """
        Test for adding scope to a ScopeMixin inherited class instance
        """
        scope1 = u'spells'
        scope2 = u'charms'
        neville = models.User(username=u'neville', fullname=u'Neville Longbottom')
        client = self.fixtures.client
        neville_token = models.AuthToken(
            client=client, user=neville, validity=0, scope=scope1
        )
        db.session.add_all([neville, neville_token])
        neville_token.add_scope(scope2)
        self.assertEqual(neville_token.scope, (scope2, scope1))
