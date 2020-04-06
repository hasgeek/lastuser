# -*- coding: utf-8 -*-

from coaster.utils import utcnow
from lastuserapp import db
import lastuser_core.models as models

from .test_db import TestDatabaseFixture


class TestClient(TestDatabaseFixture):
    def test_client_secret_is(self):
        """
        Test for checking if Client's secret is a ClientCredential
        """
        auth_client = self.fixtures.auth_client
        credentials = models.AuthClientCredential.new(auth_client)
        self.assertTrue(auth_client.secret_is(credentials[1], credentials[0].name))

    def test_client_host_matches(self):
        """
        Test for verifying client's host_matches method is able to
        split the referrer URL correctly
        """
        auth_client = self.fixtures.auth_client
        auth_client.redirect_uris = ["http://hasjob.dev:5000"]
        referrer = "http://hasjob.dev:5000/logout"
        self.assertTrue(auth_client.host_matches(referrer))

    def test_client_owner(self):
        """
        Test if client's owner is said Organization
        """
        owner = self.fixtures.auth_client.owner
        batdog = self.fixtures.batdog
        self.assertIsInstance(owner, models.Organization)
        self.assertEqual(owner, batdog)

    def test_client_owner_is(self):
        """
        Test if client's owner is a user
        """
        auth_client = self.fixtures.auth_client
        crusoe = self.fixtures.crusoe
        with self.assertRaises(AttributeError):
            self.assertFalse(auth_client.owner_is(self.fixtures.batdog))
        self.assertTrue(auth_client.owner_is(crusoe))
        self.assertFalse(auth_client.owner_is(None))

    def test_client_permissions(self):
        """
        Test for adding default view permission to client
        and if given user is owner of client, then add
        'edit', 'delete', 'assign-permissions' and 'new-resource'
        permissions.
        """
        crusoe = self.fixtures.crusoe
        auth_client = self.fixtures.auth_client
        permissions_expected_to_be_added = [
            'view',
            'edit',
            'delete',
            'assign-permissions',
            'new-resource',
        ]
        permissions_received = []
        result = auth_client.permissions(crusoe)
        self.assertIsInstance(result, set)
        for each in result:
            permissions_received.append(each)
        self.assertCountEqual(permissions_expected_to_be_added, permissions_received)

    def test_client_authtoken_for(self):
        """
        Test for retrieving authtoken for this user and client (only confidential clients)
        """
        # scenario 1: for a client that has confidential=True
        auth_client = self.fixtures.auth_client
        crusoe = self.fixtures.crusoe
        result = auth_client.authtoken_for(crusoe)
        client_token = models.AuthToken(
            auth_client=auth_client, user=crusoe, scope='id', validity=0
        )
        result = auth_client.authtoken_for(user=crusoe)
        self.assertEqual(client_token, result)
        self.assertIsInstance(result, models.AuthToken)
        assert result.user == crusoe

        # scenario 2: for a client that has confidential=False
        varys = models.User(username='varys', fullname='Lord Varys')
        house_lannisters = models.AuthClient(
            title='House of Lannisters',
            confidential=False,
            user=varys,
            website='houseoflannisters.westeros',
        )
        varys_session = models.UserSession(
            user=varys,
            ipaddr='192.168.1.99',
            user_agent='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.110 Safari/537.36',
            accessed_at=utcnow(),
        )
        lannisters_auth_token = models.AuthToken(
            auth_client=house_lannisters,
            user=varys,
            scope='throne',
            validity=0,
            user_session=varys_session,
        )
        db.session.add_all(
            [varys, house_lannisters, lannisters_auth_token, varys_session]
        )
        db.session.commit()
        result = house_lannisters.authtoken_for(varys, user_session=varys_session)
        self.assertIsInstance(result, models.AuthToken)
        assert "Lord Varys" == result.user.fullname

    def test_client_get(self):
        """
        Test for verifying Client's get method
        """
        auth_client = self.fixtures.auth_client
        batdog = self.fixtures.batdog
        key = auth_client.buid
        # scenario 1: when no key or namespace
        with self.assertRaises(TypeError):
            models.AuthClient.get()
        # scenario 2: when given key
        result1 = models.AuthClient.get(key)
        self.assertIsInstance(result1, models.AuthClient)
        self.assertEqual(result1.buid, key)
        self.assertEqual(result1.owner, batdog)
        # scenario 3: when given namespace
        namespace = 'fun.batdogadventures.com'
        result2 = models.AuthClient.get(namespace=namespace)
        self.assertIsInstance(result2, models.AuthClient)
        self.assertEqual(result2.namespace, namespace)
        self.assertEqual(result2.owner, batdog)
