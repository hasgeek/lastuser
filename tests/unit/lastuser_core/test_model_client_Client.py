# -*- coding: utf-8 -*-

from lastuserapp import db
import lastuser_core.models as models
from .test_db import TestDatabaseFixture
from datetime import datetime


class TestClient(TestDatabaseFixture):

    def test_client(self):
        """Test for verifying creation of instance of Client """
        # user, org, title, description, confidential, website, namespace, redirect_uri, notification_uri, active, allow_any_login, team_access, key, trusted
        holly = models.User(username=u'holly', fullname=u'Holiday Golightly')
        db.session.add(holly)
        sing_sing = models.Organization(name=u'sing_sing', title=u'Sing Sing')
        sing_sing.owners.users.append(holly)
        db.session.add(sing_sing)
        db.session.commit()
        title = u"Tiffany's"
        description = u"Breakfast at Tiffany's"
        website = u'tiffany.com'
        namespace = u'diamonds.tiffany.com'
        redirect_uri = u'tiffany.com/login/redirect'
        result = models.Client(title=title, org=sing_sing, confidential=True, namespace=namespace, website=website, description=description, redirect_uri=redirect_uri)
        db.session.add(result)
        db.session.commit()
        self.assertIsInstance(result, models.Client)
        self.assertEqual(result.org, sing_sing)
        self.assertEqual(result.title, title)
        self.assertEqual(result.description, description)
        self.assertEqual(result.website, website)
        self.assertEqual(result.namespace, namespace)
        self.assertEqual(result.redirect_uri, redirect_uri)
        self.assertTrue(result.confidential)

    def test_client_secret_is(self):
        """
        Test for checking if Client's secret is a ClientCredential
        """
        client = self.fixtures.client
        credentials = models.ClientCredential.new(client)
        self.assertTrue(client.secret_is(credentials[1], credentials[0].name))

    def test_client_host_matches(self):
        """
        Test for verifying client's host_matches method is able to
        split the referrer URL correctly
        """
        client = self.fixtures.client
        client.redirect_uri = u"http://hasjob.dev:5000"
        referrer = u"http://hasjob.dev:5000/logout"
        self.assertTrue(client.host_matches(referrer))

    def test_client_owner(self):
        """
        Test if client's owner is said Organization
        """
        owner = self.fixtures.client.owner
        batdog = self.fixtures.batdog
        self.assertIsInstance(owner, models.Organization)
        self.assertEqual(owner, batdog)

    def test_client_owner_is(self):
        """
        Test if client's owner is a user
        """
        client = self.fixtures.client
        crusoe = self.fixtures.crusoe
        with self.assertRaises(AttributeError):
            self.assertFalse(client.owner_is(self.fixtures.batdog))
        self.assertTrue(client.owner_is(crusoe))
        self.assertFalse(client.owner_is(None))

    def test_client_permissions(self):
        """
        Test for adding default view permission to client
        and if given user is owner of client, then add
        'edit', 'delete', 'assign-permissions' and 'new-resource'
        permissions.
        """
        crusoe = self.fixtures.crusoe
        client = self.fixtures.client
        permissions_expected_to_be_added = ['view', 'edit', 'delete', 'assign-permissions', 'new-resource']
        permissions_received = []
        result = client.permissions(crusoe)
        self.assertIsInstance(result, set)
        for each in result:
            permissions_received.append(each)
        self.assertItemsEqual(permissions_expected_to_be_added, permissions_received)

    def test_client_authtoken_for(self):
        """
        Test for retrieving authtoken for this user and client (only confidential clients)
        """
        # scenario 1: for a client that has confidential=True
        client = self.fixtures.client
        crusoe = self.fixtures.crusoe
        result = client.authtoken_for(crusoe)
        client_token = models.AuthToken(client=client, user=crusoe, scope=u'id', validity=0)
        result = client.authtoken_for(user=crusoe)
        self.assertIsInstance(result, models.AuthToken)

        # scenario 2: for a client that has confidential=False
        varys = models.User(username=u'varys', fullname=u'Lord Varys')
        house_lannisters = models.Client(title=u'House of Lannisters', confidential=False, user=varys, website=u'houseoflannisters.westeros')
        varys_session = models.UserSession(user=varys, ipaddr='192.168.1.99', user_agent=u'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.110 Safari/537.36', accessed_at=datetime.utcnow())
        lannisters_auth_token = models.AuthToken(client=house_lannisters, user=varys, scope=u'throne', validity=0, user_session=varys_session)
        db.session.add_all([varys,house_lannisters,lannisters_auth_token, varys_session])
        db.session.commit()
        result = house_lannisters.authtoken_for(varys, user_session=varys_session)
        self.assertIsInstance(result, models.AuthToken)

    def test_client_orgs_with_team_access(self):
        """
        Test for retrieving a list of organizations that this client has access to the teams of
        """
        batdog = self.fixtures.batdog
        client = self.fixtures.client
        result = client.orgs_with_team_access()
        self.assertIsInstance(result, list)
        self.assertItemsEqual(result, [batdog])

    def test_client_get(self):
        """
        Test for verifying Client's get method
        """
        client = self.fixtures.client
        batdog = self.fixtures.batdog
        key = client.key
        # scenario 1: when no key or namespace
        with self.assertRaises(TypeError):
            models.Client.get()
        # scenario 2: when given key
        result1 = models.Client.get(key)
        self.assertIsInstance(result1, models.Client)
        self.assertEqual(result1.key, key)
        self.assertEqual(result1.owner, batdog)
        # scenario 3: when given namespace
        namespace = u'fun.batdogadventures.com'
        result2 = models.Client.get(namespace=namespace)
        self.assertIsInstance(result2, models.Client)
        self.assertEqual(result2.namespace, namespace)
        self.assertEqual(result2.owner, batdog)
