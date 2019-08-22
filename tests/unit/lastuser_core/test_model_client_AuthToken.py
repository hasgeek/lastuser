# -*- coding: utf-8 -*-

from datetime import timedelta

from coaster.utils import buid, utcnow
from lastuserapp import db
import lastuser_core.models as models

from .test_db import TestDatabaseFixture


class TestAuthToken(TestDatabaseFixture):
    def test_authtoken_init(self):
        """
        Test for verifying creation of AuthToken instance
        note: Only one authtoken per user and client
        """
        client = self.fixtures.client
        crusoe = self.fixtures.crusoe
        result = models.AuthToken(client=client, user=crusoe, scope=u'id', validity=0)
        self.assertIsInstance(result, models.AuthToken)
        self.assertEqual(result.user, crusoe)
        self.assertEqual(result.client, client)

    def test_authtoken_refresh(self):
        """Test to verify creation of new token while retaining the refresh token."""
        hagrid = models.User(username=u'hagrid', fullname=u'Rubeus Hagrid')
        auth_token = models.AuthToken(user=hagrid, algorithm='hmac-sha-1')
        existing_token = auth_token.token
        existing_secret = auth_token.secret
        auth_token.refresh()
        self.assertNotEqual(existing_token, auth_token.token)
        self.assertNotEqual(existing_secret, auth_token.secret)

    def test_authtoken_is_valid(self):
        """
        Test for verifying if AuthToken's token is valid
        """
        client = self.fixtures.client
        # scenario 1: when validity is unlimited (0)
        tomriddle = models.User(username=u'voldemort', fullname=u'Tom Riddle')
        scope = [u'id', u'email']
        tomriddle_token = models.AuthToken(
            client=client, user=tomriddle, scope=scope, validity=0
        )
        self.assertTrue(tomriddle_token.is_valid())

        # scenario 2: when validity has not been given
        draco = models.User(username=u'draco', fullname=u'Draco Malfoy')
        draco_token = models.AuthToken(client=client, user=draco, scope=scope)
        with self.assertRaises(TypeError):
            draco_token.is_valid()

        # scenario 3: when validity is limited
        harry = models.User(username=u'harry', fullname=u'Harry Potter')
        harry_token = models.AuthToken(
            client=client, user=harry, scope=scope, validity=3600, created_at=utcnow()
        )
        self.assertTrue(harry_token.is_valid())

        # scenario 4: when validity is limited *and* the token has expired
        cedric = models.User(username=u'cedric', fullname=u'Cedric Diggory')
        cedric_token = models.AuthToken(
            client=client,
            user=cedric,
            scope=scope,
            validity=1,
            created_at=utcnow() - timedelta(1),
        )
        self.assertFalse(cedric_token.is_valid())

    def test_authtoken_get(self):
        """
        Test for retreiving a AuthToken instance given a token
        """
        specialdachs = self.fixtures.specialdachs
        oakley = self.fixtures.oakley
        scope = [u'id']
        dachsadv = models.Client(
            title=u"Dachshund Adventures",
            org=specialdachs,
            confidential=True,
            website=u"http://dachsadv.com",
        )
        auth_token = models.AuthToken(client=dachsadv, user=oakley, scope=scope)
        token = auth_token.token
        db.session.add(dachsadv, auth_token)
        result = models.AuthToken.get(token)
        self.assertIsInstance(result, models.AuthToken)
        self.assertEqual(result.client, dachsadv)

    def test_authtoken_all(self):
        """
        Test for retreiving all AuthToken instances for given users
        """
        client = self.fixtures.client

        # scenario 1: When users passed are an instance of Query class
        hermione = models.User(username=u'herminone', fullname=u'Hermione Granger')
        herminone_token = models.AuthToken(client=client, user=hermione, scope=[u'id'])
        myrtle = models.User(username=u'myrtle', fullname=u'Moaning Myrtle')
        myrtle_token = models.AuthToken(client=client, user=myrtle, scope=[u'id'])
        alastor = models.User(username=u'alastor', fullname=u'Alastor Moody')
        alastor_token = models.AuthToken(client=client, user=alastor, scope=[u'id'])
        greyback = models.User(username=u'greyback', fullname=u'Fenrir Greyback')
        greyback_token = models.AuthToken(client=client, user=greyback, scope=[u'id'])
        pottermania = models.Organization(name=u'pottermania', title=u'Pottermania')
        pottermania.owners.users.append(hermione)
        pottermania_members = [hermione, alastor, greyback, myrtle]
        for member in pottermania_members:
            pottermania.members.users.append(member)
        db.session.add_all(
            [
                myrtle,
                myrtle_token,
                hermione,
                herminone_token,
                alastor,
                alastor_token,
                greyback,
                greyback_token,
                pottermania,
            ]
        )
        db.session.commit()

        # scenario 1 and count == 1
        result1 = models.AuthToken.all(pottermania.owners.users)
        self.assertIsInstance(result1, list)
        self.assertIsInstance(result1[0], models.AuthToken)
        self.assertItemsEqual(result1, [herminone_token])

        # scenario 1 and count > 1
        result2 = models.AuthToken.all(pottermania.members.users)
        self.assertIsInstance(result2, list)
        for each in result2:
            self.assertIsInstance(each, models.AuthToken)
        self.assertItemsEqual(
            result2, [herminone_token, alastor_token, greyback_token, myrtle_token]
        )

        # Scenario 2: When users passed are not an instance of Query class
        lily = models.User(username=u'lily', fullname=u'Lily Evans Potter')
        cho = models.User(username=u'cho', fullname=u'Cho Chang')
        lily_token = models.AuthToken(client=client, user=lily, scope=[u'memories'])
        cho_token = models.AuthToken(client=client, user=cho, scope=[u'charms'])
        db.session.add_all([lily, lily_token, cho, cho_token])
        db.session.commit()

        # scenario 2 and count == 1
        result3 = models.AuthToken.all([lily])
        self.assertIsInstance(result3, list)
        self.assertIsInstance(result3[0], models.AuthToken)
        self.assertItemsEqual(result3, [lily_token])

        # scenario 2 and count > 1
        result4 = models.AuthToken.all([lily, cho])
        self.assertIsInstance(result4, list)
        for each in result4:
            self.assertIsInstance(each, models.AuthToken)
        self.assertItemsEqual(result4, [lily_token, cho_token])

        # scenario 5: When user instances passed don't have any AuthToken against them
        oakley = self.fixtures.oakley
        piglet = self.fixtures.piglet
        users = [piglet, oakley]
        result5 = models.AuthToken.all(users)
        self.assertListEqual(result5, [])

    def test_authtoken_user(self):
        """
        Test for checking AuthToken's user property
        """
        crusoe = self.fixtures.crusoe
        client = self.fixtures.client

        user_session = models.UserSession(buid=buid(), user=crusoe)
        auth_token_with_user_session = models.AuthToken(
            user=crusoe, user_session=user_session
        )
        self.assertIsInstance(
            auth_token_with_user_session.user_session.user, models.User
        )
        self.assertEqual(auth_token_with_user_session.user_session.user, crusoe)

        auth_token_without_user_session = models.AuthToken(client=client, user=crusoe)
        self.assertIsInstance(auth_token_without_user_session._user, models.User)
        self.assertEqual(auth_token_without_user_session._user, crusoe)

    # def test_authtoken_migrate_user(self):
    #     """
    #     FIXME: Test for migrating user who has an AuthToken issued
    #     """
    #     piglet = self.fixtures.piglet
    #     specialdachs = self.fixtures.specialdachs
    #     scope_piglet = [u'id', u'email']
    #     londontales = models.Client(title=u'London tales', org=specialdachs, confidential=True, website=u'http://londondachtales.uk')
    #     auth_token = models.AuthToken(client=londontales, user=piglet, scope=scope_piglet, validity=0)
    #     token = auth_token.token
    #
    #     db.session.add(auth_token)
    #     db.session.add(londontales)
    #     piggles = models.User(username=u"piggles")
    #     naughtymonkey = models.User(username=u"naughtymonkey")
    #     db.session.add(piggles)
    #     db.session.add(naughtymonkey)
    #     db.session.commit()
    #
    #     # Scenario: When only one user has authtokens associated with them
    #     models.AuthToken.migrate_user(piglet, naughtymonkey)
    #     scope_received_piglet = models.AuthToken.get(token).scope
    #     self.assertItemsEqual(scope_received_piglet, tuple(scope_piglet))
    #
    #     # Scenario: There's a existing token for newuser with the same client,
    #     # then we expect to: newtoken to have extended scope
    #     scope_piggles = [u'teams']
    #     another_auth_token = models.AuthToken(client=londontales, user=piggles, scope=scope_piggles)
    #     db.session.add(another_auth_token)
    #     db.session.commit()
    #     models.AuthToken.migrate_user(piglet, piggles)
    #     scope_received = models.AuthToken.get(another_auth_token.token).scope
    #     scope_expected = tuple(set(scope_piglet + scope_piggles))
    #     self.assertItemsEqual(scope_received, scope_expected)

    def test_authtoken_algorithm(self):
        """
        Test for checking AuthToken's algorithm property
        """
        snape = models.User(username=u'snape', fullname=u'Professor Severus Snape')
        valid_algorithm = 'hmac-sha-1'
        auth_token = models.AuthToken(user=snape)
        auth_token.algorithm = None
        self.assertIsNone(auth_token._algorithm)
        auth_token.algorithm = valid_algorithm
        self.assertEqual(auth_token._algorithm, valid_algorithm)
        self.assertEqual(auth_token.algorithm, valid_algorithm)
        with self.assertRaises(ValueError):
            auth_token.algorithm = "hmac-sha-2016"
