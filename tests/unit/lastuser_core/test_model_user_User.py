# -*- coding: utf-8 -*-

from lastuserapp import db
import lastuser_core.models as models
from sqlalchemy.orm.collections import InstrumentedList
from datetime import datetime, timedelta
from .test_db import TestDatabaseFixture


class TestUser(TestDatabaseFixture):

    def test_User(self):
        """
        Test for creation of user object from User model
        """
        user = models.User(username=u'lena', fullname=u"Lena Audrey Dachshund")
        db.session.add_all([user])
        db.session.commit()
        lena = models.User.get(username=u'lena')
        self.assertIsInstance(lena, models.User)
        self.assertEqual(user.username, u'lena')
        self.assertEqual(user.fullname, u"Lena Audrey Dachshund")

    def test_user_is_valid_name(self):
        """
        Test to check if given is a valid username associated with the user
        """
        crusoe = self.fixtures.crusoe
        # scenario 1: not a valid username
        number_one = models.User(username=u'number1', fullname=u'Number One')
        self.assertFalse(number_one.is_valid_name(u'Number1'))
        # scenario 2: a valid username but not the username of instance passed
        self.assertFalse(crusoe.is_valid_name(u"oakley"))
        # scenario 3: a existing username
        self.assertTrue(crusoe.is_valid_name(u"crusoe"))
        # scenario 4: a existing org
        batdog = self.fixtures.batdog
        self.assertFalse(crusoe.is_valid_name(batdog.name))

    def test_user_profileid(self):
        """
        Test to verify profileid (same as username) if any
        """
        crusoe = self.fixtures.crusoe
        # scenario 1: when username is given
        self.assertEqual(crusoe.profileid(), crusoe.username)
        # scenario 2: when username doesn't exist
        mollie = models.User(fullname=u'Mollie')
        self.assertEqual(len(mollie.profileid()), 22)

    def test_user_displayname(self):
        """
        Test to verify any fullname or username or buid for displayname
        """
        crusoe = self.fixtures.crusoe
        oakley = self.fixtures.oakley
        self.assertEqual(crusoe.displayname(), crusoe.fullname)
        self.assertEqual(oakley.displayname(), oakley.username)
        lena = models.User()
        db.session.add(lena)
        db.session.commit()
        self.assertEqual(lena.displayname(), lena.buid)

    def test_user_pickername(self):
        """
        Test to verify fullname and username (if any)
        """
        # scenario 1: when username exists
        crusoe = self.fixtures.crusoe
        result = crusoe.pickername
        expected_result = u'{fullname} (@{username})'.format(fullname=crusoe.fullname, username=crusoe.username)
        self.assertEqual(result, expected_result)
        # scenario 2: when username doesnt exist
        mr_fedrick = models.User(fullname=u'Mr. Fedrick')
        result = mr_fedrick.pickername
        expected_result = u'{fullname}'.format(fullname=mr_fedrick.fullname)
        self.assertEqual(result, expected_result)

    def test_user_is_profile_complete(self):
        """
        Test to check if user profile is complete that is fullname, username
        and email are present
        """
        crusoe = self.fixtures.crusoe
        self.assertTrue(crusoe.is_profile_complete())
        lena = models.User()
        db.session.add(lena)
        db.session.commit()
        self.assertFalse(lena.is_profile_complete())

    def test_user_organization_owned(self):
        """
        Test for verifying organizations a user is a owner of
        """
        crusoe = self.fixtures.crusoe
        batdog = self.fixtures.batdog
        result = crusoe.organizations_owned()
        self.assertIsInstance(result, list)
        self.assertItemsEqual(result, [batdog])

    def test_user_organizations_owned_ids(self):
        """
        Test for verifying ids of organizations owned by a user
        """
        crusoe = self.fixtures.crusoe
        batdog = self.fixtures.batdog
        result = crusoe.organizations_owned_ids()
        self.assertIsInstance(result, list)
        self.assertItemsEqual(result, [batdog.id])

    def test_user_organizations(self):
        """
        Test for verifying organizations a user is a member of or owner
        """
        oakley = self.fixtures.oakley
        batdog = self.fixtures.batdog
        specialdachs = self.fixtures.specialdachs
        result = oakley.organizations()
        self.assertIsInstance(result, list)
        self.assertItemsEqual(result, [batdog, specialdachs])

    def test_user_organizations_memberof(self):
        """
        Test for verifying list of organizations this user is member of
        """
        oakley = self.fixtures.oakley
        batdog = self.fixtures.batdog
        result = oakley.organizations_memberof()
        self.assertIsInstance(result, list)
        self.assertItemsEqual(result, [batdog])

    def test_user_organizations_memberof_ids(self):
        """
        Test for verifying ids of organizations where a user is a *only* a member
        """
        oakley = self.fixtures.oakley
        batdog = self.fixtures.batdog
        result = oakley.organizations_memberof_ids()
        self.assertIsInstance(result, list)
        self.assertItemsEqual(result, [batdog.id])

    def test_user_available_permissions(self):
        """
        Test for verifying all permission objects available to a user
        (either owned by the user or available to all users)
        """
        crusoe = self.fixtures.crusoe
        bdfl = self.fixtures.bdfl
        result = crusoe.available_permissions()
        self.assertIsInstance(result, list)
        self.assertItemsEqual(result, [bdfl])
        self.assertEqual(result[0].owner, crusoe)
        self.assertEqual(result[0].title, bdfl.title)

    def test_User_username(self):
        """
        Test to retrieve User property username
        """
        crusoe = self.fixtures.crusoe
        result = crusoe.username
        self.assertIsInstance(result, unicode)
        self.assertEqual(crusoe.username, result)

    def test_user_email(self):
        """
        Test to retrieve UserEmail property email
        """
        # scenario 1: when there is primary email address
        crusoe = self.fixtures.crusoe
        self.assertIsInstance(crusoe.email, models.UserEmail)
        self.assertEqual(crusoe.email, crusoe.email)
        # scenario 2: when there is no primary email address
        mr_pilkington = models.User(username=u'pilkington')
        mr_pilkington_email = models.UserEmail(user=mr_pilkington, email=u'pilkington@animalfarm.co.uk')
        db.session.add_all([mr_pilkington, mr_pilkington_email])
        db.session.commit()
        self.assertEqual(mr_pilkington.email.email, mr_pilkington_email.email)
        self.assertTrue(mr_pilkington.email.primary)
        # scenario 3: when no email address is on db
        clover = models.User(username=u'clover')
        db.session.add(clover)
        db.session.commit()
        self.assertEqual(clover.email, u'')

    def test_user_del_email(self):
        """
        Test to delete email address for a user
        """
        mr_jones = models.User(username=u'mrjones')
        mr_jones_primary_email = models.UserEmail(email=u'mrjones@animalfarm.co.uk', primary=True, user=mr_jones)
        mr_jones_secondary_email = models.UserEmail(email=u'jones@animalfarm.co.uk', user=mr_jones)
        mr_jones_spare_email = models.UserEmail(email=u'j@animalfarm.co.uk', user=mr_jones)
        db.session.add_all([mr_jones, mr_jones_primary_email, mr_jones_secondary_email, mr_jones_spare_email])
        db.session.commit()
        # scenario 1: when email requested to be deleted is primary
        primary_email = mr_jones_primary_email.email
        mr_jones.del_email(primary_email)
        db.session.commit()
        result1 = mr_jones.emails
        self.assertIsInstance(result1, list)
        self.assertItemsEqual(result1, [mr_jones_secondary_email, mr_jones_spare_email])
        self.assertTrue(mr_jones_secondary_email.primary)
        # scenario 2: when email requested to be delete is not primary
        spare_email = mr_jones_spare_email.email
        mr_jones.del_email(spare_email)
        db.session.commit()
        result2 = mr_jones.emails
        self.assertIsInstance(result2, list)
        self.assertItemsEqual(result2, [mr_jones_secondary_email])
        self.assertTrue(mr_jones_secondary_email.primary)

    def test_user_phone(self):
        """
        Test to retrieve UserPhone property phone
        """
        # scenario 1: when there is a phone set as primary
        crusoe = self.fixtures.crusoe
        crusoe_phone = self.fixtures.crusoe_phone
        self.assertIsInstance(crusoe.phone, models.UserPhone)
        self.assertEqual(crusoe_phone, crusoe.phone)
        self.assertTrue(crusoe.phone.primary)
        # scenario 2: when there is a phone but not as primary
        snowball = models.User(username=u'snowball')
        snowball_phone = models.UserPhone(phone=u'+918574808032', user=snowball)
        db.session.add_all([snowball, snowball_phone])
        db.session.commit()
        self.assertIsInstance(snowball.phone, models.UserPhone)
        self.assertEqual(snowball_phone, snowball.phone)
        self.assertTrue(snowball.phone.primary)
        # scenario 3: when there is no phone on db
        piglet = self.fixtures.piglet
        assert piglet.phone is u''

    def test_user_password(self):
        """
        Test to set user password
        """
        # Scenario 1: Set None as password
        castle = models.User(username=u'castle', fullname=u'Rick Castle')
        castle.password = None
        self.assertEqual(castle.pw_hash, None)
        # Scenario 2: Set valid password
        kate = models.User(username=u'kate', fullname=u'Detective Kate Beckette')
        kate.password = u'12thprecinct'
        db.session.add(kate)
        db.session.commit()
        result = models.User.get(buid=kate.buid)
        self.assertEqual(len(result.pw_hash), 60)
        self.assertTrue(result.password_is(u'12thprecinct'))
        self.assertGreater(result.pw_expires_at, result.pw_set_at)

    def test_user_clients_with_team_access(self):
        """
        Test to verify a list of clients with access to the user's organizations' teams.
        """
        aro = models.User(username=u'aro')
        jane = models.User(username=u'jane')
        marcus = models.User(username=u'marcus')
        volturi = models.Organization(name=u'volturi', title=u'The Volturi')
        volturi.owners.users.append(aro)
        volturi.members.users.append(marcus)
        volturi.members.users.append(jane)
        volturi.make_teams()
        volterra = models.Client(title=u'Volterra, Tuscany', org=volturi, confidential=True, website=u'volterra.co.it')
        enforcers = models.Client(title=u'Volturi\'s thugs', org=volturi, confidential=True, website=u'volturi.co.it')
        volterra_auth_token = models.AuthToken(client=volterra, user=aro, scope=u'teams', validity=0)
        volterra_auth_token  # NOQA
        enforcers_auth_token = models.AuthToken(client=enforcers, user=marcus, scope=u'teams', validity=0)
        enforcers_auth_token  # NOQA
        self.assertItemsEqual(aro.clients_with_team_access(), [volterra])
        self.assertItemsEqual(marcus.clients_with_team_access(), [enforcers])
        self.assertEqual(jane.clients_with_team_access(), [])

    def test_user_password_has_expired(self):
        """
        Test to check if password for a user has expired
        """
        alexis = models.User(username=u'alexis', fullname=u'Alexis Castle')
        alexis.password = u'unfortunateincidents'
        alexis.pw_expires_at = datetime.utcnow() + timedelta(0, 0, 1)
        db.session.add(alexis)
        db.session.commit()
        result = models.User.get(buid=alexis.buid)
        self.assertIsNotNone(result)
        self.assertTrue(alexis.password_has_expired())

    def test_user_password_is(self):
        """
        Test to retrieve hashed password for a user
        """
        # scenario 1: no password been set
        oldmajor = models.User(username=u'oldmajor')
        self.assertFalse(oldmajor.password_is(u'oinkoink'))
        # scenario 3: if password has been set
        dumbeldore = models.User(u'dumbeldore', fullname=u'Albus Dumberldore')
        dumbeldore_password = u'dissendium'
        dumbeldore.password = dumbeldore_password
        self.assertTrue(dumbeldore.password_is(dumbeldore_password))

    def test_user_is_active(self):
        """
        Test for user's ACTIVE status
        where ACTIVE = 0 indicates a Regular, active user
        """
        crusoe = self.fixtures.crusoe
        self.assertEqual(crusoe.status, 0)
        oakley = models.User.get(username=u'oakley')
        oakley.status = 1
        self.assertEqual(oakley.status, 1)

    def test_User_autocomplete(self):
        """
        Test for User's autocomplete method
        """
        crusoe = self.fixtures.crusoe
        oakley = self.fixtures.oakley
        piglet = self.fixtures.piglet
        # lena = models.User.query.filter_by(username=u'lena').one_or_none()
        # FIXME # scenario 1: when empty query passed
        # result1 = models.User.autocomplete(u'*')
        # self.assertEqual(result1 or lena)
        # scenario 2: when query passed
        queries = [u"[oa]", u"Pig", "crusoe@keepballin.ca"]
        result2 = []
        for each in queries:
            result2.append(models.User.autocomplete(each))
        for result in result2:
            self.assertIsInstance(result, list)
            for each in result:
                self.assertIsInstance(each, models.User)
        query_for_oakley = models.User.autocomplete(queries[0])
        self.assertItemsEqual(query_for_oakley, [oakley])
        query_for_piglet = models.User.autocomplete(queries[1])
        self.assertItemsEqual(query_for_piglet, [piglet])
        query_for_crusoe = models.User.autocomplete(queries[2])
        self.assertItemsEqual(query_for_crusoe, [crusoe])

    def test_user_merged_user(self):
        """
        Test for checking if user had a old id
        """
        # ## Merge a user onto an older user ###
        crusoe = self.fixtures.crusoe
        crusoe2 = models.User(username=u"crusoe2", fullname=u"Crusoe2")
        db.session.add(crusoe2)
        db.session.commit()
        merged_user = models.merge_users(crusoe, crusoe2)
        db.session.commit()
        # ## DONE ###
        self.assertIsInstance(merged_user, models.User)
        # because the logic is to merge into older account so merge status set on newer account
        self.assertEqual(crusoe.status, 0)
        self.assertEqual(crusoe2.status, 2)
        self.assertEqual(merged_user.username, u"crusoe")
        self.assertIsInstance(merged_user.oldids, InstrumentedList)
        assert u'of User crusoe "Crusoe Celebrity Dachshund">' in repr(merged_user.oldids)

    def test_User_get(self):
        """
        Test for User's get method
        """
        # scenario 1: if both username and buid not passed
        with self.assertRaises(TypeError):
            models.User.get()
        crusoe = self.fixtures.crusoe
        piglet = self.fixtures.piglet
        # scenario 2: if buid is passed
        lookup_by_buid = models.User.get(buid=crusoe.buid)
        self.assertIsInstance(lookup_by_buid, models.client.User)
        self.assertEqual(lookup_by_buid.buid, crusoe.buid)
        # scenario 3: if username is passed
        lookup_by_username = models.User.get(username=u"crusoe")
        self.assertIsInstance(lookup_by_username, models.User)
        self.assertEqual(lookup_by_username.username, u"crusoe")
        # scenario 4: if defercols is set to True
        lookup_by_username = models.User.get(username=u"crusoe", defercols=True)
        self.assertIsInstance(lookup_by_username, models.User)
        self.assertEqual(lookup_by_username.username, u"crusoe")
        # scenario 5: when user.status is active
        lector = models.User()
        lector.status = models.USER_STATUS.ACTIVE
        db.session.add(lector)
        db.session.commit()
        lookup_by_buid_status = models.User.get(buid=lector.buid)
        self.assertIsInstance(lookup_by_buid_status, models.User)
        self.assertEqual(lookup_by_buid_status.status, lector.status)
        # scenario 6 : when user.status is USER_STATUS.MERGED
        piglet = self.fixtures.piglet
        piggy = models.User(username=u'piggy')
        db.session.add(piggy)
        db.session.commit()
        merged_user = models.merge_users(piglet, piggy)
        merged_user  # NOQA
        db.session.commit()
        lookup_by_buid_merged = models.User.get(buid=piggy.buid)
        self.assertIsInstance(lookup_by_buid_merged, models.User)
        self.assertEqual(lookup_by_buid_merged.username, piglet.username)

    def test_User_all(self):
        """
        Test for User's all method
        """
        # scenario 1: when neither buids or usernames are passed
        with self.assertRaises(Exception):
            models.User.all()
        crusoe = self.fixtures.crusoe
        oakley = self.fixtures.oakley
        expected_result = [crusoe, oakley]
        # scenario 2: when both buids and usernames are passed
        lookup_by_both = models.User.all(buids=[crusoe.buid], usernames=[oakley.username])
        self.assertIsInstance(lookup_by_both, list)
        self.assertItemsEqual(lookup_by_both, expected_result)
        # scenario 3: when only buids are passed
        lookup_by_buids = models.User.all(buids=[crusoe.buid, oakley.buid])
        self.assertIsInstance(lookup_by_buids, list)
        self.assertItemsEqual(lookup_by_buids, expected_result)
        # scenario 4: when only usernames are passed
        lookup_by_usernames = models.User.all(usernames=[crusoe.username, oakley.username])
        self.assertIsInstance(lookup_by_usernames, list)
        self.assertItemsEqual(lookup_by_usernames, expected_result)
        # scenario 5: when defercols is set to True
        lookup_by_usernames_defercols = models.User.all(usernames=[crusoe.username, oakley.username], defercols=True)
        lookup_by_usernames_defercols  # NOQA
        self.assertIsInstance(lookup_by_usernames, list)
        self.assertItemsEqual(lookup_by_usernames, expected_result)
        # scenario 6: when user.status is active
        hannibal = models.User(username=u'hannibal')
        hannibal.status = models.USER_STATUS.ACTIVE
        db.session.add(hannibal)
        db.session.commit()
        lookup_by_buid_status = models.User.all(usernames=[hannibal.username])
        self.assertIsInstance(lookup_by_buid_status, list)
        self.assertEqual(lookup_by_buid_status[0].status, hannibal.status)
        # scenario 7 : when user.status is USER_STATUS.MERGED
        jykll = models.User()
        hyde = models.User()
        db.session.add_all([jykll, hyde])
        db.session.commit()
        merged_user = models.merge_users(jykll, hyde)
        merged_user  # NOQA
        db.session.commit()
        lookup_by_buid_merged = models.User.all(buids=[hyde.buid])
        self.assertIsInstance(lookup_by_buid_merged, list)
        self.assertEqual(lookup_by_buid_merged[0].username, jykll.username)

    def test_user_add_email(self):
        """
        Test to add email address for a user
        """
        # scenario 1: if primary flag is True and user has no existing email
        mr_whymper = models.User(username=u'whymper')
        whymper_email = u'whmmm@animalfarm.co.uk'
        whymper_result = mr_whymper.add_email(whymper_email, primary=True)
        self.assertEqual(whymper_result.email, whymper_email)
        # # scenario 2: when primary flag is True but user has existing primary email
        crusoe = self.fixtures.crusoe
        crusoe_new_email = u'crusoe@batdog.ca'
        crusoe_result = crusoe.add_email(email=crusoe_new_email, primary=True)
        self.assertEqual(crusoe_result.email, crusoe_new_email)
        # # scenario 3: when primary flag is True but user has existing email same as one passed
        crusoe_existing_email = u'crusoe@keepballin.ca'
        crusoe_result = crusoe.add_email(crusoe_existing_email, primary=True)
        self.assertEqual(crusoe_result.email, crusoe_existing_email)
        # scenario 4: when requested to adds an email with domain belonging to a team, add user to team
        gustav = models.User(username=u'gustav')
        gustav_email = u'g@keepballin.ca'
        gustav_result = gustav.add_email(gustav_email)
        db.session.add(gustav)
        db.session.commit()
        self.assertEqual(gustav_result.email, gustav_email)

    def test_make_email_primary(self):
        """
        Test to make an email primary for a user
        """
        mr_whymper = models.User(username=u'whymmper')
        whymper_email = u'whmmmm@animalfarm.co.uk'
        whymper_result = mr_whymper.add_email(whymper_email)
        mr_whymper.primary_email = whymper_result
        self.assertEqual(whymper_result.email, whymper_email)
        self.assertEqual(whymper_result.primary, True)
