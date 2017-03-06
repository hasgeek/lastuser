# -*- coding: utf-8 -*-

from lastuserapp import db, init_for
import lastuser_core.models as models
from .test_db import TestDatabaseFixture
from datetime import datetime as dt
from coaster.utils import buid
from datetime import datetime, timedelta
from flask.testing import FlaskClient
from flask import url_for
from bs4 import BeautifulSoup


class TestUser(TestDatabaseFixture):

    def test_UserSession_init(self):
        """Test to verify the creation of UserSession instance"""
        result = models.UserSession()
        self.assertIsInstance(result, models.UserSession)

    def test_usersession_ua(self):
        """Test to verify user_agent property of UserSession instance"""
        ua=u'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.110 Safari/537.36'
        another_user_session = models.UserSession(user_agent=ua)
        self.assertIsInstance(another_user_session.ua, dict)

    def test_usersession_has_sudo(self):
        """Test to set sudo and test if UserSession instance has_sudo """
        crusoe = self.fixtures.crusoe
        another_user_session = models.UserSession(user=crusoe, ipaddr='192.168.1.1', user_agent=u'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.110 Safari/537.36', accessed_at=datetime.utcnow())
        another_user_session.set_sudo()
        db.session.add(another_user_session)
        db.session.commit()
        self.assertTrue(another_user_session.has_sudo)

    def test_usersession_revoke(self):
        """Test to revoke on UserSession instance"""
        crusoe = self.fixtures.crusoe
        yet_another_usersession = models.UserSession(user=crusoe, ipaddr='192.168.1.1', user_agent=u'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.110 Safari/537.36', accessed_at=datetime.utcnow())
        yet_another_usersession.revoke()
        result = models.UserSession.query.filter_by(buid=yet_another_usersession.buid).one_or_none()
        self.assertIsNotNone(result.revoked_at)

    def test_UserSession_get(self):
        """Test for verifying UserSession's get method"""
        oakley = self.fixtures.oakley
        oakley_buid = buid()
        oakley_session = models.UserSession(user=oakley, ipaddr='192.168.1.2', buid=oakley_buid, user_agent=u'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.110 Safari/537.36', accessed_at=datetime.utcnow())
        result = oakley_session.get(buid=oakley_buid)
        self.assertIsInstance(result, models.UserSession)
        self.assertEqual(result.user_id, oakley.id)

    def test_usersession_active_sessions(self):
        "Test for verifying UserSession's active_sessions"
        piglet = self.fixtures.piglet
        piglet_session = models.UserSession(user=piglet, ipaddr='192.168.1.3', buid=buid(), user_agent=u'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.110 Safari/537.36', accessed_at=datetime.utcnow())
        self.assertIsInstance(piglet.active_sessions(), list)
        self.assertItemsEqual(piglet.active_sessions(), [piglet_session])

    def test_UserSession_authenticate(self):
        """Test to verify authenticate method on UserSession"""
        chandler = models.User(username=u'chandler', fullname=u'Chandler Bing')
        chandler_buid=buid()
        chandler_session = models.UserSession(user=chandler, ipaddr='192.168.1.4', buid=chandler_buid, user_agent=u'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.110 Safari/537.36', accessed_at=datetime.utcnow())
        db.session.add(chandler)
        db.session.add(chandler_session)
        db.session.commit()
        result = models.UserSession.authenticate(chandler_buid)
        self.assertIsInstance(result, models.UserSession)
        self.assertEqual(result, chandler_session)

    # def test_usersession_access(self):
    #     """Test to verify access method on UserSession instance"""
    #     # put app context to Flask stack
    #     self.ctx = self.app.test_request_context()
    #     self.ctx.push()
    #
    #     # # scenario 0: when client is None
    #     # phoebe = models.User(username=u'phoebe', fullname=u'Phoebe Buffay')
    #     # phoebe._set_password(u'smellycat')
    #     # db.session.add(phoebe)
    #     # db.session.commit()
    #     # # Simulate a login
    #     # test_client = self.fixtures.test_client
    #     # with test_client as l:
    #     #     response = l.get(url_for('login'))
    #     #     soup = BeautifulSoup(response.data, 'html.parser')
    #     #     csrf_token = soup.find(id='csrf_token')['value']
    #     #     headers={'origin':url_for('login')}
    #     #     cookies = response.headers.get_all('Set-Cookie')
    #     #     headers['Set-Cookie'] = "".join(cookies)
    #     #     body={'password':u'smellycat','username':u'phoebe', 'csrf_token': csrf_token, 'form.id': 'passwordlogin'}
    #     #     response = l.post(url_for('login'), headers=headers, data=body, follow_redirects=True)
    #     #     result = models.UserSession.query.filter_by(user=phoebe).all()
    #     #     result[0].access()
    #     # self.assertEqual(result[0].ipaddr, u'')
    #     # self.assertEqual(result[0].user_agent, u'')
    #
    #     # scenario 1: when client is not registered on user
    #     joey = models.User(username=u'joey', fullname=u'Joey Tribiani')
    #     joey._set_password(u'howyoudoin')
    #     actorsguild = models.Organization(name=u'actorsguild', title=u'Actors Guild')
    #     actorsguild.members.users.append(joey)
    #     daysofourlives = models.Client(title=u'Days of Our Lives', org=actorsguild, confidential=False, website=u'daysofourlives.nyc')
    #     db.session.add(joey)
    #     db.session.add(daysofourlives)
    #     db.session.add(actorsguild)
    #     db.session.commit()
    #     # Simulate a login
    #     test_client = self.fixtures.test_client
    #     with test_client as l:
    #         response = l.get(url_for('login'))
    #         soup = BeautifulSoup(response.data, 'html.parser')
    #         csrf_token = soup.find(id='csrf_token')['value']
    #         headers={'origin':url_for('login')}
    #         cookies = response.headers.get_all('Set-Cookie')
    #         headers['Set-Cookie'] = "".join(cookies)
    #         body={'password':u'howyoudoin','username':u'joey', 'csrf_token': csrf_token, 'form.id': 'passwordlogin'}
    #         response = l.post(url_for('login'), headers=headers, data=body, follow_redirects=True)
    #         result = models.UserSession.query.filter_by(user=joey).all()
    #         print result[0].user.clients
    #
    #     # Pop app context
    #     self.ctx.pop()
    #     # # scenario 2: when client *is* registered on user
