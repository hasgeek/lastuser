# -*- coding: utf-8 -*-

from sqlalchemy.exc import IntegrityError

from lastuserapp import db
import lastuser_core.models as models

from .test_db import TestDatabaseFixture


class TestName(TestDatabaseFixture):
    def test_is_available_name(self):
        """
        Names are only available if valid and unused
        """
        assert models.Name.is_available_name('invalid_name') is False
        # 'piglet' is a name taken in the fixtures
        assert models.Name.get('piglet') is not None
        assert models.Name.is_available_name('piglet') is False
        assert models.Name.is_available_name('peppa') is True

    def test_validate_name_candidate(self):
        """
        The name validator returns error codes as expected
        """
        assert models.Name.validate_name_candidate(None) == 'blank'
        assert models.Name.validate_name_candidate('') == 'blank'
        assert models.Name.validate_name_candidate('invalid_name') == 'invalid'
        assert models.Name.validate_name_candidate('0123456789' * 7) == 'long'
        assert models.Name.validate_name_candidate('0123456789' * 6) is None
        assert models.Name.validate_name_candidate('test-reserved') is None
        db.session.add(models.Name(name=u'test-reserved', reserved=True))
        db.session.commit()
        assert models.Name.validate_name_candidate('test-reserved') == 'reserved'
        assert models.Name.validate_name_candidate('piglet') == 'user'
        assert models.Name.validate_name_candidate('batdog') == 'org'

    def test_reserved_name(self):
        """
        Names can be reserved, with no user or organization
        """
        reserved_name = models.Name(name=u'reserved-name', reserved=True)
        db.session.add(reserved_name)
        db.session.commit()
        retrieved_name = models.Name.get(u'reserved-name')
        assert retrieved_name is reserved_name
        assert reserved_name.user is None
        assert reserved_name.user_id is None
        assert reserved_name.org is None
        assert reserved_name.org_id is None

    def test_unassigned_name(self):
        """
        Names must be assigned to a user or organization if not reserved
        """
        unassigned_name = models.Name(name=u'unassigned')
        db.session.add(unassigned_name)
        with self.assertRaises(IntegrityError):
            db.session.commit()

    def test_double_assigned_name(self):
        """
        Names cannot be assigned to both a user and an organization simultaneously
        """
        user = models.User(fullname=u"User")
        org = models.Organization(title=u"Organization")
        name = models.Name(name=u'double-assigned', user=user, org=org)
        db.session.add_all([user, org, name])
        with self.assertRaises(IntegrityError):
            db.session.commit()

    def test_user_two_names(self):
        """
        A user cannot have two names
        """
        assert self.fixtures.piglet.username == u'piglet'
        peppa = models.Name(name=u'peppa', user=self.fixtures.piglet)
        db.session.add(peppa)
        with self.assertRaises(IntegrityError):
            db.session.commit()

    def test_org_two_names(self):
        """
        An organization cannot have two names
        """
        assert self.fixtures.batdog.name == u'batdog'
        bathound = models.Name(name=u'bathound', org=self.fixtures.batdog)
        db.session.add(bathound)
        with self.assertRaises(IntegrityError):
            db.session.commit()

    def test_remove_name(self):
        """
        Removing a name from a user or org also removes it from the Name table
        """
        assert self.fixtures.oakley.username == u'oakley'
        assert models.Name.get(u'oakley') is not None
        self.fixtures.oakley.username = None
        db.session.commit()
        assert models.Name.get(u'oakley') is None

        assert self.fixtures.specialdachs.name == u'specialdachs'
        assert models.Name.get(u'specialdachs') is not None
        self.fixtures.specialdachs.name = None
        db.session.commit()
        assert models.Name.get(u'specialdachs') is None

    def test_name_transfer(self):
        assert self.fixtures.nameless.username is None
        assert models.Name.get(u'newname') is None
        newname = models.User(username=u'newname', fullname="New Name")
        db.session.add(newname)
        db.session.commit()
        assert models.Name.get(u'newname') is not None
        assert newname.username == u'newname'

        merged = models.merge_users(self.fixtures.nameless, newname)
        assert merged is not newname
        assert merged is self.fixtures.nameless
        assert newname.username is None
        assert merged.username == u'newname'
        assert self.fixtures.nameless.username == u'newname'
