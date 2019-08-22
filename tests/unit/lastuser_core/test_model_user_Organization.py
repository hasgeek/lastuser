# -*- coding: utf-8 -*-

from lastuserapp import db
import lastuser_core.models as models

from .test_db import TestDatabaseFixture


class TestOrganization(TestDatabaseFixture):
    def test_organization_init(self):
        """
        Test for initializing a Organization instance
        """
        name = u'dachshunited'
        title = u'Dachshunds United'
        dachsunited = models.Organization(name=name, title=title)
        self.assertIsInstance(dachsunited, models.Organization)
        self.assertEqual(dachsunited.title, title)
        self.assertEqual(dachsunited.name, name)

    def test_organization_make_teams(self):
        """
        Test for verifying the creation of default Teams: owners and members
        """
        crusoe = self.fixtures.crusoe
        oakley = self.fixtures.oakley
        piglet = self.fixtures.piglet
        name = u'dachshunited'
        title = u'Dachshunds United'
        dachsunited = models.Organization(name=name, title=title)
        # Scenario: before any users were added to the organization
        self.assertIsInstance(dachsunited.owners, models.Team)
        self.assertIsInstance(dachsunited.members, models.Team)
        self.assertEqual(dachsunited.owners.users.all(), [])
        self.assertEqual(dachsunited.members.users.all(), [])
        with self.assertRaises(TypeError):
            dachsunited.members.get()
        # After adding users to the organization
        dachsunited.owners.users.append(crusoe)
        dachsunited.members.users.append(oakley)
        dachsunited.members.users.append(piglet)
        assert u'<Team Owners of Organization {name} "{title}">'.format(
            name=name, title=title
        ) in repr(dachsunited.owners)
        assert u'<Team Members of Organization {name} "{title}">'.format(
            name=name, title=title
        ) in repr(dachsunited.members)

    def test_organization_get(self):
        """
        Test for retrieving an organization
        """
        name = u'spew'
        title = u'S.P.E.W'
        spew = models.Organization(name=name, title=title)
        db.session.add(spew)
        db.session.commit()
        # scenario 1: when neither name or buid are passed
        with self.assertRaises(TypeError):
            models.Organization.get()
        # scenario 2: when buid is passed
        buid = spew.buid
        get_by_buid = models.Organization.get(buid=buid)
        self.assertIsInstance(get_by_buid, models.Organization)
        assert u'<Organization' in repr(get_by_buid)
        assert u'"{title}">'.format(title=title) in repr(get_by_buid)
        # scenario 3: when username is passed
        get_by_name = models.Organization.get(name=name)
        self.assertIsInstance(get_by_name, models.Organization)
        assert u'<Organization {name} "{title}">'.format(
            name=name, title=title
        ) in repr(get_by_name)
        # scenario 4: when defercols is set to True
        get_by_name_with_defercols = models.Organization.get(name=name, defercols=True)
        self.assertIsInstance(get_by_name_with_defercols, models.Organization)
        assert u'<Organization {name} "{title}">'.format(
            name=name, title=title
        ) in repr(get_by_name_with_defercols)

    def test_organization_all(self):
        """
        Test for getting all organizations (takes buid or name optionally)
        """
        gryffindor = models.Organization(name=u'gryffindor')
        ravenclaw = models.Organization(name=u'ravenclaw')
        db.session.add(gryffindor)
        db.session.add(ravenclaw)
        db.session.commit()
        # scenario 1: when neither buids nor names are given
        self.assertEqual(models.Organization.all(), [])
        # scenario 2: when buids are passed
        orglist = [gryffindor, ravenclaw]
        orgids = [gryffindor.buid, ravenclaw.buid]
        all_by_buids = models.Organization.all(buids=orgids)
        self.assertIsInstance(all_by_buids, list)
        self.assertItemsEqual(all_by_buids, orglist)
        # scenario 3: when org names are passed
        names = [gryffindor.name, ravenclaw.name]
        all_by_names = models.Organization.all(names=names)
        self.assertIsInstance(all_by_names, list)
        self.assertItemsEqual(all_by_names, orglist)
        # scenario 4: when defercols is set to True for names
        all_by_names_with_defercols = models.Organization.all(names=names)
        self.assertIsInstance(all_by_names_with_defercols, list)
        self.assertItemsEqual(all_by_names_with_defercols, orglist)
        # scenario 5: when defercols is set to True for buids
        all_by_buids_with_defercols = models.Organization.all(buids=orgids)
        self.assertIsInstance(all_by_buids_with_defercols, list)
        self.assertItemsEqual(all_by_buids_with_defercols, orglist)

    def test_organization_valid_name(self):
        """
        Test for checking if given is a valid organization name
        """
        hufflepuffs = models.Organization(name=u'hufflepuffs', title=u'Huffle Puffs')
        self.assertFalse(hufflepuffs.is_valid_name(u'#$%#%___2836273untitled'))
        self.assertTrue(hufflepuffs.is_valid_name(u'hufflepuffs'))

    def test_organization_pickername(self):
        """
        Test for checking Organization's pickername
        """
        # scenario 1: when only title is given
        abnegation = models.Organization(title=u"Abnegation")
        self.assertIsInstance(abnegation.pickername, unicode)
        self.assertEqual(abnegation.pickername, abnegation.title)

        # scenario 2: when both name and title are given
        name = u'cullens'
        title = u'The Cullens'
        olympic_coven = models.Organization(title=title)
        olympic_coven.name = name
        db.session.add(olympic_coven)
        db.session.commit()
        self.assertIsInstance(olympic_coven.pickername, unicode)
        assert (
            u'{title} (@{name})'.format(title=title, name=name)
            in olympic_coven.pickername
        )

    def test_organization_permissions(self):
        """
        Test for adding and retrieving an organization's permissions
        """
        permissions_expected = ['view', 'edit', 'delete', 'view-teams', 'new-team']
        crusoe = self.fixtures.crusoe
        oakley = self.fixtures.oakley
        batdog = self.fixtures.batdog
        # scenario 1: if user is owner of organization
        crusoe_query = batdog.permissions(crusoe)
        self.assertIsInstance(crusoe_query, set)
        valid_permissions_received = []
        for each in crusoe_query:
            valid_permissions_received.append(each)
        self.assertItemsEqual(permissions_expected, valid_permissions_received)
        # scenario 2: if user is not owner
        oakley_permission = models.Permission(name=u"huh", title=u"Huh!?", user=oakley)
        perms = oakley_permission.permissions(user=oakley)
        perms.add('view')
        oakley_query = batdog.permissions(oakley)
        self.assertIsInstance(oakley_query, set)
        self.assertEqual(oakley_query, set())

    def test_organization_available_permissions(self):
        """
        Test for retrieving all permission instances available to an organization.
        (either owned by this organization or available to all users).
        """
        batdog = self.fixtures.batdog
        org_with_no_permissions = batdog.available_permissions()
        self.assertIsInstance(org_with_no_permissions, list)
        self.assertEqual(org_with_no_permissions, [])
        specialdachs = self.fixtures.specialdachs
        permission_name = u"netizens"
        netizens = models.client.Permission(
            name=permission_name, title=permission_name, allusers=True, org=specialdachs
        )
        db.session.add(netizens)
        db.session.commit()
        org_with_permissions = specialdachs.available_permissions()
        self.assertIsInstance(org_with_permissions, list)
        self.assertItemsEqual(org_with_permissions, [netizens])

    def test_organization_name(self):
        """
        Test for retrieving Organization's name
        name is a setter method
        """
        insurgent = models.Organization(title=u'Insurgent')
        with self.assertRaises(ValueError):
            insurgent.name = u'35453496*%&^$%^'
        with self.assertRaises(ValueError):
            insurgent.name = u'Insurgent'
        insurgent.name = u'insurgent'
        self.assertEqual(insurgent.name, u'insurgent')

    def test_organization_clients_with_team_access(self):
        """
        Test for retrieving a list of clients with access to the organization's teams.
        """
        client = self.fixtures.client
        batdog = self.fixtures.batdog
        self.assertItemsEqual(batdog.clients_with_team_access(), [client])
