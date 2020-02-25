# -*- coding: utf-8 -*-

from lastuser_core.models import (
    CLIENT_TEAM_ACCESS,
    Client,
    ClientTeamAccess,
    Organization,
    Permission,
    Resource,
    ResourceAction,
    SMSMessage,
    Team,
    TeamClientPermissions,
    User,
    UserClientPermissions,
    UserEmail,
    UserPhone,
)
from lastuserapp import db


class Fixtures(object):
    def make_fixtures(self):
        """
        Create users, attach them to organizations. Create test client app, add test
        resource, action and message.
        """
        crusoe = User(username="crusoe", fullname="Crusoe Celebrity Dachshund")
        oakley = User(username="oakley")
        piglet = User(username="piglet")
        nameless = User(fullname="Nameless")

        db.session.add_all([crusoe, oakley, piglet, nameless])
        self.crusoe = crusoe
        self.oakley = oakley
        self.piglet = piglet
        self.nameless = nameless

        crusoe_email = UserEmail(
            email="crusoe@keepballin.ca", user=crusoe, primary=True
        )
        crusoe_phone = UserPhone(phone="+8080808080", user=crusoe, primary=True)
        oakley_email = UserEmail(email="huh@keepballin.ca", user=oakley)
        db.session.add_all([crusoe_email, crusoe_phone, oakley_email])
        self.crusoe_email = crusoe_email
        self.crusoe_phone = crusoe_phone

        batdog = Organization(name='batdog', title='Batdog')
        batdog.owners.users.append(crusoe)
        batdog.members.users.append(oakley)
        db.session.add(batdog)
        self.batdog = batdog

        specialdachs = Organization(name="specialdachs", title="Special Dachshunds")
        specialdachs.owners.users.append(oakley)
        specialdachs.members.users.append(piglet)
        db.session.add(specialdachs)
        self.specialdachs = specialdachs

        client = Client(
            title="Batdog Adventures",
            org=batdog,
            confidential=True,
            namespace='fun.batdogadventures.com',
            website="http://batdogadventures.com",
        )
        db.session.add(client)
        self.client = client

        dachshunds = Team(title="Dachshunds", org=batdog)
        db.session.add(dachshunds)
        self.dachshunds = dachshunds

        team_client_permission = TeamClientPermissions(
            team=dachshunds, client=client, access_permissions="admin"
        )
        self.team_client_permission = team_client_permission
        db.session.add(team_client_permission)

        client_team_access = ClientTeamAccess(
            org=batdog, client=client, access_level=CLIENT_TEAM_ACCESS.ALL
        )
        db.session.add(client_team_access)

        bdfl = Permission(name="bdfl", title="BDFL", user=crusoe)
        db.session.add(bdfl)
        self.bdfl = bdfl

        user_client_permissions = UserClientPermissions(user=crusoe, client=client)
        db.session.add(user_client_permissions)
        self.user_client_permissions = user_client_permissions

        resource = Resource(name="test_resource", title="Test Resource", client=client)
        db.session.add(resource)
        self.resource = resource

        resource_action = ResourceAction(name='Fun', resource=resource, title='fun')
        db.session.add(resource_action)
        self.resource_action = resource_action

        action = ResourceAction(name="read", title="Read", resource=resource)
        db.session.add(action)
        self.action = action

        message = SMSMessage(
            phone_number=crusoe_phone.phone,
            transaction_id="Ruff" * 5,
            message="Wuff Wuff",
        )
        db.session.add(message)
        db.session.commit()
        self.message = message
