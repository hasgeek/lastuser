#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys

reload(sys)
sys.setdefaultencoding('utf-8')

from lastuser_core.models import Client, Organization, Permission, User  # isort:skip
from lastuserapp import app, db  # isort:skip

# incase data exists from previously run tests
db.drop_all()
# create schema again
db.create_all()

# Add fixtures for test app
# user for CRUD workflow: creating client app
gustav = User(
    username=u"gustav", fullname=u"Gustav 'world' Dachshund", password='worldismyball'
)

# org for associating with client
# client for CRUD workflow of defining perms *in* client
# spare user for CRUD workflow of assigning permissions
oakley = User(username=u"oakley", fullname=u"Oakley 'huh' Dachshund")
dachsunited = Organization(name=u"dachsunited", title=u"Dachs United")
dachsunited.owners.users.append(gustav)
dachsunited.members.users.append(oakley)
dachshundworld = Client(
    title=u"Dachshund World",
    org=dachsunited,
    confidential=True,
    website=u"http://gustavsdachshundworld.com",
)
partyanimal = Permission(name=u"partyanimal", title=u"Party Animal", org=dachsunited)

db.session.add(gustav)
db.session.add(oakley)
db.session.add(dachsunited)
db.session.add(dachshundworld)
db.session.add(partyanimal)
db.session.commit()

app.run('0.0.0.0')
