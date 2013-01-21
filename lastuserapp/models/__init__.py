# -*- coding: utf-8 -*-

from flask.ext.sqlalchemy import SQLAlchemy
from coaster.sqlalchemy import BaseMixin  # Imported from here by other models
from lastuserapp import app

db = SQLAlchemy(app)


from lastuserapp.models.user import *
from lastuserapp.models.client import *
from lastuserapp.models.notice import *


def getuser(name):
    if '@' in name:
        if name.startswith('@'):
            extid = UserExternalId.query.filter_by(service='twitter', username=name[1:]).first()
            if extid:
                return extid.user
            else:
                return None
        else:
            useremail = UserEmail.query.filter_by(email=name).first()
            if useremail:
                return useremail.user
            # No verified email id. Look for an unverified id; return first found
            useremail = UserEmailClaim.query.filter_by(email=name).first()
            if useremail:
                return useremail.user
            return None
    else:
        return User.query.filter_by(username=name).first()
