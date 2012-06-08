# -*- coding: utf-8 -*-

from flask.ext.sqlalchemy import SQLAlchemy
from lastuserapp import app

db = SQLAlchemy(app)


class IdMixin(object):
    id = db.Column(db.Integer, primary_key=True)


class TimestampMixin(object):
    created_at = db.Column(db.DateTime, default=db.func.now(), nullable=False)
    updated_at = db.Column(db.DateTime, default=db.func.now(), onupdate=db.func.now(), nullable=False)


class BaseMixin(IdMixin, TimestampMixin):
    """
    Base mixin class for all tables that adds id and timestamp columns
    """
    pass


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
