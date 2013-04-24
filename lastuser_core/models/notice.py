# -*- coding: utf-8 -*-

from lastuser_core.models import db, BaseMixin

__all__ = ['SMSMessage', 'SMS_STATUS']


# --- Flags -------------------------------------------------------------------

class SMS_STATUS:
    QUEUED = 0
    PENDING = 1
    DELIVERED = 2
    FAILED = 3
    UNKNOWN = 4


# --- Channels ----------------------------------------------------------------

class Channel(object):
    delivery_flag = False
    bounce_flag = False
    read_flag = False
    channel_type = 0


class ChannelBrowser(Channel):
    delivery_flag = True
    bounce_flag = False
    read_flag = True
    channel_type = 1


class ChannelEmail(Channel):
    delivery_flag = False
    bounce_flag = True
    read_flag = False
    channel_type = 2


class ChannelTwitter(Channel):
    delivery_flag = True
    bounce_flag = True
    read_flag = False
    channel_type = 3


class ChannelSMS(Channel):
    delivery_flag = True
    bounce_flag = True
    read_flag = False
    channel_type = 4


# --- Models ------------------------------------------------------------------

class SMSMessage(BaseMixin, db.Model):
    __tablename__ = 'smsmessage'
    __bind_key__ = 'lastuser'
    # Phone number that the message was sent to
    phone_number = db.Column(db.String(15), nullable=False)
    transaction_id = db.Column(db.Unicode(40), unique=True, nullable=True)
    # The message itself
    message = db.Column(db.UnicodeText, nullable=False)
    # Flags
    status = db.Column(db.Integer, default=0, nullable=False)
    status_at = db.Column(db.DateTime, nullable=True)
    fail_reason = db.Column(db.Unicode(25), nullable=True)
