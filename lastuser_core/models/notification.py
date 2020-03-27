# -*- coding: utf-8 -*-

from baseframe import __
from coaster.utils import LabeledEnum

from . import BaseMixin, db

__all__ = ['SMSMessage', 'SMS_STATUS']


# --- Flags -------------------------------------------------------------------


class SMS_STATUS(LabeledEnum):  # NOQA: N801
    QUEUED = (0, __("Queued"))
    PENDING = (1, __("Pending"))
    DELIVERED = (2, __("Delivered"))
    FAILED = (3, __("Failed"))
    UNKNOWN = (4, __("Unknown"))


# --- Models ------------------------------------------------------------------


class SMSMessage(BaseMixin, db.Model):
    __tablename__ = 'smsmessage'
    # Phone number that the message was sent to
    phone_number = db.Column(db.String(15), nullable=False)
    transaction_id = db.Column(db.UnicodeText, unique=True, nullable=True)
    # The message itself
    message = db.Column(db.UnicodeText, nullable=False)
    # Flags
    status = db.Column(db.Integer, default=SMS_STATUS.QUEUED, nullable=False)
    status_at = db.Column(db.TIMESTAMP(timezone=True), nullable=True)
    fail_reason = db.Column(db.UnicodeText, nullable=True)
