# -*- coding: utf-8 -*-

from sqlalchemy.ext.declarative import declared_attr
from coaster.utils import LabeledEnum
from baseframe import __
from ..registry import OrderedDict
from . import db, BaseMixin, BaseScopedNameMixin
from .user import User, UserEmail, UserPhone
from .client import Client

__all__ = ['SMSMessage', 'SMS_STATUS']


# --- Flags -------------------------------------------------------------------

class SMS_STATUS(LabeledEnum):
    QUEUED    = (0, __(u"Queued"))
    PENDING   = (1, __(u"Pending"))
    DELIVERED = (2, __(u"Delivered"))
    FAILED    = (3, __(u"Failed"))
    UNKNOWN   = (4, __(u"Unknown"))


class NOTIFICATION_FLAGS(LabeledEnum):
    DELIVERY = (0, __(u"Delivery"))
    READ     = (1, __(u"Read"))
    BOUNCE   = (2, __(u"Bounce"))


class NOTIFICATION_TYPE(LabeledEnum):
    MANDATORY     = (0, u'mandatory',     __(u"Mandatory"))      # Mandatory service announcement
    TRANSACTIONAL = (1, u'transactional', __(u"Transactional"))  # Result of user activity
    ALERT         = (2, u'alert',         __(u"Alert"))          # Periodic alert based on set criteria
    MASS          = (3, u'mass',          __(u"Mass"))           # Mass mail from the service provider


# A note on frequency: scheduling/batching is done by Lastuser, not by the client app
class NOTIFICATION_FREQUENCY(LabeledEnum):
    IMMEDIATE = (0, u'immed',   __(u"Immediately"))      # Alert user immediately
    DELAYED   = (1, u'delay',   __(u"Delayed"))          # Send after a timeout, allowing app to cancel (tentative)
    DAILY     = (2, u'daily',   __(u"Batched daily"))    # Send a daily digest
    WEEKLY    = (3, u'weekly',  __(u"Batched weekly"))   # Send a weekly digest
    MONTHLY   = (4, u'monthly', __(u"Batched monthly"))  # Send a monthly digest


# --- Transport Channels ------------------------------------------------------

# Move these into a registry like the LoginRegistry

class Channel(object):
    name = u''
    title = u""
    flags = []

    delivery_flag = False
    bounce_flag = False
    read_flag = False


class ChannelBrowser(Channel):
    name = u'browser'
    title = __(u"In app")
    flags = [NOTIFICATION_FLAGS.DELIVERY, NOTIFICATION_FLAGS.READ]

    delivery_flag = True
    bounce_flag = False
    read_flag = True


class ChannelEmail(Channel):
    name = u'email'
    title = __(u"Email")
    flags = [NOTIFICATION_FLAGS.BOUNCE, NOTIFICATION_FLAGS.READ]

    delivery_flag = False
    bounce_flag = True
    read_flag = True


class ChannelTwitter(Channel):
    name = u'twitter'
    title = __(u"Twitter")
    flags = [NOTIFICATION_FLAGS.DELIVERY, NOTIFICATION_FLAGS.BOUNCE]

    delivery_flag = True
    bounce_flag = True
    read_flag = False


class ChannelSMS(Channel):
    name = u'sms'
    title = __(u"SMS")
    flags = [NOTIFICATION_FLAGS.DELIVERY, NOTIFICATION_FLAGS.BOUNCE]

    delivery_flag = True
    bounce_flag = True
    read_flag = False


channel_registry = OrderedDict([(c.name, c.title) for c in [
    ChannelBrowser, ChannelEmail, ChannelSMS, ChannelTwitter
    ]])


# --- Models ------------------------------------------------------------------

class SMSMessage(BaseMixin, db.Model):
    __tablename__ = 'smsmessage'
    # Phone number that the message was sent to
    phone_number = db.Column(db.String(15), nullable=False)
    transaction_id = db.Column(db.UnicodeText, unique=True, nullable=True)
    # The message itself
    message = db.Column(db.UnicodeText, nullable=False)
    # Flags
    status = db.Column(db.Integer, default=0, nullable=False)
    status_at = db.Column(db.TIMESTAMP(timezone=True), nullable=True)
    fail_reason = db.Column(db.UnicodeText, nullable=True)


# class ChannelMixin(object):
#     @declared_attr
#     def _channels(self):
#         """
#         Preferred channels for sending this notification class (in order of preference).
#         Only listed channels are available for delivery of this notification.
#         """
#         return db.Column('channels', db.UnicodeText, default=u'', nullable=False)

#     def _channels_get(self):
#         return [c.strip() for c in self._channels.replace(u'\r', u' ').replace(u'\n', u' ').split(u' ') if c]

#     def _channels_set(self, value):
#         if isinstance(value, basestring):
#             value = [value]
#         self._channels = u' '.join([c.strip() for c in value if c])

#     @declared_attr
#     def channels(self):
#         return db.synonym('_channels', descriptor=property(self._channels_get, self._channels_set))


# class NotificationClass(ChannelMixin, BaseScopedNameMixin, db.Model):
#     """
#     A NotificationClass is a type of notification
#     """

#     __tablename__ = 'notification_class'

#     #: Client app that will send these notifications
#     client_id = db.Column(None, db.ForeignKey('client.id'), nullable=False)
#     client = db.relationship(Client, backref=db.backref('notifications', cascade='all, delete-orphan'))
#     parent = db.synonym('client')

#     #: User-unique notification class. The name is now a random unique string that is saved in the app
#     #: and is used to send these notifications
#     user_id = db.Column(None, db.ForeignKey('user.id'), nullable=True)
#     user = db.relationship(User, foreign_keys=[user_id],
#         backref=db.backref('notifications', cascade='all, delete-orphan'))

#     #: Type of notification (as per NOTIFICATION_TYPE), currently for informational purposes only
#     type = db.Column(db.SmallInteger, nullable=False)
#     #: Default delivery frequency
#     freq = db.Column(db.SmallInteger, nullable=False, default=NOTIFICATION_FREQUENCY.IMMEDIATE)

#     __table_args__ = (db.UniqueConstraint('client_id', 'name'),)


# class UserNotificationPreference(ChannelMixin, BaseMixin, db.Model):
#     __tablename__ = 'user_notification_preference'

#     #: The notification class these preferences are for
#     notification_class_id = db.Column(None, db.ForeignKey('notification_class.id'), nullable=False)
#     notification_class = db.relationship(NotificationClass,
#         backref=db.backref('user_preferences', lazy='dynamic', cascade='all, delete-orphan'))

#     #: The user these preferences are for
#     user_id = db.Column(None, db.ForeignKey('user.id'), nullable=False)
#     user = db.relationship(User, foreign_keys=[user_id],
#         backref=db.backref('notification_preferences', cascade='all, delete-orphan'))

#     #: Context for user's preferences (default user's buid, else org's buid)
#     #: If we migrate User/Organization/Team into a Principal model (ticket #91)
#     #: this should become a foreign key to Principal.
#     context = db.Column(db.Unicode(22))

#     #: Preferred email address for delivering these notifications. If blank,
#     #: implies default email (user.email) or no email, depending on whether
#     #: 'email' is in the channels
#     email_id = db.Column(None, db.ForeignKey('useremail.id'), nullable=True)
#     email = db.relationship(UserEmail)

#     #: Preferred phone number for delivering these notifications. If blank,
#     #: implies default phone (user.phone) or no SMS, depending on whether
#     #: 'sms' is in the channels
#     phone_id = db.Column(None, db.ForeignKey('userphone.id'), nullable=True)
#     phone = db.relationship(UserPhone)

#     #: User's preferred delivery frequency (null = default)
#     _freq = db.Column('freq', db.SmallInteger, nullable=True)

#     __table_args__ = (db.UniqueConstraint('user_id', 'notification_class_id', 'context'),)

#     def _freq_get(self):
#         return self._freq if self._freq is not None else self.notification_class.freq

#     def _freq_set(self, value):
#         self._freq = value

#     freq = db.synonym('_freq', descriptor=property(_freq_get, _freq_set))

#     def _channels_set(self, value):
#         available_channels = self.notification_class.channels
#         if isinstance(value, basestring):
#             value = [value]
#         self._channels = u' '.join([c.strip() for c in value if c and c in available_channels])

#     channels = db.synonym('_channels', descriptor=property(ChannelMixin._channels_get, _channels_set))
