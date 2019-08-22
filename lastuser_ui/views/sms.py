# -*- coding: utf-8 -*-

"""
Adds support for texting Indian mobile numbers
"""

from flask import current_app, flash

import requests

from baseframe import _
from lastuser_core.models import SMSMessage, db


def send_message(msg):
    if msg.phone_number.startswith('+91'):  # Indian number. Use Exotel
        if len(msg.phone_number) != 13:
            raise ValueError(_("Invalid Indian mobile number"))
        # All okay. Send!
        if not (
            current_app.config.get('SMS_EXOTEL_SID')
            and current_app.config.get('SMS_EXOTEL_TOKEN')
        ):
            raise ValueError(_("This server is not configured to send SMS"))
        else:
            sid = current_app.config['SMS_EXOTEL_SID']
            token = current_app.config['SMS_EXOTEL_TOKEN']
            try:
                r = requests.post(
                    'https://twilix.exotel.in/v1/Accounts/{sid}/Sms/send.json'.format(
                        sid=sid
                    ),
                    auth=(sid, token),
                    data={
                        'From': current_app.config.get('SMS_EXOTEL_FROM'),
                        'To': msg.phone_number,
                        'Body': msg.message,
                    },
                )
                if r.status_code in (200, 201):
                    # All good
                    jsonresponse = r.json()
                    if isinstance(jsonresponse, (list, tuple)) and jsonresponse:
                        msg.transaction_id = (
                            jsonresponse[0].get('SMSMessage', {}).get('Sid')
                        )
                    else:
                        msg.transaction_id = jsonresponse.get('SMSMessage', {}).get(
                            'Sid'
                        )
                else:
                    # FIXME: This function should not be sending messages to the UI
                    flash(_("Message could not be sent"), 'danger')
            except requests.ConnectionError:
                flash(
                    _(
                        "The SMS delivery engine is not reachable at the moment. Please try again"
                    ),
                    'danger',
                )
    else:
        # No number validation
        # All okay. Send!
        if not (
            current_app.config.get('SMS_TWILIO_SID')
            and current_app.config.get('SMS_TWILIO_TOKEN')
        ):
            raise ValueError(_("This server is not configured to send SMS"))
        else:
            sid = current_app.config['SMS_TWILIO_SID']
            token = current_app.config['SMS_TWILIO_TOKEN']
            try:
                r = requests.post(
                    'https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json'.format(
                        sid=sid
                    ),
                    auth=(sid, token),
                    data={
                        'From': current_app.config.get('SMS_TWILIO_FROM'),
                        'To': msg.phone_number,
                        'Body': msg.message,
                    },
                )
                if r.status_code in (200, 201):
                    # All good
                    jsonresponse = r.json()
                    msg.transaction_id = jsonresponse.get('sid', '')
                else:
                    # FIXME: This function should not be sending messages to the UI
                    flash(_("Message could not be sent"), 'danger')
            except requests.ConnectionError:
                flash(
                    _(
                        "The SMS delivery engine is not reachable at the moment. Please try again"
                    ),
                    'danger',
                )


def send_phone_verify_code(phoneclaim):
    msg = SMSMessage(
        phone_number=phoneclaim.phone,
        message=current_app.config['SMS_VERIFICATION_TEMPLATE'].format(
            code=phoneclaim.verification_code
        ),
    )
    # Now send this
    send_message(msg)
    db.session.add(msg)
