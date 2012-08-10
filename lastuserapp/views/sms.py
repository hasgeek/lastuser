# -*- coding: utf-8 -*-

"""
Adds support for texting Indian mobile numbers
"""

from pytz import timezone
from urllib2 import urlopen, URLError
from urllib import urlencode
from datetime import datetime

from flask import flash, request
from lastuserapp import app
from lastuserapp.models import db, SMSMessage, SMS_STATUS

# SMS GupShup sends delivery reports with this timezone
SMSGUPSHUP_TIMEZONE = timezone('Asia/Calcutta')


def send_message(msg):
    if msg.phone_number.startswith('+91'):  # Indian number. Use SMS GupShup
        if len(msg.phone_number) != 13:
            raise ValueError("Invalid Indian mobile number")
        # All okay. Send!
        # TODO: Also check if we have SMS GupShup credentials in settings.py
        params = urlencode(dict(
            method='SendMessage',
            send_to=msg.phone_number[1:],  # Number with leading +
            msg=msg.message,
            msg_type='TEXT',
            format='text',
            v='1.1',
            auth_scheme='plain',
            userid=app.config['SMS_SMSGUPSHUP_USER'],
            password=app.config['SMS_SMSGUPSHUP_PASS'],
            mask=app.config['SMS_SMSGUPSHUP_MASK']
            ))
        try:
            response = urlopen('https://enterprise.smsgupshup.com/GatewayAPI/rest?%s' % params).read()
            r_status, r_phone, r_id = [item.strip() for item in response.split('|')]
            if r_status == 'success':
                msg.status = SMS_STATUS.PENDING
                msg.transaction_id = r_id
        except URLError, e:
            # FIXME: This function should not be sending messages to the UI
            flash("Message could not be sent. Error: %s" % e)
    else:
        # Unsupported at this time
        raise ValueError("Unsupported phone number")


def send_phone_verify_code(phoneclaim):
    msg = SMSMessage(phone_number=phoneclaim.phone,
        message="Verification code: %s. If you did not request this, please report to us at %s." % (
            phoneclaim.verification_code, app.config['SITE_SUPPORT_EMAIL']))
    # Now send this
    send_message(msg)
    db.session.add(msg)


@app.route('/report/smsgupshup')
def report_smsgupshup():
    externalId = request.args.get('externalId')
    deliveredTS = request.args.get('deliveredTS')
    status = request.args.get('status')
    phoneNo = request.args.get('phoneNo')
    cause = request.args.get('cause')

    # Find a corresponding message and ensure the parameters match
    msg = SMSMessage.query.filter_by(transaction_id=externalId).first()
    if not msg:
        return "No such message", 404
    elif msg.phone_number != '+' + phoneNo:
        return "Incorrect phone number", 404
    else:
        if status == 'SUCCESS':
            msg.status = SMS_STATUS.DELIVERED
        elif status == 'FAIL':
            msg.status = SMS_STATUS.FAILED
        else:
            msg.status == SMS_STATUS.UNKNOWN
        msg.fail_reason = cause
        if deliveredTS:
            deliveredTS = float(deliveredTS) / 1000.0
        # This delivery time is in IST, GMT+0530
        # Convert this into a naive UTC timestamp before saving
        local_status_at = datetime.fromtimestamp(deliveredTS)
        msg.status_at = local_status_at - SMSGUPSHUP_TIMEZONE.utcoffset(local_status_at)
    db.session.commit()
    return "Status updated"
