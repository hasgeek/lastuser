# -*- coding: utf-8 -*-

from markdown import markdown
from flask import render_template, url_for
from flask.ext.mail import Mail, Message
from baseframe import _
from html2text import html2text
from uuid import uuid4
import pystache

mail = Mail()


def verify_confirm_email_template(template, reset=False):
    """
    Verifies that the confirm email template is valid and contains a tag for confirm_link
    """
    try:
        random_confirm_link = unicode(uuid4())
        return random_confirm_link in pystache.render(template, {'confirm_link': random_confirm_link})
    except:
        return False


def verify_reset_email_template(template, reset=False):
    """
    Verifies that the template is valid and contains a tag for email
    """
    try:
        random_reset_link = unicode(uuid4())
        return random_reset_link in pystache.render(template, {'reset_link': random_reset_link})
    except:
        return False


def confirm_email_template_dict(email, user, confirm_link=None):
    """
    Provides user data into scope of the email templating engine
    """
    return {
        'name': user.title,
        'email': email,
        'confirm_link': confirm_link,
        }


def reset_email_template_dict(email, user, reset_link=None):
    """
    Provides user data into scope of the email templating engine
    """
    return {
        'name': user.title,
        'email': email,
        'reset_link': reset_link
        }


def send_email_verify_link(useremail, subject="Confirm your email address", template=None):
    """
    Mail a verification link to the user.
    """
    msg = Message(subject=subject,
        recipients=[useremail.email])
    confirm_link = url_for('lastuser_oauth.confirm_email', _external=True, md5sum=useremail.md5sum, secret=useremail.verification_code)
    if template is None:
        msg.html = render_template('emailverify.html', useremail=useremail, confirm_link=confirm_link)
    else:
        if verify_confirm_email_template(template):
            msg.html = pystache.render(template, confirm_email_template_dict(useremail.email, useremail.owner, confirm_link))
        else:
            raise ValueError(_("Invalid template"))
    msg.body = html2text(msg.html)
    mail.send(msg)


def send_password_reset_link(email, user, secret, subject="Reset your password", template=None):
    msg = Message(subject=subject,
        recipients=[email])
    reset_link = url_for('.reset_email', _external=True, userid=user.userid, secret=secret)
    if template is None:
        msg.html = render_template('emailreset.html', user=user, secret=secret)
    else:
        if verify_reset_email_template(template, reset=True):
            msg.html = pystache.render(template, reset_email_template_dict(email, user, reset_link=reset_link))
        else:
            raise ValueError(_("Invalid template"))
    msg.body = html2text(msg.html)
    mail.send(msg)
