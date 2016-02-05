# -*- coding: utf-8 -*-

from markdown import markdown
from flask import render_template
from flask.ext.mail import Mail, Message
from baseframe import _
from html2text import html2text
from uuid import uuid4
import pystache

mail = Mail()


def verify_email_template(template, reset=False):
    """
    Verifies that the template is valid and contains a tag for email
    """
    try:
        random_email = unicode(uuid4())
        if random_email in pystache.render(template, {'email': random_email}):
            return True
    except:
        return False
    return False


def user_template_dict(email, user, secret=None):
    """
    Provides user data into scope of the email templating engine
    """
    return {
        'name': unicode(user.title),
        'email': unicode(email),
        'secret': unicode(secret)
    }


def send_email_verify_link(useremail, template=None):
    """
    Mail a verification link to the user.
    """
    msg = Message(subject=_("Confirm your email address"),
        recipients=[useremail.email])
    if template is None:
        msg.html = render_template('emailverify.html', useremail=useremail)
    else:
        if verify_email_template(template):
            msg.html = pystache.render(template, user_template_dict(useremail.email, useremail.owner))
        else:
            raise ValueError(_("Invalid template"))
    msg.body = html2text(msg.html)
    mail.send(msg)


def send_password_reset_link(email, user, secret, template=None):
    msg = Message(subject=_("Reset your password"),
        recipients=[email])
    if template is None:
        msg.html = render_template('emailreset.html', user=user, secret=secret)
    else:
        if verify_email_template(template, reset=True):
            msg.html = pystache.render(template, user_template_dict(email, user, secret=secret))
        else:
            raise ValueError(_("Invalid template"))
    msg.body = html2text(msg.html)
    mail.send(msg)
