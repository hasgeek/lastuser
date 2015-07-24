# -*- coding: utf-8 -*-

from markdown import markdown
from flask import render_template
from flask.ext.mail import Mail, Message
from baseframe import _
from html2text import html2text

mail = Mail()


def send_email_verify_link(useremail):
    """
    Mail a verification link to the user.
    """
    msg = Message(subject=_("Confirm your email address"),
        recipients=[useremail.email])
    msg.html = render_template('emailverify.html', useremail=useremail)
    msg.body = html2text(msg.html)
    mail.send(msg)


def send_password_reset_link(email, user, secret):
    msg = Message(subject=_("Reset your password"),
        recipients=[email])
    msg.html = render_template('emailreset.html', user=user, secret=secret)
    msg.body = html2text(msg.html)
    mail.send(msg)
