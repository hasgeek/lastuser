# -*- coding: utf-8 -*-

from markdown import markdown
from flask import render_template
from flask.ext.mail import Mail, Message

mail = Mail()


def send_email_verify_link(useremail):
    """
    Mail a verification link to the user.
    """
    msg = Message(subject="Confirm your email address",
        recipients=[useremail.email])
    msg.body = render_template("emailverify.md", useremail=useremail)
    msg.html = markdown(msg.body)
    mail.send(msg)


def send_password_reset_link(email, user, secret):
    msg = Message(subject="Reset your password",
        recipients=[email])
    msg.body = render_template("emailreset.md", user=user, secret=secret)
    msg.html = markdown(msg.body)
    mail.send(msg)
