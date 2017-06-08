from flask import g, session
from lastuser_core.models import db
from lastuserapp import app


def before_all(context):
    context.app_context = app.test_request_context()
    context.app_context.push()
    db.create_all()


def after_all(context):
    context.app_context.pop()
    db.session.commit()
    db.drop_all()


def before_step(context, step):
    with app.test_client() as c:
        c.post('/logout', follow_redirects=True)
