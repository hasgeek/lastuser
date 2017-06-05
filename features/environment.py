from lastuser_core.models import db
from lastuserapp import app


def before_all(context):
    context.app_context = app.test_request_context()
    context.app_context.push()
    context.test_client = app.test_client()
    db.create_all()


def after_all(context):
    db.session.commit()
    db.drop_all()
