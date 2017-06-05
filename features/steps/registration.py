from flask import g
from behave import *
from mock import MagicMock
from lastuserapp import app
from lastuser_core.models import *


@given('we have a new user')
def given_new_user(context):
    context.app_context = app.test_request_context()
    context.app_context.push()
    context.test_client = app.test_client()
    db.drop_all()
    db.create_all()
    context.new_user = dict(
        fullname='Alyssa P Hacker',
        email='alyssa@hacker.com',
        username='alyssa',
        password='alyssa',
        confirm_password='alyssa'
    )


@when('a new user submits the registration form with the proper details')
def when_form_submit(context):
    return context.test_client.post('/register', data=context.new_user, follow_redirects=True)


@then('the new user will be registered')
def then_user_registered(context):
    # import IPython; IPython.embed()
    user = User.get(username='alyssa')
    assert user is not None
    assert len(user.emailclaims) is 1
    # assert g.user is user


# def after_all(context):
#     db.drop_all()
