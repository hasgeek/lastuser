from flask import g
from behave import *
from mock import MagicMock
from lastuserapp import app
from lastuser_core.models import *


@given('a new user trying to register with a used username')
def given_new_user(context):
    context.app_context = app.test_request_context()
    context.app_context.push()
    context.test_client = app.test_client()
    import IPython; IPython.embed()
    db.drop_all()
    db.create_all()
    context.new_user = dict(
        fullname='Alyssa P Hacker',
        email='alyssa@hacker.com',
        username='alyssa',
        password='alyssa',
        confirm_password='alyssa'
    )


@when('this new user submits the registration form with a username that has already been used')
def when_form_submit(context):
    context.test_client.post('/register', data=context.new_user, follow_redirects=True)
    return context.test_client.post('/register', data=context.new_user, follow_redirects=True)


@then('the new user will not be registered')
def then_user_registered(context):
    user_query = User.query.filter_by(username='username')
    assert user_query.count() == 1
