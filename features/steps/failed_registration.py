from flask import g
from behave import *
from mock import MagicMock
from lastuser_core.models import *


@given('a new user trying to register with a used username')
def given_new_user(context):
    context.new_user = dict(
        fullname='Alyssa P Hacker',
        email='alyssa@hacker.com',
        username='alyssa',
        password='alyssa',
        confirm_password='alyssa'
    )
    resp = context.test_client.post('/register', data=context.new_user, follow_redirects=True)
    # print(resp.data)


@when('this new user submits the registration form with a username that has already been used')
def when_form_submit(context):
    resp = context.test_client.post('/register', data=context.new_user, follow_redirects=True)
    return resp


@then('the new user will not be registered')
def then_user_registered(context):
    user_query = User.query.filter_by(username=context.new_user['username'])
    assert user_query.count() == 1
