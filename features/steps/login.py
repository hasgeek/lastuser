from flask import g
from behave import when, then, given
from mock import MagicMock
from lastuser_core.models import db, User


@given("we have an existing user")
def given_existing_user(context):
    context.test_user = dict(
        fullname='Alyssa P Hacker',
        email='alyssa@hacker.com',
        username='alyssa',
        password='alyssa',
        confirm_password='alyssa'
    )
    context.test_client.post('/register', data=context.test_user, follow_redirects=True)


@when("the user tries to log in")
def when_login_form_submit(context):
    login_data = dict(
        username=context.test_user['username'],
        password=context.test_user['password']
    )
    context.test_client.post('/login', data=login_data, follow_redirects=True)


@then("we log the user in")
def user_login(context):
    assert g.user is not None
