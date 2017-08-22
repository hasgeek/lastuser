from behave import given, when, then
from lastuser_core.models import User
from utils import register_test_user


@given('we have a new user')
def given_new_user(context):
    # context.test_user already exists in environment.py
    pass


@when('a new user submits the registration form with the proper details')
def when_form_submit(context):
    register_test_user(context)


@then('the new user will be registered')
def then_user_registered(context):
    user = User.get(username=context.test_user['username'])
    assert user is not None
    assert len(user.emailclaims) is 1
