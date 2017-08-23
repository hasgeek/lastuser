from flask import g
from behave import when, then, given
from lastuserapp import app
from .utils import login_user


@given("we do not know that user")
def given_existing_user(context):
    context.test_user = dict(
        username='bobthehacker',
        password='bobthehacker'
    )


@when("the nonexisting user tries to log in")
def when_login_form_submit(context):
    login_user(context, context.test_user)


@then("we do not log the user in")
def user_login(context):
    wrong_password_error = context.browser.find_elements_by_xpath('//p[@class="help-error" and contains(text(), "User does not exist")]')
    assert len(wrong_password_error) == 1
