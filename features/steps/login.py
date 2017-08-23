from behave import when, then, given
from utils import register_test_user, login_test_user


@given("we have an existing user")
def given_existing_user(context):
    register_test_user(context)


@when("the user tries to log in")
def when_login_form_submit(context):
    login_test_user(context)
    context.wait.until(lambda browser: browser.find_element_by_id('hg-user-btn'))


@then("we log the user in")
def user_login(context):
    assert context.browser.find_element_by_id('hg-user-btn').is_enabled()
