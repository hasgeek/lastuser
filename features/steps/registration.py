from behave import given, when, then
from lastuser_core.models import User


@given('we have a new user')
def given_new_user(context):
    context.test_user = dict(
        fullname='Alyssa P Hacker',
        email='alyssa@hacker.com',
        username='alyssa',
        password='alyssa',
        confirm_password='alyssa'
        )


@when('a new user submits the registration form with the proper details')
def when_form_submit(context):
    context.browser.visit('/register')

    assert context.browser.find_element_by_name('csrf_token').is_enabled()
    for k, v in context.test_user.iteritems():
        context.browser.find_element_by_name(k).send_keys(v)

    register_form = context.browser.find_element_by_id('form-register')
    register_form.submit()


@then('the new user will be registered')
def then_user_registered(context):
    user = User.get(username=context.test_user['username'])
    assert user is not None
    assert len(user.emailclaims) == 1
