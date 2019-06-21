from behave import given, when, then
from lastuser_core.models import User


@given('a new user trying to register with a used username')
def given_new_user(context):
    context.test_user = dict(
        fullname='Alyssa P Hacker',
        email='alyssa@hacker.com',
        username='alyssa',
        password='alyssa',
        confirm_password='alyssa'
        )
    # registering the test user
    context.browser.visit('/register')
    assert context.browser.find_element_by_name('csrf_token').is_enabled()
    for k, v in context.test_user.iteritems():
        context.browser.find_element_by_name(k).send_keys(v)

    register_form = context.browser.find_element_by_id('form-register')
    register_form.submit()


@when('this new user submits the registration form with a username that has already been used')
def when_form_submit(context):
    # trying to register another used with same username
    # this will fail
    context.browser.visit('/register')
    assert context.browser.find_element_by_name('csrf_token').is_enabled()
    for k, v in context.test_user.iteritems():
        context.browser.find_element_by_name(k).send_keys(v)

    register_form = context.browser.find_element_by_id('form-register')
    register_form.submit()
    # page will have error message
    alert = context.browser.find_elements_by_xpath("//*[contains(text(), 'This username is taken')]")
    assert len(alert) == 1


@then('the new user will not be registered')
def then_user_registered(context):
    # just one user exists, the first one
    user = User.get(username=context.test_user['username'])
    assert user is not None
