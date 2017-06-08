from flask import g
from behave import when, then, given
from lastuserapp import app


@given("we have an existing user")
def given_existing_user(context):
    context.test_user = dict(
        fullname='Alyssa P Hacker',
        email='alyssa@hacker.com',
        username='alyssa',
        password='alyssa',
        confirm_password='alyssa'
    )
    with app.test_client() as c:
        c.post('/register', data=context.test_user, follow_redirects=True)


@when("the user tries to log in")
def when_login_form_submit(context):
    assert g.user is None
    context.login_data = dict(
        username=context.test_user['username'],
        password=context.test_user['password'],
    )
    context.login_data['form.id'] = "passwordlogin"
    with app.test_client() as c:
        c.post('/login', data=context.login_data)
        context.user = g.user


@then("we log the user in")
def user_login(context):
    assert context.user is not None
