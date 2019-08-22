# -*- coding: utf-8 -*-
from behave import given, then, when
import selenium.webdriver.support.ui as ui


@given("we have an existing user")
def given_existing_user(context):
    context.test_user = {
        'fullname': 'Alyssa P Hacker',
        'email': 'alyssa@hacker.com',
        'username': 'alyssa',
        'password': 'alyssa',
        'confirm_password': 'alyssa',
    }

    context.browser.visit('/register')
    assert context.browser.find_element_by_name('csrf_token').is_enabled()
    for k, v in context.test_user.iteritems():
        context.browser.find_element_by_name(k).send_keys(v)

    register_form = context.browser.find_element_by_id('form-register')
    register_form.submit()


@when("the user tries to log in")
def when_login_form_submit(context):
    context.login_data = {
        'username': context.test_user['username'],
        'password': context.test_user['password'],
    }
    wait = ui.WebDriverWait(context.browser, 30)

    context.browser.visit('/login')
    assert context.browser.find_element_by_name('csrf_token').is_enabled()

    context.browser.find_element_by_id('showmore').click()
    for k, v in context.login_data.iteritems():
        context.browser.find_element_by_name(k).send_keys(v)

    context.browser.find_element_by_name('username').submit()

    context.user_button = wait.until(
        lambda browser: browser.find_element_by_id('hg-user-btn')
    )


@then("we log the user in")
def user_login(context):
    assert context.user_button.is_enabled()
