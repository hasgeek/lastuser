from flask import g
from behave import when, then, given
from lastuserapp import app
from utils import login_test_user, login_user


# @given("we have an existing user")
# already defined in login.py


@given("the user is logged in")
def user_logs_in(context):
    login_test_user(context)


@when("the user visits their profile page")
def when_login_form_submit(context):
    context.browser.visit('/profile')


@then("the user can see their details")
def visit_profile_page(context):
    assert context.browser.find_element_by_id('hg-user-btn').is_enabled()
    infoboxes = context.browser.find_elements_by_class_name('infobox')
    assert len(infoboxes) > 0
    infobox = infoboxes[0]
    assert context.test_user['username'] in infobox.text


@then("the user can edit their profile")
def edit_profile(context):
    context.browser.visit('/profile/edit')
    context.browser.find_element_by_name("fullname").clear()
    context.browser.find_element_by_name("fullname").send_keys(context.test_user["fullname"] + "test")
    context.browser.find_element_by_name("username").clear()
    context.browser.find_element_by_name("username").send_keys(context.test_user["username"] + "test")
    context.browser.find_element_by_name("fullname").submit()

    infoboxes = context.browser.find_elements_by_class_name('infobox')
    assert len(infoboxes) > 0
    infobox = infoboxes[0]
    assert context.test_user['username'] + "test" in infobox.text


@then("the user can change their password")
def change_password(context):
    context.browser.visit('/profile/password')
    # context.browser.save_screenshot('pre-password.jpg')
    context.browser.find_element_by_name("old_password").send_keys(context.test_user["password"])
    context.browser.find_element_by_name("password").send_keys(context.test_user["test_new_password"])
    context.browser.find_element_by_name("confirm_password").send_keys(context.test_user["test_new_password"])
    context.browser.find_element_by_name("password").submit()

    alert = context.browser.find_elements_by_xpath("//div[@class='alert alert-success fade in']")
    assert len(alert) == 1
    assert 'Your new password has been saved' in context.browser.page_source

    # now let's logout and login again
    context.browser.delete_all_cookies()
    login_user(context, dict(username=context.test_user["username"] + "test", password=context.test_user["test_new_password"]))
    assert context.browser.find_element_by_id('hg-user-btn').is_enabled()
