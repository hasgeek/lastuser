def register_test_user(context, clear_cookies=True):
    register_user(context, context.test_user, clear_cookies)


def register_user(context, user_dict, clear_cookies=True):
    context.browser.visit('/register')
    assert context.browser.find_element_by_name('csrf_token').is_enabled()
    for k, v in user_dict.iteritems():
        if not k.startswith('test_'):
            context.browser.find_element_by_name(k).send_keys(v)

    register_form = context.browser.find_element_by_id('register')
    register_form.submit()

    context.wait.until(lambda browser: browser.find_element_by_id('hg-user-btn'))

    if clear_cookies:
        context.browser.delete_all_cookies()


def login_test_user(context):
    login_user(context, context.test_user)


def login_user(context, user_dict):
    context.login_data = dict(
        username=user_dict['username'],
        password=user_dict['password']
    )

    context.browser.visit('/login')
    assert context.browser.find_element_by_name('csrf_token').is_enabled()

    context.browser.find_element_by_id('showmore').click()
    for k, v in context.login_data.iteritems():
        context.browser.find_element_by_name(k).send_keys(v)

    context.browser.find_element_by_name('username').submit()


def get_namespace_from_website(website):
    from urlparse import urlparse

    parsed_url = urlparse(website)
    netloc_reversed = parsed_url.netloc.split('.')
    netloc_reversed.reverse()
    return '.'.join(netloc_reversed)
