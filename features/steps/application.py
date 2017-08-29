from utils import get_namespace_from_website


@when('the user visits the client application page')
def when_visit_app_page(context):
    context.browser.visit('/apps/new')
    context.test_app_name = 'testappname'
    context.test_app_description = 'this is a test app'
    context.test_app_website = 'http://test.auth.hasgeek.com'
    context.test_app_redirect_uri = 'http://test.auth.hasgeek.com/redirect'
    context.test_app_notification_uri = 'http://test.auth.hasgeek.com/notification'
    context.test_app_iframe_uri = 'http://test.auth.hasgeek.com/iframe'
    context.test_app_namespace = get_namespace_from_website(context.test_app_website)
    context.test_org_title = 'testorgtitle'
    context.test_org_name = 'testorgname'


@then('the user can add a new client application')
def then_new_app(context):
    context.browser.find_element_by_id('title').send_keys(context.test_app_name)
    context.browser.find_element_by_id('description').send_keys(context.test_app_description)
    context.browser.find_element_by_id('website').send_keys(context.test_app_website)
    context.browser.find_element_by_id('namespace').send_keys(context.test_app_namespace)
    context.browser.find_element_by_id('redirect_uri').send_keys(context.test_app_redirect_uri)
    context.browser.find_element_by_id('notification_uri').send_keys(context.test_app_notification_uri)
    context.browser.find_element_by_id('iframe_uri').send_keys(context.test_app_iframe_uri)
    context.browser.find_element_by_id('title').submit()
    infoboxes = context.browser.find_elements_by_class_name('infobox')

    # print(context.browser.current_url)
    # http://localhost:7001/apps/h6YvCJUtShOkIpkISWZQQQ
    assert '/apps/new' not in context.browser.current_url
    assert '/apps' in context.browser.current_url

    context.test_app_id = context.browser.current_url.split('/')[-1]

    assert len(infoboxes) > 0

    infobox = infoboxes[0]

    assert context.test_app_name in infobox.text
    assert context.test_app_description in infobox.text
    assert context.test_app_website in infobox.text
    assert context.test_app_redirect_uri in infobox.text
    assert context.test_app_notification_uri in infobox.text
    assert context.test_app_iframe_uri in infobox.text
    assert context.test_app_namespace in infobox.text


@then('the user can edit the new client application')
def then_edit_app(context):
    context.browser.visit('/apps/{id}/edit'.format(id=context.test_app_id))
    context.browser.find_element_by_id('title').clear()
    context.browser.find_element_by_id('title').send_keys(context.test_app_name + 'test')
    context.browser.find_element_by_id('title').submit()

    infoboxes = context.browser.find_elements_by_class_name('infobox')

    assert len(infoboxes) > 0
    infobox = infoboxes[0]

    assert context.test_app_name + 'test' in infobox.text


@then('the user can add a new organization')
def then_add_org(context):
    context.browser.visit('/organizations/new')
    context.browser.find_element_by_id('title').send_keys(context.test_org_title)
    context.browser.find_element_by_id('name').send_keys(context.test_org_name)
    context.browser.find_element_by_id('title').submit()

    new_team_buttons = context.browser.find_elements_by_xpath(
        '//a[contains(@href, "/organizations/{name}/teams/new")]'.format(name=context.test_org_name))

    assert len(new_team_buttons) > 0
    new_team_button = new_team_buttons[0]

    assert "New team" in new_team_button.text

    headers = context.browser.find_elements_by_xpath(
        '//div[@class="page-header"]//h1[contains(text(), "Organization: {title}")]'.format(title=context.test_org_title))
    assert len(headers) > 0


@then('the user profile page lists new application and organization')
def then_things_in_profile(context):
    context.browser.visit('/profile')
    container = context.browser.find_element_by_id('main-content')
    assert context.test_app_name in container.text
    assert context.test_org_title in container.text
