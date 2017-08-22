import threading
from wsgiref.simple_server import make_server
from selenium import webdriver
from lastuser_core.models import db
from lastuserapp import app
import selenium.webdriver.support.ui as ui

server_name = app.config.get('SERVER_NAME') or 'localhost:7001'
base_url = 'http://%s' % server_name
host, port = server_name.split(':')
port = int(port) if port else 7001


def before_all(context):
    context.server = make_server(host, port, app)
    context.thread = threading.Thread(target=context.server.serve_forever)
    context.thread.start()
    context.browser = webdriver.PhantomJS()
    context.browser.implicitly_wait(2)  # waits 2 second if it cannot find an element immediately
    context.browser.visit = lambda url: context.browser.get(base_url + url)

    context.test_user = dict(
        fullname='Alyssa P Hacker',
        email='alyssa@hacker.com',
        username='alyssa',
        password='alyssa',
        confirm_password='alyssa',
        test_new_password='alyssatest'
    )

    context.wait = ui.WebDriverWait(context.browser, 2)


def after_all(context):
    # Explicitly quits the browser, otherwise it won't once tests are done
    context.server.shutdown()
    context.thread.join()
    context.browser.quit()


def before_feature(context, feature):
    db.create_all()


def after_feature(context, feature):
    context.browser.delete_all_cookies()
    db.session.commit()
    db.drop_all()
