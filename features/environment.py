# -*- coding: utf-8 -*-
from wsgiref.simple_server import make_server
import threading

from selenium import webdriver

from lastuser_core.models import db
from lastuserapp import app

server_name = app.config.get('SERVER_NAME') or 'localhost:7001'
base_url = 'http://%s' % server_name
host, port = server_name.split(':')
port = int(port) if port else 7001


def before_all(context):
    context.server = make_server(host, port, app)
    context.thread = threading.Thread(target=context.server.serve_forever)
    context.thread.start()
    context.browser = webdriver.PhantomJS()
    context.browser.visit = lambda url: context.browser.get(base_url + url)


def after_all(context):
    # Explicitly quits the browser, otherwise it won't once tests are done
    context.server.shutdown()
    context.thread.join()
    context.browser.quit()


def after_step(context, step):
    context.browser.delete_all_cookies()


def before_feature(context, feature):
    db.create_all()


def after_feature(context, feature):
    db.session.commit()
    db.drop_all()
