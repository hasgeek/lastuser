# -*- coding: utf-8 -*-

import logging

from lastuserapp import app


file_handler = logging.FileHandler(app.config['LOGFILE'])
file_handler.setLevel(logging.WARNING)
app.logger.addHandler(file_handler)
if app.config['ADMINS']:
    mail_handler = logging.handlers.SMTPHandler(app.config['MAIL_SERVER'],
        app.config['DEFAULT_MAIL_SENDER'][1],
        app.config['ADMINS'],
        'lastuser failure',
        credentials = (app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD']))
    mail_handler.setLevel(logging.ERROR)
    app.logger.addHandler(mail_handler)
