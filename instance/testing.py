# -*- coding: utf-8 -*-
from os import environ
from flask import Markup

TESTING = True

SITE_TITLE = 'Lastuser'
DEBUG_TB_ENABLED = False
DEBUG_TB_INTERCEPT_REDIRECTS = False
LOGFILE = 'error.log'
SQLALCHEMY_DATABASE_URI = environ.get('SQLALCHEMY_DATABASE_URI', 'postgresql://@localhost:5432/lastuser_test_app')
SQLALCHEMY_ECHO = False
SECRET_KEY = 'random_string_here'
TIMEZONE = 'Asia/Kolkata'
CACHE_TYPE = 'redis'

#: Use SSL for some URLs
USE_SSL = False

#: Mail settings
MAIL_SUPRESS_SEND = True
MAIL_FAIL_SILENTLY = True
SITE_SUPPORT_EMAIL = environ.get('SITE_SUPPORT_EMAIL')
# Mail secrets
MAIL_SERVER = environ.get('MAIL_SERVER')
MAIL_PORT = environ.get('MAIL_PORT')
MAIL_USE_SSL = environ.get('MAIL_USE_SSL')
MAIL_USE_TLS = environ.get('MAIL_USE_TLS')
MAIL_DEFAULT_SENDER = environ.get('MAIL_DEFAULT_SENDER', 'test@example.com')
MAIL_USERNAME = environ.get('MAIL_USERNAME')
MAIL_PASSWORD = environ.get('MAIL_PASSWORD')

#: Logging: recipients of error emails
ADMINS = environ.get('ADMINS')

#: Twitter integration
OAUTH_TWITTER_KEY = environ.get('OAUTH_TWITTER_KEY')
OAUTH_TWITTER_SECRET = environ.get('OAUTH_TWITTER_SECRET')

#: GitHub integration
OAUTH_GITHUB_KEY = environ.get('OAUTH_GITHUB_KEY')
OAUTH_GITHUB_SECRET = environ.get('OAUTH_GITHUB_KEY')

#: Google integration
OAUTH_GOOGLE_KEY = environ.get('OAUTH_GOOGLE_KEY')
OAUTH_GOOGLE_SECRET = environ.get('OAUTH_GOOGLE_SECRET')
#: Default is ['email', 'profile']
OAUTH_GOOGLE_SCOPE = ['email', 'profile']

#: TypeKit code for fonts
TYPEKIT_CODE = environ.get('TYPEKIT_CODE')

#: Google Analytics code UA-XXXXXX-X
GA_CODE = environ.get('GA_CODE')

#: Recaptcha for the registration form
RECAPTCHA_USE_SSL = USE_SSL
RECAPTCHA_PUBLIC_KEY = environ.get('RECAPTCHA_PUBLIC_KEY')
RECAPTCHA_PRIVATE_KEY = environ.get('RECAPTCHA_PRIVATE_KEY')
RECAPTCHA_OPTIONS = ''

#: Exotel support is active
SMS_EXOTEL_SID = environ.get('SMS_EXOTEL_SID')
SMS_EXOTEL_TOKEN = environ.get('SMS_EXOTEL_TOKEN')
SMS_EXOTEL_FROM = environ.get('SMS_EXOTEL_FROM')

#: Twilio support for non-indian numbers
SMS_TWILIO_SID = environ.get('SMS_TWILIO_SID')
SMS_TWILIO_TOKEN = environ.get('SMS_TWILIO_TOKEN')
SMS_TWILIO_FROM = environ.get('SMS_TWILIO_FROM')

#: Reserved usernames
#: Add to this list but do not remove any unless you want to break
#: the website
RESERVED_USERNAMES = set([
    'app',
    'apps',
    'auth',
    'client',
    'confirm',
    'login',
    'logout',
    'new',
    'profile',
    'reset',
    'register',
    'token',
    'organizations',
    ])

#: Messages (text or HTML)
MESSAGE_FOOTER = Markup('Copyright &copy; <a href="http://hasgeek.com/">HasGeek</a>. Powered by <a href="https://github.com/hasgeek/lastuser" title="GitHub project page">Lastuser</a>, open source software from <a href="https://github.com/hasgeek">HasGeek</a>.')
USERNAME_REASON = ''
EMAIL_REASON = 'Please provide an email address to complete your profile'
BIO_REASON = ''
TIMEZONE_REASON = 'Dates and times will be shown in your preferred timezone'
ORG_NAME_REASON = u"Your company’s name as it will appear in the URL. Letters, numbers and dashes only"
ORG_TITLE_REASON = u"Your organization’s given name, preferably without legal suffixes"
ORG_DESCRIPTION_REASON = u"A few words about your organization (optional). Plain text only"
LOGIN_MESSAGE_1 = ""
LOGIN_MESSAGE_2 = ""
