# -*- coding: utf-8 -*-
from flask import Markup

#: The title of this site
SITE_TITLE = 'Lastuser'

#: Support contact email
SITE_SUPPORT_EMAIL = 'test@example.com'

#: TypeKit code for fonts
TYPEKIT_CODE = ''

#: Google Analytics code UA-XXXXXX-X
GA_CODE = ''

#: Database backend
SQLALCHEMY_BINDS = {
    'lastuser': 'sqlite:///test.db',
    }

#: Cache type
CACHE_TYPE = 'redis'

#: Secret key
SECRET_KEY = 'make this something random'

#: Timezone
TIMEZONE = 'Asia/Calcutta'

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
    'embed',
    'api',
    'static',
    '_baseframe',
    'www',
    'ftp',
    'smtp',
    'imap',
    'pop',
    'pop3',
    'email',
    ])

#: Mail settings
#: MAIL_FAIL_SILENTLY : default True
#: MAIL_SERVER : default 'localhost'
#: MAIL_PORT : default 25
#: MAIL_USE_TLS : default False
#: MAIL_USE_SSL : default False
#: MAIL_USERNAME : default None
#: MAIL_PASSWORD : default None
#: DEFAULT_MAIL_SENDER : default None
MAIL_FAIL_SILENTLY = False
MAIL_SERVER = 'localhost'
DEFAULT_MAIL_SENDER = 'Lastuser <test@example.com>'
MAIL_DEFAULT_SENDER = DEFAULT_MAIL_SENDER  # For new versions of Flask-Mail

#: Logging: recipients of error emails
ADMINS = []

#: Logging: recipients of error smses
ADMIN_NUMBERS = []

#: Log file
LOGFILE = 'error.log'

#: Use SSL for some URLs
USE_SSL = False

#: Twitter integration
OAUTH_TWITTER_KEY = ''
OAUTH_TWITTER_SECRET = ''

#: GitHub integration
OAUTH_GITHUB_KEY = ''
OAUTH_GITHUB_SECRET = ''

#: Google integration. Get an app here: https://console.developers.google.com/
GOOGLE_CLIENT_ID = ''
GOOGLE_CLIENT_SECRET = ''
GOOGLE_SCOPE = ['email', 'profile'] # Minimum sccope = ['email', 'profile']

#: Recaptcha for the registration form
RECAPTCHA_USE_SSL = USE_SSL
RECAPTCHA_PUBLIC_KEY = ''
RECAPTCHA_PRIVATE_KEY = ''
RECAPTCHA_OPTIONS = ''

#: SMS gateways
#: SMSGupShup support is deprecated
SMS_SMSGUPSHUP_MASK = ''
SMS_SMSGUPSHUP_USER = ''
SMS_SMSGUPSHUP_PASS = ''
#: Exotel support is active
SMS_EXOTEL_SID = ''
SMS_EXOTEL_TOKEN = ''
SMS_EXOTEL_FROM = ''
#: Twilio support for non-indian numbers
SMS_TWILIO_SID = ''
SMS_TWILIO_TOKEN = ''
SMS_TWILIO_FROM = ''

#: Messages (text or HTML)
MESSAGE_FOOTER = Markup('Copyright &copy; <a href="http://hasgeek.com/">HasGeek</a>. Powered by <a href="https://github.com/hasgeek/lastuser" title="GitHub project page">Lastuser</a>, open source software from <a href="https://github.com/hasgeek">HasGeek</a>.')
USERNAME_REASON = ''
EMAIL_REASON = 'Please provide an email address to complete your profile'
TIMEZONE_REASON = 'Dates and times will be shown in your preferred timezone'
ORG_NAME_REASON = u"Your company’s name as it will appear in the URL. Letters, numbers and dashes only"
ORG_TITLE_REASON = u"Your organization’s given name, preferably without legal suffixes"
LOGIN_MESSAGE_1 = ""
LOGIN_MESSAGE_2 = ""
SMS_VERIFICATION_TEMPLATE = 'Your verification code is {code}. If you did not request this, please ignore.'
CREATE_ACCOUNT_MESSAGE = u"This account is for you as an individual. We’ll make one for your company later"
LOGOUT_UNAUTHORIZED_MESSAGE = "We detected a possibly unauthorized attempt to log you out. If you really did intend to logout, please click on the logout link again"
