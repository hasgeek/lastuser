# -*- coding: utf-8 -*-

#: The title of this site
SITE_TITLE='LastUser'
#: Support contact email
SITE_SUPPORT_EMAIL = 'test@example.com'
#: TypeKit code for fonts
TYPEKIT_CODE=''
#: Google Analytics code UA-XXXXXX-X
GA_CODE=''
#: Database backend
SQLALCHEMY_DATABASE_URI = 'sqlite:///test.db'
#: Secret key
SECRET_KEY = 'make this something random'
#: Timezone
TIMEZONE = 'Asia/Calcutta'
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
DEFAULT_MAIL_SENDER = ('LastUser', 'test@example.com')
#: Logging: recipients of error emails
ADMINS=[]
#: Log file
LOGFILE='error.log'
#: Use SSL for some URLs
USE_SSL=False
#: Twitter integration
OAUTH_TWITTER_KEY=''
OAUTH_TWITTER_SECRET=''
#: Recaptcha for the registration form
RECAPTCHA_USE_SSL=USE_SSL
RECAPTCHA_PUBLIC_KEY=''
RECAPTCHA_PRIVATE_KEY=''
RECAPTCHA_OPTIONS=''
#: Messages (in markdown)
MESSAGE_FOOTER='Copyright &copy; HasGeek. Powered by LastUser, open source software from HasGeek.'
