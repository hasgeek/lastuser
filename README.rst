Lastuser
========

User management is a pain. There's no need to write new user management code
for each new app to do basic things like logging in, managing the profile and
verifying email addresses. Setup one Lastuser instance for all your apps and
defer all user management to it. Use the API to integrate with your app.

This project is a work in progress.


Test deployment
---------------

Here is how you make a test deployment::

    $ git clone https://github.com/hasgeek/lastuser
    $ cd lastuser
    $ cp instance/settings-sample.py instance/settings.py
    $ open instance/settings.py # Customize this file as needed
    $ pip install -r requirements.txt
    $ python runserver.py

You may also want to setup the database with::

    $ python manage.py db create

For development setup, you can also set the `CACHE_TYPE` to `simple` in `instance/settings.py` or in `instance/development.py`::

    #: Cache type
    CACHE_TYPE = 'simple'

