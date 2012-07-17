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
    $ cp lastuserapp/settings-sample.py lastuserapp/settings.py
    $ open lastuserapp/settings.py # Customize this file as needed
    $ python setup.py develop
    $ python runserver.py
