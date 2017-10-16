Lastuser
========

[![Build status](https://secure.travis-ci.org/hasgeek/lastuser.svg?branch=master)](https://travis-ci.org/hasgeek/lastuser) [![Coverage status](https://coveralls.io/repos/hasgeek/lastuser/badge.svg)](https://coveralls.io/r/hasgeek/lastuser)

User management is a pain. Apps shouldn't have their own user management code if it can be centrally managed. Lastuser does it for HasGeek. This open source code release is intended to help you examine our code, work with our APIs, and lend a helping hand where needed.

Usage
-----

Lastuser requires PostgreSQL and Python 2.7. A [virtualenv](https://virtualenv.readthedocs.org/) is strongly recommended. Instructions:

    $ git clone https://github.com/hasgeek/lastuser
    $ cd lastuser
    $ pip install -r requirements.txt
    $ createdb lastuser
    $ cp instance/settings-sample.py instance/development.py

Edit to customize `instance/development.py` as needed, then populate the database:

    $ python manage.py createdb

You should now be able to run the development server, accessible at `http://localhost:7000`:

    $ python runserver.py

To use Lastuser effectively, you will need to create an `/etc/hosts` entry pointing to localhost, for Lastuser and any client apps you may need:

    127.0.0.1 lastuser.mymachine.local
    127.0.0.1 clientapp.mymachine.local

Tests
-----

Before you run the tests:

    $ pip install -r test_requirements.txt
    $ cp secrets.test.sample secrets.test

`secrets.test` contains API keys for various external services Lastuser works with. Note that Lastuser's functional tests are incomplete at this time.

Next, create a test database. Do not use your development database for this as the test database is wiped after each run of the test suite:

    $ createdb lastuser_test_app

Run the tests from the root directory of the project:

    $ ./runtests.sh

Support
-------

Feel free to file a bug report for anything that doesn't work or is amiss in our code. We're available for a chat in #tech on [friends.hasgeek.com](http://friendsofhasgeek.slack.com).
