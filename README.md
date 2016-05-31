Lastuser
========

User management is a pain. There's no need to write new user management code for
each new app to do basic things like logging in, managing the profile and
verifying email addresses. Setup one Lastuser instance for all your apps and
defer all user management to it. Use the API to integrate with your app.

Usage
-----

To install and run Lastuser on your computer:

	$ git clone https://github.com/hasgeek/lastuser
	$ cd lastuser
  $ cp instance/settings-sample.py instance/development.py

	Edit to customize `instance/development.py` as needed.

	$ python manage.py db create

	Setup [Virtualenv](https://virtualenv.readthedocs.org/) for this directory.

	$ pip install -r requirements.txt
	$ python runserver.py

Your Lastuser server will now be accessible at `http://localhost:7000`.

Tests
-----

### Integration

Integration tests serve to verify server responses are correct.

    $ which npm # Check if you have NPM installed
    $ npm install -g casperjs phantomjs # Install CasperJS and PhantomJS system-wide
    $ dropdb lastuser_test_app && createdb lastuser_test_app # Drop any old testing db that may have remained and create again

At this point, please note that `instance/testing.py` requires third-party services' API keys. We suggest you create a `secrets.test` and export all confidential keys required for testing in it.

    $ source secrets.test
    $ python runtestserver.py # Run the test server
    $ source tests/integration/set_test_credentials.sh # Populate the required environment variables
    $ casperjs test /path/to/casperjs_test_file

Support
-------

Feel free to file a bug report for anything that doesn't work or is amiss in our code. When in doubt, leave us a message in #tech on [friendsofhasgeek.slack.com](http://friendsofhasgeek.slack.com).
