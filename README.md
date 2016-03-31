Lastuser
========

User management is a pain. There's no need to write new user management code for
each new app to do basic things like logging in, managing the profile and
verifying email addresses. Setup one Lastuser instance for all your apps and
defer all user management to it. Use the API to integrate with your app.

Usage
-----

To install and run LastUser on your computer:

	$ git clone https://github.com/hasgeek/lastuser
	$ cd lastuser
  $ cp instance/settings-sample.py instance/development.py

	Edit to customize `instance/development.py` as needed.

	$ python manage.py db create

	Setup [Virtualenv](https://virtualenv.readthedocs.org/) for this directory.

	$ pip install -r requirements.txt
	$ python runserver.py

Your LastUser server will now be accessible at `http://localhost:7000`.

Tests
-----

### Unit

Unit tests are in place to test a single unit of the code, usually a method/function.

Before you run the tests:

		$ cp secrets.test.sample secrets.test

Populate this file with values pertaining to components you would want enabled.
Note that API keys for Twitter, Github and Google are necessary as some Tests
depend on those components being enabled. To set secrets in your environment:

		$ source secrets.test

Now, create the test database with:

		$ createdb lastuser_test_app

Run the tests from the root directory of the project:

		$ nosetests

To see code coverage statistics:

		$ cd tests
		$ nosetests --with-coverage --cover-package=lastuser_core,lastuser_oauth

Optionally you can include the `--with-timer` flag with the `nosetests` command to see if there are tests that take longer than 1 second each.

Support
-------

Feel free to file a bug report for anything that doesn't work or is amiss in our code. When in doubt, leave us a message in #tech on [friendsofhasgeek.slack.com](http://friendsofhasgeek.slack.com).
