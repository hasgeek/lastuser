#!/bin/sh
set -e
export FLASK_ENV="TESTING"
coverage run `which nosetests --with-timer` && coverage report
coverage run `which behave` && coverage report
