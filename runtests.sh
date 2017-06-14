#!/bin/sh
set -e
export FLASK_ENV="TESTING"
coverage run `which nosetests --with-timer`
coverage report
