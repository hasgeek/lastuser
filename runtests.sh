#!/bin/sh
set -e
export FLASK_ENV="TESTING"
if [ -f secrets.test ]; then
	source ./secrets.test
fi
coverage run `which nosetests` "$@"
coverage run -a `which behave`
coverage report -m
