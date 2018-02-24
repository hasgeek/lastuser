#!/bin/sh
set -e
export FLASK_ENV="TESTING"
if [ -f secrets.test ]; then
	source ./secrets.test
fi
coverage run -m pytest "$@"
coverage run -a -m behave
coverage report -m
