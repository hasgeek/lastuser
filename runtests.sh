#!/bin/sh
set -e
export FLASK_ENV="TESTING"
coverage run `which nosetests` "$@"
coverage run -a `which behave`
coverage report -m
