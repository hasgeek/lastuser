#!/bin/sh
export FLASK_ENV="TESTING"
coverage run `which nosetests --with-timer`
coverage report
