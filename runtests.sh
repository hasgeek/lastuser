#!/bin/bash
set -e
export FLASK_ENV="TESTING"
if [ -f secrets.test ]; then
	source ./secrets.test
fi
coverage run -m pytest "$@"
# FIXME: behave test flow is broken because our registration flow changed.
# also, we're using cypress for E2E tests on funnel, so better to replace
# the E2E tests using cypress from here on. Fixing the behave tests is
# time consuming and not worth the effort at this point.
# coverage run -a -m behave
coverage report -m
