# -*- coding: utf-8 -*-

import unittest

from lastuser_core.utils import (
    make_redirect_url,
    mask_email,
    strip_phone,
    valid_phone,
)


class FlaskrTestCase(unittest.TestCase):
    def test_strip_phone(self):
        """
        Check if given has spaces or dashes and strip it

        """
        self.assertEqual(strip_phone('+91-7676-33-2020'), '+917676332020')
        self.assertEqual(strip_phone('+91 7676 33 2020'), '+917676332020')

    def test_valid_phone(self):
        """
        Check if given is a valid phone number.

        """
        assert valid_phone('+917676332020') is True
        assert valid_phone('+91 7676 33 2020') is False
        assert valid_phone('A91 7676 3A3 2020') is False
        assert valid_phone('*^$&766767**^&^') is False

    def test_make_redirect_url(self):
        # scenario 1: straight forward splitting
        result = make_redirect_url('http://example.com/?foo=bar', foo='baz')
        expected_result = 'http://example.com/?foo=bar&foo=baz'
        self.assertEqual(result, expected_result)

        # scenario 2: with use_fragment set as True
        result = make_redirect_url(
            'http://example.com/?foo=bar', use_fragment=True, foo='baz'
        )
        expected_result = 'http://example.com/?foo=bar#foo=baz'
        self.assertEqual(result, expected_result)

    def test_mask_email(self):
        self.assertEqual(mask_email('foobar@example.com'), 'f****@e****')
