# -*- coding: utf-8 -*-

from urllib.parse import urlencode as make_query_string
import re
import urllib.parse

# --- Constants ---------------------------------------------------------------

PHONE_STRIP_RE = re.compile(r'[\t .()\[\]-]+')
PHONE_VALID_RE = re.compile(r'^\+[0-9]+$')

# --- Utilities ---------------------------------------------------------------


def make_redirect_url(url, use_fragment=False, **params):
    urlparts = list(urllib.parse.urlsplit(url))
    # URL parts:
    # 0: scheme
    # 1: netloc
    # 2: path
    # 3: query -- appended to
    # 4: fragment
    queryparts = urllib.parse.parse_qsl(
        urlparts[4] if use_fragment else urlparts[3], keep_blank_values=True
    )
    queryparts.extend([(k, v) for k, v in params.items() if v is not None])
    queryparts = [
        (
            key.encode('utf-8') if isinstance(key, str) else key,
            value.encode('utf-8') if isinstance(value, str) else value,
        )
        for key, value in queryparts
    ]
    if use_fragment:
        urlparts[4] = make_query_string(queryparts)
    else:
        urlparts[3] = make_query_string(queryparts)
    return urllib.parse.urlunsplit(urlparts)


def strip_phone(candidate):
    return PHONE_STRIP_RE.sub('', candidate)


def valid_phone(candidate):
    return not PHONE_VALID_RE.search(candidate) is None


def mask_email(email):
    """
    Masks an email address

    >>> mask_email(u'foobar@example.com')
    u'f****@e****'
    >>> mask_email(u'not-email')
    u'n****'
    """
    if '@' not in email:
        return '{e}****'.format(e=email[0])
    username, domain = email.split('@')
    return '{u}****@{d}****'.format(u=username[0], d=domain[0])
