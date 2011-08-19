# -*- coding: utf-8 -*-

# Id generation
from random import randint
import uuid
from base64 import urlsafe_b64encode
import re
import urlparse
from urllib import urlencode as make_query_string

# --- Constants ---------------------------------------------------------------

USERNAME_VALID_RE = re.compile('^[a-z0-9][a-z0-9-_\.]*[a-z0-9]$')
PHONE_STRIP_RE = re.compile(r'[\t .()\[\]-]+')
PHONE_VALID_RE = re.compile(r'^\+[0-9]+$')

# --- Utilities ---------------------------------------------------------------

def newid():
    """
    Return a new random id that is exactly 22 characters long. See
    http://en.wikipedia.org/wiki/Base64#Variants_summary_table
    for URL-safe Base64
    """
    return urlsafe_b64encode(uuid.uuid4().bytes).rstrip('=')


def newsecret():
    """
    Cheap OAuth secret generator.
    """
    return newid()+newid()

def newpin(digits=4):
    """
    Return a random numeric string with the specified number of digits, default 4
    """
    return (u'%%0%dd' % digits) % randint(0, 10**digits)


def make_redirect_url(url, **params):
    urlparts = list(urlparse.urlsplit(url))
    # URL parts:
    # 0: scheme
    # 1: netloc
    # 2: path
    # 3: query -- appended to
    # 4: fragment
    queryparts = urlparse.parse_qsl(urlparts[3], keep_blank_values=True)
    queryparts.extend(params.items())
    urlparts[3] = make_query_string(queryparts)
    return urlparse.urlunsplit(urlparts)


def valid_username(candidate):
    return not USERNAME_VALID_RE.search(candidate) is None

def strip_phone(candidate):
    return PHONE_STRIP_RE.sub('', candidate)

def valid_phone(candidate):
    return not PHONE_VALID_RE.search(candidate) is None
