# -*- coding: utf-8 -*-

# Id generation
import uuid
from base64 import urlsafe_b64encode
import re
import urlparse
from urllib import urlencode as make_query_string


# --- Constants ---------------------------------------------------------------

USERNAME_INVALID_RE = re.compile(r'\W', re.U)

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
    return not USERNAME_INVALID_RE.search(candidate) is None
