# -*- coding: utf-8 -*-

# Id generation
from random import randint
import uuid
from base64 import urlsafe_b64encode
import re
import urlparse
from urllib import urlencode as make_query_string

# --- Constants ---------------------------------------------------------------

USERNAME_VALID_RE = re.compile('^[a-z0-9][a-z0-9-]*[a-z0-9]$')
PHONE_STRIP_RE = re.compile(r'[\t .()\[\]-]+')
PHONE_VALID_RE = re.compile(r'^\+[0-9]+$')

# --- Utilities ---------------------------------------------------------------


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


def strip_phone(candidate):
    return PHONE_STRIP_RE.sub('', candidate)


def valid_phone(candidate):
    return not PHONE_VALID_RE.search(candidate) is None


def get_gravatar_md5sum(url):
    """
    Retrieve the MD5 sum from a Gravatar URL. Returns None if the URL is invalid.

    >>> get_gravatar_md5sum(
    ...     'https://secure.gravatar.com/avatar/31b0e7df40a7e327e7908f61a314fe47?d=https'
    ...     '://a248.e.akamai.net/assets.github.com%2Fimages%2Fgravatars%2Fgravatar-140.png')
    '31b0e7df40a7e327e7908f61a314fe47'
    """
    parts = urlparse.urlparse(url)
    if parts.netloc not in ['www.gravatar.com', 'secure.gravatar.com', 'gravatar.com']:
        return None
    if not parts.path.startswith('/avatar/'):
        return None
    md5sum = parts.path.split('/')[2]
    if len(md5sum) != 32:
        return None
    return md5sum
