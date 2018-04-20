# -*- coding: utf-8 -*-

# Id generation
import re
import urlparse
from urllib import urlencode as make_query_string

# --- Constants ---------------------------------------------------------------

PHONE_STRIP_RE = re.compile(r'[\t .()\[\]-]+')
PHONE_VALID_RE = re.compile(r'^\+[0-9]+$')

# --- Utilities ---------------------------------------------------------------


def make_redirect_url(url, use_fragment=False, **params):
    urlparts = list(urlparse.urlsplit(url))
    # URL parts:
    # 0: scheme
    # 1: netloc
    # 2: path
    # 3: query -- appended to
    # 4: fragment
    queryparts = urlparse.parse_qsl(urlparts[4] if use_fragment else urlparts[3], keep_blank_values=True)
    queryparts.extend([(k, v) for k, v in params.items() if v is not None])
    queryparts = [(key.encode('utf-8') if isinstance(key, unicode) else key,
                   value.encode('utf-8') if isinstance(value, unicode) else value) for key, value in queryparts]
    if use_fragment:
        urlparts[4] = make_query_string(queryparts)
    else:
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


def mask_email(email):
    """
    Masks an email address

    >>> mask_email(u'foobar@example.com')
    u'f****@e****'

    """
    if '@' not in email:
        return email
    username, domain = email.split('@')
    masked_username = username.replace(username[1:], '*' * 4)
    masked_domain = domain.replace(domain[1:], '*' * 4)
    return u'@'.join([masked_username, masked_domain])
