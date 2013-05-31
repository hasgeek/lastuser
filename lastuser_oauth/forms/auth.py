# -*- coding: utf-8 -*-

from baseframe.forms import Form


class AuthorizeForm(Form):
    """
    OAuth authorization form. Has no fields and is only used for CSRF protection.
    """
    pass
