# -*- coding: utf-8 -*-

import baseframe.forms as forms


class AuthorizeForm(forms.Form):
    """
    OAuth authorization form. Has no fields and is only used for CSRF protection.
    """
