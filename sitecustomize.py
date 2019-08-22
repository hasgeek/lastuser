# -*- coding: utf-8 -*-
# Required to make OpenID work with Wordpress (first instance where it came up)
import sys

if not hasattr(sys, 'setdefaultencoding'):
    reload(sys)
sys.setdefaultencoding('utf-8')
