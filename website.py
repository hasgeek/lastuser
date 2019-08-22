# -*- coding: utf-8 -*-

import os.path
import sys

from lastuserapp import app as application

sys.path.insert(0, os.path.dirname(__file__))

__all__ = ['application']
