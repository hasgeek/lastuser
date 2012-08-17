#!/usr/bin/env python
import os
import readline
from pprint import pprint

os.environ['LASTUSER_ENV'] = 'dev'

from flask import *
from lastuserapp import *

os.environ['PYTHONINSPECT'] = 'True'
