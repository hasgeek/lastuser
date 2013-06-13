#!/usr/bin/env python
import os
import readline
from pprint import pprint

os.environ['LASTUSER_ENV'] = 'dev'

from lastuserapp import *
from lastuser_core import models
from lastuser_core.models import db


os.environ['PYTHONINSPECT'] = 'True'
