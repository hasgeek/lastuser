import sys
import os, os.path
sys.path.insert(0, os.path.dirname(__file__))
os.environ['LASTUSER_ENV'] = 'production'
from lastuserapp import app as application
