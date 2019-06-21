import sys
import os.path
sys.path.insert(0, os.path.dirname(__file__))
from lastuserapp import app as application

__all__ = ['application']
