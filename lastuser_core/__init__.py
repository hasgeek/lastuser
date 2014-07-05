# -*- coding: utf-8 -*-

from flask import Blueprint
from .registry import ResourceRegistry, OrderedDict

lastuser_core = Blueprint('lastuser_core', __name__)

#: Global resource registry
resource_registry = ResourceRegistry()
login_registry = OrderedDict()

# Register signals
from . import signals
