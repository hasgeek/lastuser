# -*- coding: utf-8 -*-

from flask import Blueprint
from .registry import ResourceRegistry, LoginProviderRegistry, OrderedDict

lastuser_core = Blueprint('lastuser_core', __name__)

#: Global resource registry
resource_registry = ResourceRegistry()
login_registry = LoginProviderRegistry()
channel_registry = OrderedDict()

# Register signals
from . import signals  # NOQA
