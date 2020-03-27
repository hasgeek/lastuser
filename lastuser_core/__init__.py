# -*- coding: utf-8 -*-

from flask import Blueprint

from .registry import LoginProviderRegistry, ResourceRegistry

lastuser_core = Blueprint('lastuser_core', __name__)

#: Global resource registry
resource_registry = ResourceRegistry()
login_registry = LoginProviderRegistry()

# Register signals
from . import signals  # NOQA  # isort:skip
