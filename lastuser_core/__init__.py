# -*- coding: utf-8 -*-

from flask import Blueprint
from lastuser_core.registry import ResourceRegistry, LoginProviderRegistry

lastuser_core = Blueprint('lastuser_core', __name__)

#: Global resource registry
resource_registry = ResourceRegistry()
login_registry = LoginProviderRegistry()
