#!/usr/bin/env python

from coaster.manage import init_manager

from lastuser_core.models import db
from lastuserapp import app, init_for


if __name__ == "__main__":
    manager = init_manager(app, db, init_for)
    manager.run()
