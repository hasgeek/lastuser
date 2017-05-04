#!/usr/bin/env python

from coaster.manage import init_manager

import lastuser_core
import lastuser_oauth
import lastuser_ui
import lastuserapp
import lastuser_core.models as models
from lastuser_core.models import db
from lastuserapp import app


if __name__ == '__main__':
    db.init_app(app)
    manager = init_manager(app, db, lastuser_core=lastuser_core, lastuser_oauth=lastuser_oauth, lastuser_ui=lastuser_ui, lastuserapp=lastuserapp, models=models)
    manager.run()
