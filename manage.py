#!/usr/bin/env python
# -*- coding: utf-8 -*-

from coaster.manage import Manager, init_manager
from lastuser_core.models import db
from lastuserapp import app
import lastuser_core
import lastuser_core.models as models
import lastuser_oauth
import lastuser_ui
import lastuserapp

periodic = Manager(usage="Periodic tasks from cron (with recommended intervals)")


@periodic.command
def phoneclaims():
    """Sweep phone claims to close all unclaimed beyond expiry period (10m)"""
    models.UserPhoneClaim.delete_expired()
    db.session.commit()


if __name__ == '__main__':
    db.init_app(app)
    manager = init_manager(
        app,
        db,
        lastuser_core=lastuser_core,
        lastuser_oauth=lastuser_oauth,
        lastuser_ui=lastuser_ui,
        lastuserapp=lastuserapp,
        models=models,
    )
    manager.add_command('periodic', periodic)
    manager.run()
