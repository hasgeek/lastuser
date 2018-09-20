#!/usr/bin/env python

from datetime import datetime, timedelta
from coaster.manage import init_manager, Manager

import lastuser_core
import lastuser_oauth
import lastuser_ui
import lastuserapp
import lastuser_core.models as models
from lastuser_core.models import db
from lastuserapp import app

periodic = Manager(usage="Periodic tasks from cron (with recommended intervals)")


@periodic.command
def phoneclaims():
    """Sweep phone claims to close all unclaimed beyond expiry period (10m)"""
    pc = models.UserPhoneClaim
    pc.query.filter(
        pc.updated_at < (datetime.utcnow() - timedelta(hours=1)),
        pc.verification_expired
        ).delete()
    db.session.commit()


if __name__ == '__main__':
    db.init_app(app)
    manager = init_manager(app, db, lastuser_core=lastuser_core, lastuser_oauth=lastuser_oauth, lastuser_ui=lastuser_ui, lastuserapp=lastuserapp, models=models)
    manager.add_command('periodic', periodic)
    manager.run()
