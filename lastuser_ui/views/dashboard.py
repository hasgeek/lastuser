# -*- coding: utf-8 -*-

from functools import wraps
from collections import defaultdict
from cStringIO import StringIO
import unicodecsv
from flask import current_app, abort, render_template
from coaster.auth import current_auth

from lastuser_core.models import db, User, USER_STATUS
from .. import lastuser_ui


def requires_dashboard(f):
    """
    Decorator to require a login for the given view.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_auth.is_authenticated or current_auth.user.buid not in current_app.config.get('DASHBOARD_USERS', []):
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


@lastuser_ui.route('/dashboard')
@requires_dashboard
def dashboard():
    user_count = User.query.filter_by(status=USER_STATUS.ACTIVE).count()
    mau = db.session.query('mau').from_statement(db.text(
        '''SELECT COUNT(DISTINCT(user_session.user_id)) AS mau FROM user_session, "user" WHERE user_session.user_id = "user".id AND "user".status = :status AND user_session.accessed_at >= (NOW() AT TIME ZONE 'UTC') - INTERVAL '30 days' '''
        )).params(status=USER_STATUS.ACTIVE).first()[0]

    return render_template('dashboard.html.jinja2',
        user_count=user_count,
        mau=mau
        )


@lastuser_ui.route('/dashboard/data/users_by_month.csv')
@requires_dashboard
def dashboard_data_users_by_month():
    users_by_month = db.session.query('month', 'count').from_statement(db.text(
        '''SELECT date_trunc('month', "user".created_at) AS month, count(*) AS count FROM "user" WHERE status=:status GROUP BY month ORDER BY month'''
        )).params(status=USER_STATUS.ACTIVE)

    outfile = StringIO()
    out = unicodecsv.writer(outfile, 'excel')
    out.writerow(['month', 'count'])
    for month, count in users_by_month:
        out.writerow([month.strftime('%Y-%m-%d'), count])
    return outfile.getvalue(), 200, {'Content-Type': 'text/plain'}


@lastuser_ui.route('/dashboard/data/users_by_client.csv')
@requires_dashboard
def dashboard_data_users_by_client():
    client_users = defaultdict(lambda: {'counts': {'hour': 0, 'day': 0, 'week': 0, 'month': 0, 'quarter': 0, 'halfyear': 0, 'year': 0}})

    for label, interval in (
            ('hour', '1 hour'),
            ('day', '1 day'),
            ('week', '1 week'),
            ('month', '1 month'),
            ('quarter', '3 months'),
            ('halfyear', '6 months'),
            ('year', '1 year'),
            ):
        clients = db.session.query('client_id', 'count', 'title', 'website').from_statement(db.text(
            '''SELECT client_users.client_id, count(*) AS count, client.title AS title, client.website AS website FROM (SELECT user_session.user_id, session_client.client_id FROM user_session, session_client, "user" WHERE user_session.user_id = "user".id AND session_client.user_session_id = user_session.id AND "user".status = :status AND session_client.updated_at >= (NOW() AT TIME ZONE 'UTC') - INTERVAL :interval GROUP BY session_client.client_id, user_session.user_id) AS client_users, client WHERE client.id = client_users.client_id GROUP by client_users.client_id, client.title, client.website ORDER BY count DESC'''
        )).params(status=USER_STATUS.ACTIVE, interval=interval).all()
        for row in clients:
            client_users[row.client_id]['title'] = row.title
            client_users[row.client_id]['website'] = row.website
            client_users[row.client_id]['id'] = row.client_id
            client_users[row.client_id]['counts'][label] = row.count - sum(client_users[row.client_id]['counts'].values())

    users_by_client = sorted(client_users.values(), key=lambda r: sum(r['counts'].values()), reverse=True)

    outfile = StringIO()
    out = unicodecsv.writer(outfile, 'excel')
    out.writerow(['title', 'hour', 'day', 'week', 'month', 'quarter', 'halfyear', 'year'])

    for row in users_by_client:
        out.writerow([
            row['title'],
            row['counts']['hour'],
            row['counts']['day'],
            row['counts']['week'],
            row['counts']['month'],
            row['counts']['quarter'],
            row['counts']['halfyear'],
            row['counts']['year']
            ])
    return outfile.getvalue(), 200, {'Content-Type': 'text/plain'}
