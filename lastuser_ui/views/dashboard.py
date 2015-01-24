# -*- coding: utf-8 -*-

from functools import wraps
from flask import g, current_app, abort, render_template

from lastuser_core.models import db, User, USER_STATUS
from .. import lastuser_ui


def requires_dashboard(f):
    """
    Decorator to require a login for the given view.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not g.user or g.user.userid not in current_app.config.get('DASHBOARD_USERS', []):
            abort(403)
        return f(*args, **kwargs)
    return decorated_function


@lastuser_ui.route('/dashboard')
@requires_dashboard
def dashboard():
    user_count = User.query.filter_by(status=USER_STATUS.ACTIVE).count()
    users_by_month = db.session.query('month', 'count').from_statement(db.text(
        '''SELECT date_trunc('month', "user".created_at) AS month, count(*) AS count FROM "user" WHERE status=:status GROUP BY month ORDER BY month'''
        )).params(status=USER_STATUS.ACTIVE)

    mau = db.session.query('mau').from_statement(db.text(
        '''SELECT COUNT(DISTINCT(user_session.user_id)) AS mau FROM user_session, "user" WHERE user_session.user_id = "user".id AND "user".status = :status AND user_session.accessed_at >= NOW() - INTERVAL '30 days' '''
        )).params(status=USER_STATUS.ACTIVE).first()[0]

    client_active_users = db.session.query('client_id', 'count', 'title', 'website').from_statement(db.text(
        '''SELECT client_users.client_id, count(*) AS count, client.title AS title, client.website AS website FROM (SELECT user_session.user_id, session_client.client_id FROM user_session, session_client, "user" WHERE user_session.user_id = "user".id AND session_client.user_session_id = user_session.id AND "user".status = :status AND user_session.accessed_at >= NOW() - INTERVAL '30 days' GROUP BY session_client.client_id, user_session.user_id) AS client_users, client WHERE client.id = client_users.client_id GROUP by client_users.client_id, client.title, client.website ORDER BY count DESC'''
    )).params(status=USER_STATUS.ACTIVE)

    return render_template('dashboard.html',
        user_count=user_count,
        users_by_month=users_by_month,
        mau=mau,
        client_active_users=client_active_users)
