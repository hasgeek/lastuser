# -*- coding: utf-8 -*-
"""UUIDs for principals

Revision ID: 83d3ede06c
Revises: 2661b24d343f
Create Date: 2016-08-25 11:39:49.416435

"""

# revision identifiers, used by Alembic.
revision = '83d3ede06c'
down_revision = '2661b24d343f'

from alembic import op
from sqlalchemy.sql import column, table
from sqlalchemy_utils import UUIDType
import sqlalchemy as sa

from progressbar import ProgressBar
import progressbar.widgets

from coaster.utils import uuid1mc_from_datetime

user = table(
    'user',
    column('id', sa.Integer()),
    column('created_at', sa.DateTime()),
    column('userid', sa.Unicode(22)),
    column('uuid', UUIDType(binary=False)),
)
organization = table(
    'organization',
    column('id', sa.Integer()),
    column('created_at', sa.DateTime()),
    column('userid', sa.Unicode(22)),
    column('uuid', UUIDType(binary=False)),
)
team = table(
    'team',
    column('id', sa.Integer()),
    column('created_at', sa.DateTime()),
    column('userid', sa.Unicode(22)),
    column('uuid', UUIDType(binary=False)),
)
useroldid = table(
    'useroldid',
    column('user_id', sa.Integer()),
    column('created_at', sa.DateTime()),
    column('userid', sa.Unicode(22)),
    column('uuid', UUIDType(binary=False)),
)


def get_progressbar(label, maxval):
    return ProgressBar(
        maxval=maxval,
        widgets=[
            label,
            ': ',
            progressbar.widgets.Percentage(),
            ' ',
            progressbar.widgets.Bar(),
            ' ',
            progressbar.widgets.ETA(),
            ' ',
        ],
    )


def upgrade():
    conn = op.get_bind()

    # Upgrade Organization
    op.add_column(
        'organization', sa.Column('uuid', UUIDType(binary=False), nullable=True)
    )
    count = conn.scalar(sa.select([sa.func.count('*')]).select_from(organization))
    progress = get_progressbar("Organization", count)
    progress.start()
    items = conn.execute(sa.select([organization.c.id, organization.c.created_at]))
    for counter, item in enumerate(items):
        conn.execute(
            sa.update(organization)
            .where(organization.c.id == item.id)
            .values(uuid=uuid1mc_from_datetime(item.created_at))
        )
        progress.update(counter)
    progress.finish()
    op.alter_column('organization', 'uuid', nullable=False)
    op.create_unique_constraint('organization_uuid_key', 'organization', ['uuid'])

    # Upgrade Team
    op.add_column('team', sa.Column('uuid', UUIDType(binary=False), nullable=True))
    count = conn.scalar(sa.select([sa.func.count('*')]).select_from(team))
    progress = get_progressbar("Team", count)
    progress.start()
    items = conn.execute(sa.select([team.c.id, team.c.created_at]))
    for counter, item in enumerate(items):
        conn.execute(
            sa.update(team)
            .where(team.c.id == item.id)
            .values(uuid=uuid1mc_from_datetime(item.created_at))
        )
        progress.update(counter)
    progress.finish()
    op.alter_column('team', 'uuid', nullable=False)
    op.create_unique_constraint('team_uuid_key', 'team', ['uuid'])

    # Upgrade User
    op.add_column('user', sa.Column('uuid', UUIDType(binary=False), nullable=True))
    count = conn.scalar(sa.select([sa.func.count('*')]).select_from(user))
    progress = get_progressbar("User", count)
    progress.start()
    items = conn.execute(sa.select([user.c.id, user.c.created_at]))
    for counter, item in enumerate(items):
        conn.execute(
            sa.update(user)
            .where(user.c.id == item.id)
            .values(uuid=uuid1mc_from_datetime(item.created_at))
        )
        progress.update(counter)
    progress.finish()
    op.alter_column('user', 'uuid', nullable=False)
    op.create_unique_constraint('user_uuid_key', 'user', ['uuid'])

    # Upgrade UserOldId
    op.add_column('useroldid', sa.Column('uuid', UUIDType(binary=False), nullable=True))
    count = conn.scalar(sa.select([sa.func.count('*')]).select_from(useroldid))
    progress = get_progressbar("Old ids", count)
    progress.start()
    items = conn.execute(
        sa.select([useroldid.c.user_id, useroldid.c.userid, user.c.uuid]).where(
            user.c.userid == useroldid.c.userid
        )
    )
    for counter, item in enumerate(items):
        conn.execute(
            sa.update(useroldid)
            .where(useroldid.c.userid == item.userid)
            .values(uuid=item.uuid)
        )
        progress.update(counter)
    progress.finish()
    op.alter_column('useroldid', 'uuid', nullable=False)
    op.create_unique_constraint('useroldid_uuid_key', 'useroldid', ['uuid'])


def downgrade():
    op.drop_constraint('useroldid_uuid_key', 'useroldid', type_='unique')
    op.drop_column('useroldid', 'uuid')
    op.drop_constraint('user_uuid_key', 'user', type_='unique')
    op.drop_column('user', 'uuid')
    op.drop_constraint('team_uuid_key', 'team', type_='unique')
    op.drop_column('team', 'uuid')
    op.drop_constraint('organization_uuid_key', 'organization', type_='unique')
    op.drop_column('organization', 'uuid')
