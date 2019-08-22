# -*- coding: utf-8 -*-
"""Replace userid of principals with uuid

Revision ID: 4e206c5ddabd
Revises: 83d3ede06c
Create Date: 2017-06-28 18:17:08.664550

"""
from alembic import op
from sqlalchemy.sql import column, table
from sqlalchemy_utils import UUIDType
import sqlalchemy as sa

from progressbar import ProgressBar
import progressbar.widgets

from coaster.utils import buid2uuid, uuid2buid

# revision identifiers, used by Alembic.
revision = '4e206c5ddabd'
down_revision = '83d3ede06c'
branch_labels = None
depends_on = None


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
    column('id', UUIDType(binary=False)),
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
    # For each principal table:
    # 1. Replace the contents of the uuid column (currently a random value) with buid2uuid(userid)
    # 2. Drop the userid column

    # For OldUserId table:
    # 1. Replace uuid (the matching random value) with fresh values from buid2uuid(userid)
    # 2. Drop userid primary constraint and column
    # 3. Rename uuid column to id column
    # 4. Make id the primary key

    conn = op.get_bind()

    # Upgrade Organization
    count = conn.scalar(sa.select([sa.func.count('*')]).select_from(organization))
    progress = get_progressbar("Organization", count)
    progress.start()
    items = conn.execute(sa.select([organization.c.id, organization.c.userid]))
    for counter, item in enumerate(items):
        conn.execute(
            sa.update(organization)
            .where(organization.c.id == item.id)
            .values(uuid=buid2uuid(item.userid))
        )
        progress.update(counter)
    progress.finish()

    op.drop_constraint(u'organization_userid_key', 'organization', type_='unique')
    op.drop_column('organization', 'userid')

    # Upgrade Team
    count = conn.scalar(sa.select([sa.func.count('*')]).select_from(team))
    progress = get_progressbar("Team", count)
    progress.start()
    items = conn.execute(sa.select([team.c.id, team.c.userid]))
    for counter, item in enumerate(items):
        conn.execute(
            sa.update(team)
            .where(team.c.id == item.id)
            .values(uuid=buid2uuid(item.userid))
        )
        progress.update(counter)
    progress.finish()

    op.drop_constraint(u'team_userid_key', 'team', type_='unique')
    op.drop_column('team', 'userid')

    # Upgrade User
    count = conn.scalar(sa.select([sa.func.count('*')]).select_from(user))
    progress = get_progressbar("User", count)
    progress.start()
    items = conn.execute(sa.select([user.c.id, user.c.userid]))
    for counter, item in enumerate(items):
        conn.execute(
            sa.update(user)
            .where(user.c.id == item.id)
            .values(uuid=buid2uuid(item.userid))
        )
        progress.update(counter)
    progress.finish()

    op.drop_constraint(u'user_userid_key', 'user', type_='unique')
    op.drop_column('user', 'userid')

    # Upgrade UserOldId
    count = conn.scalar(sa.select([sa.func.count('*')]).select_from(useroldid))
    progress = get_progressbar("Old ids", count)
    progress.start()
    items = conn.execute(sa.select([useroldid.c.userid]))
    for counter, item in enumerate(items):
        conn.execute(
            sa.update(useroldid)
            .where(useroldid.c.userid == item.userid)
            .values(uuid=buid2uuid(item.userid))
        )
        progress.update(counter)
    progress.finish()

    op.drop_constraint('useroldid_pkey', 'useroldid', type_='primary')
    op.drop_column('useroldid', 'userid')
    op.drop_constraint('useroldid_uuid_key', 'useroldid', type_='unique')
    op.alter_column('useroldid', 'uuid', new_column_name='id')
    op.create_primary_key('useroldid_pkey', 'useroldid', ['id'])


def downgrade():
    # For each principal table:
    # 1. Create a userid column
    # 2. Populate userid with uuid2buid(uuid)
    # 3. Make userid non-nullable
    # 4. Since the previous uuid was random (pre-upgrade), don't bother to replace it

    # For OldUserId table:
    # 1. Make a userid column
    # 2. Populate userid with uuid2buid(id)
    # 3. Drop id primary constraint and column
    # 4. Make userid non-nullable and add a primary key constraint

    conn = op.get_bind()

    # Downgrade Organization
    op.add_column('organization', sa.Column('userid', sa.String(22), nullable=True))
    count = conn.scalar(sa.select([sa.func.count('*')]).select_from(organization))
    progress = get_progressbar("Organization", count)
    progress.start()
    items = conn.execute(sa.select([organization.c.id, organization.c.uuid]))
    for counter, item in enumerate(items):
        conn.execute(
            sa.update(organization)
            .where(organization.c.id == item.id)
            .values(userid=uuid2buid(item.uuid))
        )
        progress.update(counter)
    progress.finish()

    op.alter_column('organization', 'userid', nullable=False)
    op.create_unique_constraint('organization_userid_key', 'organization', ['userid'])

    # Downgrade Team
    op.add_column('team', sa.Column('userid', sa.String(22), nullable=True))
    count = conn.scalar(sa.select([sa.func.count('*')]).select_from(team))
    progress = get_progressbar("Team", count)
    progress.start()
    items = conn.execute(sa.select([team.c.id, team.c.uuid]))
    for counter, item in enumerate(items):
        conn.execute(
            sa.update(team)
            .where(team.c.id == item.id)
            .values(userid=uuid2buid(item.uuid))
        )
        progress.update(counter)
    progress.finish()

    op.alter_column('team', 'userid', nullable=False)
    op.create_unique_constraint('team_userid_key', 'team', ['userid'])

    # Downgrade User
    op.add_column('user', sa.Column('userid', sa.String(22), nullable=True))
    count = conn.scalar(sa.select([sa.func.count('*')]).select_from(user))
    progress = get_progressbar("User", count)
    progress.start()
    items = conn.execute(sa.select([user.c.id, user.c.uuid]))
    for counter, item in enumerate(items):
        conn.execute(
            sa.update(user)
            .where(user.c.id == item.id)
            .values(userid=uuid2buid(item.uuid))
        )
        progress.update(counter)
    progress.finish()

    op.alter_column('user', 'userid', nullable=False)
    op.create_unique_constraint('user_userid_key', 'user', ['userid'])

    # Downgrade UserOldId
    op.add_column('useroldid', sa.Column('userid', sa.String(22), nullable=True))
    count = conn.scalar(sa.select([sa.func.count('*')]).select_from(useroldid))
    progress = get_progressbar("Old ids", count)
    progress.start()
    items = conn.execute(sa.select([useroldid.c.id]))
    for counter, item in enumerate(items):
        conn.execute(
            sa.update(useroldid)
            .where(useroldid.c.id == item.id)
            .values(userid=uuid2buid(item.id))
        )
        progress.update(counter)
    progress.finish()

    op.alter_column('useroldid', 'userid', nullable=False)
    op.drop_constraint('useroldid_pkey', 'useroldid', type_='primary')
    op.alter_column('useroldid', 'id', new_column_name='uuid')
    op.create_unique_constraint('useroldid_uuid_key', 'useroldid', ['uuid'])
    op.create_primary_key('useroldid_pkey', 'useroldid', ['userid'])
