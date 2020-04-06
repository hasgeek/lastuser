# -*- coding: utf-8 -*-
"""Use UUID for user_session

Revision ID: 87fc422c81f9
Revises: 039d2745e628
Create Date: 2020-04-06 13:19:16.712585

"""
from alembic import op
from sqlalchemy.sql import column, table
from sqlalchemy_utils import UUIDType
import sqlalchemy as sa

from progressbar import ProgressBar
import progressbar.widgets

from coaster.utils import buid2uuid, uuid2buid

# revision identifiers, used by Alembic.
revision = '87fc422c81f9'
down_revision = '039d2745e628'
branch_labels = None
depends_on = None

user_session = table(
    'user_session',
    column('id', sa.Integer()),
    column('buid', sa.Unicode(22)),
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
    op.add_column(
        'user_session', sa.Column('uuid', UUIDType(binary=False), nullable=True)
    )

    conn = op.get_bind()
    count = conn.scalar(sa.select([sa.func.count('*')]).select_from(user_session))
    progress = get_progressbar("User Session", count)
    progress.start()
    items = conn.execute(sa.select([user_session.c.id, user_session.c.buid]))
    for counter, item in enumerate(items):
        conn.execute(
            sa.update(user_session)
            .where(user_session.c.id == item.id)
            .values(uuid=buid2uuid(item.buid))
        )
        progress.update(counter)
    progress.finish()

    op.alter_column('user_session', 'uuid', nullable=False)
    op.drop_constraint('user_session_buid_key', 'user_session', type_='unique')
    op.create_unique_constraint('user_session_uuid_key', 'user_session', ['uuid'])
    op.drop_column('user_session', 'buid')


def downgrade():
    op.add_column(
        'user_session', sa.Column('buid', sa.VARCHAR(length=22), nullable=True)
    )

    conn = op.get_bind()
    count = conn.scalar(sa.select([sa.func.count('*')]).select_from(user_session))
    progress = get_progressbar("User Session", count)
    progress.start()
    items = conn.execute(sa.select([user_session.c.id, user_session.c.uuid]))
    for counter, item in enumerate(items):
        conn.execute(
            sa.update(user_session)
            .where(user_session.c.id == item.id)
            .values(buid=uuid2buid(item.uuid))
        )
        progress.update(counter)
    progress.finish()

    op.alter_column('user_session', 'buid', nullable=False)
    op.drop_constraint('user_session_uuid_key', 'user_session', type_='unique')
    op.create_unique_constraint('user_session_buid_key', 'user_session', ['buid'])
    op.drop_column('user_session', 'uuid')
