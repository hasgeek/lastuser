# -*- coding: utf-8 -*-
"""Make client.key a UUID

Revision ID: 8a9bf9d385c2
Revises: f65c00c0cfc3
Create Date: 2020-03-20 18:43:41.802182

"""
from alembic import op
from sqlalchemy.sql import column, table
from sqlalchemy_utils import UUIDType
import sqlalchemy as sa

from progressbar import ProgressBar
import progressbar.widgets

from coaster.utils import buid2uuid, uuid2buid

# revision identifiers, used by Alembic.
revision = '8a9bf9d385c2'
down_revision = 'f65c00c0cfc3'
branch_labels = None
depends_on = None


client = table(
    'client',
    column('id', sa.Integer()),
    column('key', sa.Unicode(22)),
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
    op.add_column('client', sa.Column('uuid', UUIDType(binary=False), nullable=True))

    conn = op.get_bind()
    count = conn.scalar(sa.select([sa.func.count('*')]).select_from(client))
    progress = get_progressbar("Clients", count)
    progress.start()
    items = conn.execute(sa.select([client.c.id, client.c.key]))
    for counter, item in enumerate(items):
        conn.execute(
            sa.update(client)
            .where(client.c.id == item.id)
            .values(uuid=buid2uuid(item.key))
        )
        progress.update(counter)
    progress.finish()

    op.alter_column('client', 'uuid', nullable=False)
    op.drop_constraint('client_key_key', 'client', type_='unique')
    op.create_unique_constraint('client_uuid_key', 'client', ['uuid'])
    op.drop_column('client', 'key')


def downgrade():
    op.add_column(
        'client',
        sa.Column('key', sa.VARCHAR(length=22), autoincrement=False, nullable=False),
    )

    conn = op.get_bind()
    count = conn.scalar(sa.select([sa.func.count('*')]).select_from(client))
    progress = get_progressbar("Clients", count)
    progress.start()
    items = conn.execute(sa.select([client.c.id, client.c.uuid]))
    for counter, item in enumerate(items):
        conn.execute(
            sa.update(client)
            .where(client.c.id == item.id)
            .values(key=uuid2buid(item.uuid))
        )
        progress.update(counter)
    progress.finish()

    op.drop_constraint('client_uuid_key', 'client', type_='unique')
    op.create_unique_constraint('client_key_key', 'client', ['key'])
    op.drop_column('client', 'uuid')
