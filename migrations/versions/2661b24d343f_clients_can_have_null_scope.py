# -*- coding: utf-8 -*-
"""Clients can have null scope

Revision ID: 2661b24d343f
Revises: 3d4b7578d2e9
Create Date: 2016-02-20 20:29:13.042232

"""

# revision identifiers, used by Alembic.
revision = '2661b24d343f'
down_revision = '3d4b7578d2e9'

from alembic import op
import sqlalchemy as sa

client = sa.sql.table('client', sa.sql.column('scope', sa.TEXT()))


def upgrade():
    op.alter_column('client', 'scope', existing_type=sa.TEXT(), nullable=True)
    op.execute(client.update().where(client.c.scope == '').values({'scope': None}))


def downgrade():
    op.alter_column(
        'client', 'scope', existing_type=sa.TEXT(), nullable=False, server_default=''
    )
    op.alter_column('client', 'scope', server_default=None)
