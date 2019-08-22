# -*- coding: utf-8 -*-
"""Scope for trusted clients

Revision ID: 3d4b7578d2e9
Revises: f0b1ec57c79
Create Date: 2016-02-18 18:36:22.508348

"""

# revision identifiers, used by Alembic.
revision = '3d4b7578d2e9'
down_revision = 'f0b1ec57c79'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column(
        'client',
        sa.Column('scope', sa.UnicodeText(), nullable=False, server_default=''),
    )
    op.alter_column('client', 'scope', server_default=None)


def downgrade():
    op.drop_column('client', 'scope')
