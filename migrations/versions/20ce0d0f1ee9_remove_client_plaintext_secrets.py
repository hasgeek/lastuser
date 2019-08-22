# -*- coding: utf-8 -*-
"""Remove client plaintext secrets

Revision ID: 20ce0d0f1ee9
Revises: 4d2baa5b1c46
Create Date: 2015-01-15 00:06:59.450000

"""

# revision identifiers, used by Alembic.
revision = '20ce0d0f1ee9'
down_revision = '4d2baa5b1c46'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.drop_column('client', 'secret')


def downgrade():
    op.add_column(
        'client',
        sa.Column(
            'secret',
            sa.VARCHAR(length=44),
            autoincrement=False,
            nullable=False,
            server_default='',
        ),
    )
    op.alter_column('client', 'secret', server_default=None)
