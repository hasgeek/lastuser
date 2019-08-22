# -*- coding: utf-8 -*-
"""Client confidential flag

Revision ID: 1bfb508c7ceb
Revises: 25c7f8680a52
Create Date: 2015-04-05 16:41:54.101398

"""

# revision identifiers, used by Alembic.
revision = '1bfb508c7ceb'
down_revision = '25c7f8680a52'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column(
        'client',
        sa.Column('confidential', sa.Boolean(), nullable=False, server_default='1'),
    )
    op.alter_column('client', 'confidential', server_default=None)


def downgrade():
    op.drop_column('client', 'confidential')
