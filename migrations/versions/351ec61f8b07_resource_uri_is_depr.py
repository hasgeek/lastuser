# -*- coding: utf-8 -*-
"""Resource URI is deprecated

Revision ID: 351ec61f8b07
Revises: 10c4a18dea0
Create Date: 2014-11-05 15:39:29.462833

"""

# revision identifiers, used by Alembic.
revision = '351ec61f8b07'
down_revision = '10c4a18dea0'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.drop_column('client', 'resource_uri')


def downgrade():
    op.add_column(
        'client', sa.Column('resource_uri', sa.VARCHAR(length=250), nullable=True)
    )
