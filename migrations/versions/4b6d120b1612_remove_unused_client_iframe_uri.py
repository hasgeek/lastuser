# -*- coding: utf-8 -*-
"""Remove unused client.iframe_uri

Revision ID: 4b6d120b1612
Revises: cb427668346f
Create Date: 2020-03-20 04:09:23.758500

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '4b6d120b1612'
down_revision = 'cb427668346f'
branch_labels = None
depends_on = None


def upgrade():
    op.drop_column('client', 'iframe_uri')


def downgrade():
    op.add_column(
        'client', sa.Column('iframe_uri', sa.TEXT(), autoincrement=False, nullable=True)
    )
