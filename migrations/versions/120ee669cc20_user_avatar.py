# -*- coding: utf-8 -*-
"""User avatar

Revision ID: 120ee669cc20
Revises: 4d19ada674c2
Create Date: 2014-12-30 18:18:54.583533

"""

# revision identifiers, used by Alembic.
revision = '120ee669cc20'
down_revision = '4d19ada674c2'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('user', sa.Column('avatar', sa.Unicode(length=250), nullable=True))


def downgrade():
    op.drop_column('user', 'avatar')
