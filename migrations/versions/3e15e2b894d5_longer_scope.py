# -*- coding: utf-8 -*-
"""Longer scope

Revision ID: 3e15e2b894d5
Revises: 2dcc6f5ab4cf
Create Date: 2014-02-10 02:38:16.568657

"""

# revision identifiers, used by Alembic.
revision = '3e15e2b894d5'
down_revision = '2dcc6f5ab4cf'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.alter_column('authcode', 'scope', type_=sa.UnicodeText)
    op.alter_column('authtoken', 'scope', type_=sa.UnicodeText)


def downgrade():
    op.alter_column('authtoken', 'scope', type_=sa.Unicode(250))
    op.alter_column('authcode', 'scope', type_=sa.Unicode(250))
