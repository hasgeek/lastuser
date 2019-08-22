# -*- coding: utf-8 -*-
"""Longer external usernames

Revision ID: 25c7f8680a52
Revises: cc8cfbcf8f1
Create Date: 2015-02-24 21:10:53.865326

"""

# revision identifiers, used by Alembic.
revision = '25c7f8680a52'
down_revision = 'cc8cfbcf8f1'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.alter_column(
        'userexternalid',
        'username',
        type_=sa.Unicode(250),
        existing_type=sa.Unicode(80),
    )


def downgrade():
    op.alter_column(
        'userexternalid',
        'username',
        type_=sa.Unicode(80),
        existing_type=sa.Unicode(250),
    )
