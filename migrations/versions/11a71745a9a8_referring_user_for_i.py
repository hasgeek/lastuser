# -*- coding: utf-8 -*-
"""Referring user for invitees

Revision ID: 11a71745a9a8
Revises: 16f88a0a1ad3
Create Date: 2014-04-15 23:42:38.808138

"""

# revision identifiers, used by Alembic.
revision = '11a71745a9a8'
down_revision = '16f88a0a1ad3'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column(
        'user',
        sa.Column(
            'referrer_id',
            sa.Integer(),
            sa.ForeignKey('user.id', name='user_referrer_id_fkey'),
            nullable=True,
        ),
    )


def downgrade():
    op.drop_column('user', 'referrer_id')
