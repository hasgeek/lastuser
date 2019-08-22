# -*- coding: utf-8 -*-
"""Timestamp team membership

Revision ID: 165f20377abe
Revises: 35a6ffd7a079
Create Date: 2014-03-25 18:17:30.010140

"""

# revision identifiers, used by Alembic.
revision = '165f20377abe'
down_revision = '35a6ffd7a079'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column(
        'team_membership',
        sa.Column(
            'created_at', sa.DateTime(), server_default=sa.func.now(), nullable=False
        ),
    )
    op.add_column(
        'team_membership',
        sa.Column(
            'updated_at', sa.DateTime(), server_default=sa.func.now(), nullable=False
        ),
    )
    op.alter_column('team_membership', 'created_at', server_default=None)
    op.alter_column('team_membership', 'updated_at', server_default=None)
    op.create_primary_key(
        'team_membership_pkey', 'team_membership', ['user_id', 'team_id']
    )


def downgrade():
    op.drop_column('team_membership', 'updated_at')
    op.drop_column('team_membership', 'created_at')
