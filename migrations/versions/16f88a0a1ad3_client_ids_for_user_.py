# -*- coding: utf-8 -*-
"""Client ids for user/org/team

Revision ID: 16f88a0a1ad3
Revises: 3a4e0ea70ef
Create Date: 2014-04-13 15:12:17.408052

"""

# revision identifiers, used by Alembic.
revision = '16f88a0a1ad3'
down_revision = '3a4e0ea70ef'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column(
        'organization',
        sa.Column(
            'client_id',
            sa.Integer(),
            sa.ForeignKey('client.id', name='organization_client_id_fkey'),
            nullable=True,
        ),
    )
    op.add_column(
        'team',
        sa.Column(
            'client_id',
            sa.Integer(),
            sa.ForeignKey('client.id', name='team_client_id_fkey'),
            nullable=True,
        ),
    )
    op.add_column(
        'user',
        sa.Column(
            'client_id',
            sa.Integer(),
            sa.ForeignKey('client.id', name='user_client_id_fkey'),
            nullable=True,
        ),
    )


def downgrade():
    op.drop_column('user', 'client_id')
    op.drop_column('team', 'client_id')
    op.drop_column('organization', 'client_id')
