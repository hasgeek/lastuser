# -*- coding: utf-8 -*-
"""Remove obsolete ClientTeamAccess

Revision ID: f65c00c0cfc3
Revises: 4b6d120b1612
Create Date: 2020-03-20 04:42:28.526187

"""
from alembic import op
from sqlalchemy.dialects import postgresql
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'f65c00c0cfc3'
down_revision = '4b6d120b1612'
branch_labels = None
depends_on = None


def upgrade():
    op.drop_table('clientteamaccess')
    op.drop_column('client', 'team_access')


def downgrade():
    op.add_column(
        'client',
        sa.Column('team_access', sa.BOOLEAN(), autoincrement=False, nullable=False),
    )
    op.create_table(
        'clientteamaccess',
        sa.Column('org_id', sa.INTEGER(), autoincrement=False, nullable=True),
        sa.Column('client_id', sa.INTEGER(), autoincrement=False, nullable=False),
        sa.Column('access_level', sa.INTEGER(), autoincrement=False, nullable=False),
        sa.Column('id', sa.INTEGER(), autoincrement=True, nullable=False),
        sa.Column(
            'created_at',
            postgresql.TIMESTAMP(timezone=True),
            autoincrement=False,
            nullable=False,
        ),
        sa.Column(
            'updated_at',
            postgresql.TIMESTAMP(timezone=True),
            autoincrement=False,
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ['client_id'], ['client.id'], name='clientteamaccess_client_id_fkey'
        ),
        sa.ForeignKeyConstraint(
            ['org_id'], ['organization.id'], name='clientteamaccess_org_id_fkey'
        ),
        sa.PrimaryKeyConstraint('id', name='clientteamaccess_pkey'),
    )
