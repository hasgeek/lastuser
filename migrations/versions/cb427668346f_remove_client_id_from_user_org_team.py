# -*- coding: utf-8 -*-
"""Remove client_id from user, org, team

Revision ID: cb427668346f
Revises: 1f10aa945af0
Create Date: 2020-03-20 03:59:15.592293

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'cb427668346f'
down_revision = '1f10aa945af0'
branch_labels = None
depends_on = None


def upgrade():
    op.drop_constraint(
        'organization_client_id_fkey', 'organization', type_='foreignkey'
    )
    op.drop_column('organization', 'client_id')
    op.drop_constraint('team_client_id_fkey', 'team', type_='foreignkey')
    op.drop_column('team', 'client_id')
    op.drop_constraint('user_client_id_fkey', 'user', type_='foreignkey')
    op.drop_constraint('user_referrer_id_fkey', 'user', type_='foreignkey')
    op.drop_column('user', 'client_id')
    op.drop_column('user', 'referrer_id')


def downgrade():
    op.add_column(
        'user',
        sa.Column('referrer_id', sa.INTEGER(), autoincrement=False, nullable=True),
    )
    op.add_column(
        'user', sa.Column('client_id', sa.INTEGER(), autoincrement=False, nullable=True)
    )
    op.create_foreign_key(
        'user_referrer_id_fkey', 'user', 'user', ['referrer_id'], ['id']
    )
    op.create_foreign_key(
        'user_client_id_fkey', 'user', 'client', ['client_id'], ['id']
    )
    op.add_column(
        'team', sa.Column('client_id', sa.INTEGER(), autoincrement=False, nullable=True)
    )
    op.create_foreign_key(
        'team_client_id_fkey', 'team', 'client', ['client_id'], ['id']
    )
    op.add_column(
        'organization',
        sa.Column('client_id', sa.INTEGER(), autoincrement=False, nullable=True),
    )
    op.create_foreign_key(
        'organization_client_id_fkey', 'organization', 'client', ['client_id'], ['id']
    )
