# -*- coding: utf-8 -*-
"""Remove team domain

Revision ID: 07f975f81f03
Revises: 4e206c5ddabd
Create Date: 2017-08-04 15:12:11.992856

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '07f975f81f03'
down_revision = '4e206c5ddabd'
branch_labels = None
depends_on = None


def upgrade():
    op.drop_index('ix_team_domain', table_name='team')
    op.drop_column('team', 'domain')


def downgrade():
    op.add_column(
        'team',
        sa.Column('domain', sa.VARCHAR(length=253), autoincrement=False, nullable=True),
    )
    op.create_index('ix_team_domain', 'team', ['domain'], unique=False)
