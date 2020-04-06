# -*- coding: utf-8 -*-
"""Remove Permission model

Revision ID: bc9dda290638
Revises: 4279e1e5aec2
Create Date: 2020-03-26 00:09:50.999503

"""
from alembic import op
from sqlalchemy.dialects import postgresql
from sqlalchemy.sql import column
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'bc9dda290638'
down_revision = '4279e1e5aec2'
branch_labels = None
depends_on = None


def upgrade():
    op.drop_table('permission')


def downgrade():
    op.create_table(
        'permission',
        sa.Column('user_id', sa.INTEGER(), autoincrement=False, nullable=True),
        sa.Column('org_id', sa.INTEGER(), autoincrement=False, nullable=True),
        sa.Column('name', sa.VARCHAR(length=80), autoincrement=False, nullable=False),
        sa.Column('title', sa.VARCHAR(length=250), autoincrement=False, nullable=False),
        sa.Column('description', sa.TEXT(), autoincrement=False, nullable=False),
        sa.Column('allusers', sa.BOOLEAN(), autoincrement=False, nullable=False),
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
        sa.CheckConstraint(
            sa.case([(column('user_id').isnot(None), 1)], else_=0)
            + sa.case([(column('org_id').isnot(None), 1)], else_=0)
            == 1,
            name='permission_user_id_or_org_id',
        ),
        sa.ForeignKeyConstraint(
            ['org_id'], ['organization.id'], name='permission_org_id_fkey'
        ),
        sa.ForeignKeyConstraint(
            ['user_id'], ['user.id'], name='permission_user_id_fkey'
        ),
        sa.PrimaryKeyConstraint('id', name='permission_pkey'),
    )
