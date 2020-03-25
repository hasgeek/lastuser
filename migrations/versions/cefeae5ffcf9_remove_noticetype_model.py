# -*- coding: utf-8 -*-
"""Remove NoticeType model

Revision ID: cefeae5ffcf9
Revises: bc9dda290638
Create Date: 2020-03-26 02:22:40.145304

"""
from alembic import op
from sqlalchemy.dialects import postgresql
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'cefeae5ffcf9'
down_revision = 'bc9dda290638'
branch_labels = None
depends_on = None


def upgrade():
    op.drop_table('noticetype')


def downgrade():
    op.create_table(
        'noticetype',
        sa.Column('user_id', sa.INTEGER(), autoincrement=False, nullable=False),
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
        sa.ForeignKeyConstraint(
            ['user_id'], ['user.id'], name='noticetype_user_id_fkey'
        ),
        sa.PrimaryKeyConstraint('id', name='noticetype_pkey'),
    )
