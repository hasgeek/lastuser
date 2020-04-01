# -*- coding: utf-8 -*-
"""Remove user_flash_message

Revision ID: 039d2745e628
Revises: 77893cc3830a
Create Date: 2020-04-01 21:54:15.903756

"""
from alembic import op
from sqlalchemy.dialects import postgresql
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '039d2745e628'
down_revision = '77893cc3830a'
branch_labels = None
depends_on = None


def upgrade():
    op.drop_table('user_flash_message')


def downgrade():
    op.create_table(
        'user_flash_message',
        sa.Column('user_id', sa.INTEGER(), autoincrement=False, nullable=False),
        sa.Column('seq', sa.INTEGER(), autoincrement=False, nullable=False),
        sa.Column('category', sa.TEXT(), autoincrement=False, nullable=False),
        sa.Column('message', sa.TEXT(), autoincrement=False, nullable=False),
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
            ['user_id'], ['user.id'], name='user_flash_message_user_id_fkey'
        ),
        sa.PrimaryKeyConstraint('id', name='user_flash_message_pkey'),
    )
