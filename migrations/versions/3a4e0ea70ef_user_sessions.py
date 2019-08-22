# -*- coding: utf-8 -*-
"""User sessions

Revision ID: 3a4e0ea70ef
Revises: 165f20377abe
Create Date: 2014-04-10 01:39:00.122310

"""

# revision identifiers, used by Alembic.
revision = '3a4e0ea70ef'
down_revision = '165f20377abe'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'user_session',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.Column('buid', sa.Unicode(length=22), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('ipaddr', sa.String(length=45), nullable=False),
        sa.Column('user_agent', sa.Unicode(length=250), nullable=False),
        sa.Column('accessed_at', sa.DateTime(), nullable=False),
        sa.Column('revoked_at', sa.DateTime(), nullable=True),
        sa.Column('sudo_enabled_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['user.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('buid'),
    )
    op.add_column(
        'authcode',
        sa.Column(
            'session_id', sa.Integer(), sa.ForeignKey('user_session.id'), nullable=True
        ),
    )


def downgrade():
    op.drop_column('authcode', 'session_id')
    op.drop_table('user_session')
