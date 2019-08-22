# -*- coding: utf-8 -*-
"""Track clients that verify sessions

Revision ID: 51eadbed921b
Revises: 20ce0d0f1ee9
Create Date: 2015-01-15 01:56:04.308088

"""

# revision identifiers, used by Alembic.
revision = '51eadbed921b'
down_revision = '20ce0d0f1ee9'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'session_client',
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.Column('user_session_id', sa.Integer(), nullable=False),
        sa.Column('client_id', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['client_id'], ['client.id']),
        sa.ForeignKeyConstraint(['user_session_id'], ['user_session.id']),
        sa.PrimaryKeyConstraint('user_session_id', 'client_id'),
    )


def downgrade():
    op.drop_table('session_client')
