# -*- coding: utf-8 -*-
"""Public client auth token

Revision ID: f0b1ec57c79
Revises: 1bfb508c7ceb
Create Date: 2015-04-09 03:41:19.376536

"""

# revision identifiers, used by Alembic.
revision = 'f0b1ec57c79'
down_revision = '1bfb508c7ceb'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column(
        'authtoken', sa.Column('user_session_id', sa.Integer(), nullable=True)
    )
    op.create_unique_constraint(
        'authtoken_user_session_id_client_id_key',
        'authtoken',
        ['user_session_id', 'client_id'],
    )
    op.create_foreign_key(
        'authtoken_user_session_id_fkey',
        'authtoken',
        'user_session',
        ['user_session_id'],
        ['id'],
    )


def downgrade():
    op.drop_constraint(
        'authtoken_user_session_id_fkey', 'authtoken', type_='foreignkey'
    )
    op.drop_constraint(
        'authtoken_user_session_id_client_id_key', 'authtoken', type_='unique'
    )
    op.drop_column('authtoken', 'user_session_id')
