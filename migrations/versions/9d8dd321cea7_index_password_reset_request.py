# -*- coding: utf-8 -*-
"""Index password reset request

Revision ID: 9d8dd321cea7
Revises: ee6107769222
Create Date: 2020-04-01 11:40:35.049318

"""
from alembic import op

# revision identifiers, used by Alembic.
revision = '9d8dd321cea7'
down_revision = 'ee6107769222'
branch_labels = None
depends_on = None


def upgrade():
    op.create_index(
        op.f('ix_auth_password_reset_request_user_id'),
        'auth_password_reset_request',
        ['user_id'],
        unique=False,
    )


def downgrade():
    op.drop_index(
        op.f('ix_auth_password_reset_request_user_id'),
        table_name='auth_password_reset_request',
    )
