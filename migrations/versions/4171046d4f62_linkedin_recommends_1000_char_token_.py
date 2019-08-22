# -*- coding: utf-8 -*-
"""LinkedIn recommends 1000 char token fields

Revision ID: 4171046d4f62
Revises: 3506dcc19f7a
Create Date: 2017-10-17 14:45:45.692758

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '4171046d4f62'
down_revision = '3506dcc19f7a'
branch_labels = None
depends_on = None


def upgrade():
    op.alter_column(
        'userexternalid',
        'oauth_token',
        type_=sa.String(1000),
        existing_type=sa.String(250),
    )
    op.alter_column(
        'userexternalid',
        'oauth_token_secret',
        type_=sa.String(1000),
        existing_type=sa.String(250),
    )


def downgrade():
    op.alter_column(
        'userexternalid',
        'oauth_token_secret',
        type_=sa.String(250),
        existing_type=sa.String(1000),
    )
    op.alter_column(
        'userexternalid',
        'oauth_token',
        type_=sa.String(250),
        existing_type=sa.String(1000),
    )
