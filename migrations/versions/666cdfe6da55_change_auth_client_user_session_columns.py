# -*- coding: utf-8 -*-
"""Change auth_client_user_session columns

Revision ID: 666cdfe6da55
Revises: 9d8dd321cea7
Create Date: 2020-04-01 21:08:44.780258

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '666cdfe6da55'
down_revision = '9d8dd321cea7'
branch_labels = None
depends_on = None


def upgrade():
    op.alter_column(
        'auth_client_user_session', 'updated_at', new_column_name='accessed_at'
    )

    for column in ('created_at', 'accessed_at'):
        op.execute(
            sa.DDL(
                'ALTER TABLE auth_client_user_session ALTER COLUMN "%(column)s" '
                'TYPE TIMESTAMP WITH TIME ZONE USING "%(column)s" AT TIME ZONE \'UTC\'',
                context={'column': column},
            )
        )

    op.drop_constraint(
        'auth_client_user_session_pkey', 'auth_client_user_session', type_='primary'
    )
    op.create_primary_key(
        'auth_client_user_session_pkey',
        'auth_client_user_session',
        ['auth_client_id', 'user_session_id'],
    )


def downgrade():
    op.drop_constraint(
        'auth_client_user_session_pkey', 'auth_client_user_session', type_='primary'
    )
    op.create_primary_key(
        'auth_client_user_session_pkey',
        'auth_client_user_session',
        ['user_session_id', 'auth_client_id'],
    )

    for column in ('created_at', 'accessed_at'):
        op.execute(
            sa.DDL(
                'ALTER TABLE auth_client_user_session ALTER COLUMN "%(column)s" '
                'TYPE TIMESTAMP WITHOUT TIME ZONE',
                context={'column': column},
            )
        )

    op.alter_column(
        'auth_client_user_session', 'accessed_at', new_column_name='updated_at'
    )
