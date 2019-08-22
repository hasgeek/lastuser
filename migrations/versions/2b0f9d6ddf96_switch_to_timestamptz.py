# -*- coding: utf-8 -*-
"""Switch to timestamptz

Revision ID: 2b0f9d6ddf96
Revises: f324b0ecd05c
Create Date: 2019-05-10 01:22:55.904783

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '2b0f9d6ddf96'
down_revision = 'f324b0ecd05c'
branch_labels = None
depends_on = None

migrate_table_columns = [
    ('authcode', 'created_at'),
    ('authcode', 'updated_at'),
    ('authtoken', 'created_at'),
    ('authtoken', 'updated_at'),
    ('client', 'created_at'),
    ('client', 'updated_at'),
    ('client_credential', 'created_at'),
    ('client_credential', 'updated_at'),
    ('client_credential', 'accessed_at'),
    ('clientteamaccess', 'created_at'),
    ('clientteamaccess', 'updated_at'),
    ('name', 'created_at'),
    ('name', 'updated_at'),
    ('noticetype', 'created_at'),
    ('noticetype', 'updated_at'),
    ('organization', 'created_at'),
    ('organization', 'updated_at'),
    ('passwordresetrequest', 'created_at'),
    ('passwordresetrequest', 'updated_at'),
    ('permission', 'created_at'),
    ('permission', 'updated_at'),
    ('resource', 'created_at'),
    ('resource', 'updated_at'),
    ('resourceaction', 'created_at'),
    ('resourceaction', 'updated_at'),
    ('smsmessage', 'created_at'),
    ('smsmessage', 'updated_at'),
    ('smsmessage', 'status_at'),
    ('team', 'created_at'),
    ('team', 'updated_at'),
    ('teamclientpermissions', 'created_at'),
    ('teamclientpermissions', 'updated_at'),
    ('user', 'created_at'),
    ('user', 'updated_at'),
    ('user', 'pw_set_at'),
    ('user', 'pw_expires_at'),
    ('user_session', 'created_at'),
    ('user_session', 'updated_at'),
    ('user_session', 'accessed_at'),
    ('user_session', 'revoked_at'),
    ('user_session', 'sudo_enabled_at'),
    ('user_useremail_primary', 'created_at'),
    ('user_useremail_primary', 'updated_at'),
    ('user_userphone_primary', 'created_at'),
    ('user_userphone_primary', 'updated_at'),
    ('userclientpermissions', 'created_at'),
    ('userclientpermissions', 'updated_at'),
    ('useremail', 'created_at'),
    ('useremail', 'updated_at'),
    ('useremailclaim', 'created_at'),
    ('useremailclaim', 'updated_at'),
    ('userexternalid', 'created_at'),
    ('userexternalid', 'updated_at'),
    ('userexternalid', 'last_used_at'),
    ('userflashmessage', 'created_at'),
    ('userflashmessage', 'updated_at'),
    ('useroldid', 'created_at'),
    ('useroldid', 'updated_at'),
    ('userphone', 'created_at'),
    ('userphone', 'updated_at'),
    ('userphoneclaim', 'created_at'),
    ('userphoneclaim', 'updated_at'),
]


def upgrade():
    for table, column in migrate_table_columns:
        op.execute(
            sa.DDL(
                'ALTER TABLE "%(table)s" ALTER COLUMN "%(column)s" TYPE TIMESTAMP WITH TIME ZONE USING "%(column)s" AT TIME ZONE \'UTC\'',
                context={'table': table, 'column': column},
            )
        )


def downgrade():
    for table, column in reversed(migrate_table_columns):
        op.execute(
            sa.DDL(
                'ALTER TABLE "%(table)s" ALTER COLUMN "%(column)s" TYPE TIMESTAMP WITHOUT TIME ZONE',
                context={'table': table, 'column': column},
            )
        )
