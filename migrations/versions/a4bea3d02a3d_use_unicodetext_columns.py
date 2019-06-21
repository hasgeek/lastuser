"""Use UnicodeText columns

Revision ID: a4bea3d02a3d
Revises: 2b0f9d6ddf96
Create Date: 2019-06-21 09:59:01.059481

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a4bea3d02a3d'
down_revision = '2b0f9d6ddf96'
branch_labels = None
depends_on = None


table_column_type = [
    ('client', 'website', sa.Unicode(250)),
    ('client', 'namespace', sa.Unicode(250)),
    ('client', 'redirect_uri', sa.Unicode(250)),
    ('client', 'notification_uri', sa.Unicode(250)),
    ('client', 'iframe_uri', sa.Unicode(250)),
    ('userflashmessage', 'category', sa.Unicode(20)),
    ('userflashmessage', 'message', sa.Unicode(250)),
    ('authcode', 'redirect_uri', sa.Unicode(1024)),
    ('userclientpermissions', 'permissions', sa.Unicode(250)),
    ('teamclientpermissions', 'permissions', sa.Unicode(250)),
    ('smsmessage', 'transaction_id', sa.Unicode(40)),
    ('smsmessage', 'fail_reason', sa.Unicode(25)),
    ('user_session', 'user_agent', sa.Unicode(250)),
    ('user', 'avatar', sa.Unicode(250)),
    ('userphone', 'phone', sa.Unicode(16)),
    ('userphoneclaim', 'phone', sa.Unicode(16)),
    ('userexternalid', 'service', sa.String(20)),
    ('userexternalid', 'userid', sa.String(250)),
    ('userexternalid', 'username', sa.Unicode(250)),
    ('userexternalid', 'oauth_token', sa.String(1000)),
    ('userexternalid', 'oauth_token_secret', sa.String(1000)),
    ('userexternalid', 'oauth_token_type', sa.String(250)),
    ]


def upgrade():
    for table, column, col_type in table_column_type:
        op.alter_column(table, column, type_=sa.UnicodeText(), existing_type=col_type)


def downgrade():
    for table, column, col_type in reversed(table_column_type):
        op.alter_column(table, column, type_=col_type, existing_type=sa.UnicodeText())
