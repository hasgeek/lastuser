# -*- coding: utf-8 -*-
"""User name index

Revision ID: 4d19ada674c2
Revises: 351ec61f8b07
Create Date: 2014-11-08 23:50:18.355509

"""

# revision identifiers, used by Alembic.
revision = '4d19ada674c2'
down_revision = '351ec61f8b07'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.execute(
        sa.DDL(
            "CREATE INDEX ix_user_username_lower ON \"user\" (lower(username) varchar_pattern_ops);"
        )
    )
    op.execute(
        sa.DDL(
            "CREATE INDEX ix_user_fullname_lower ON \"user\" (lower(fullname) varchar_pattern_ops);"
        )
    )
    op.execute(
        sa.DDL(
            "CREATE INDEX ix_useremail_email_lower ON useremail (lower(email) varchar_pattern_ops);"
        )
    )
    op.execute(
        sa.DDL(
            "CREATE INDEX ix_userexternalid_username_lower ON userexternalid (lower(username) varchar_pattern_ops);"
        )
    )


def downgrade():
    op.drop_index('ix_userexternalid_username_lower')
    op.drop_index('ix_useremail_email_lower')
    op.drop_index('ix_user_fullname_lower')
    op.drop_index('ix_user_username_lower')
