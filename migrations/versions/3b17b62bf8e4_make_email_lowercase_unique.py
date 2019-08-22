# -*- coding: utf-8 -*-
"""Make email lowercase-unique

Revision ID: 3b17b62bf8e4
Revises: 07f975f81f03
Create Date: 2017-08-07 17:33:34.077452

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '3b17b62bf8e4'
down_revision = '07f975f81f03'
branch_labels = None
depends_on = None


def upgrade():
    op.drop_index('ix_useremail_email_lower')
    op.execute(
        sa.DDL(
            'CREATE UNIQUE INDEX ix_useremail_email_lower ON useremail (lower(email) text_pattern_ops);'
        )
    )


def downgrade():
    op.drop_index('ix_useremail_email_lower')
    op.execute(
        sa.DDL(
            'CREATE INDEX ix_useremail_email_lower ON useremail (lower(email) text_pattern_ops);'
        )
    )
