# -*- coding: utf-8 -*-
"""External id last used at

Revision ID: f324b0ecd05c
Revises: 7adaca745f63
Create Date: 2018-10-02 00:22:30.365169

"""
from alembic import op
from sqlalchemy.sql import column, table
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'f324b0ecd05c'
down_revision = '7adaca745f63'
branch_labels = None
depends_on = None


def upgrade():
    userexternalid = table(
        'userexternalid',
        column('updated_at', sa.DateTime),
        column('last_used_at', sa.DateTime),
    )
    op.add_column(
        'userexternalid', sa.Column('last_used_at', sa.DateTime(), nullable=True)
    )
    op.execute(userexternalid.update().values(last_used_at=userexternalid.c.updated_at))
    op.alter_column('userexternalid', 'last_used_at', nullable=False)


def downgrade():
    op.drop_column('userexternalid', 'last_used_at')
