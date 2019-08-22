# -*- coding: utf-8 -*-
"""Restricted resources

Revision ID: 35a6ffd7a079
Revises: 3b3583fcbaea
Create Date: 2014-03-19 04:55:01.382718

"""

# revision identifiers, used by Alembic.
revision = '35a6ffd7a079'
down_revision = '3b3583fcbaea'

from alembic import op


def upgrade():
    op.alter_column('resource', 'trusted', new_column_name='restricted')


def downgrade():
    op.alter_column('resource', 'restricted', new_column_name='trusted')
