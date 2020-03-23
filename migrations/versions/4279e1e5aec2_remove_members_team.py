# -*- coding: utf-8 -*-
"""Remove Members team

Revision ID: 4279e1e5aec2
Revises: 8a9bf9d385c2
Create Date: 2020-03-24 00:24:36.249668

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '4279e1e5aec2'
down_revision = '8a9bf9d385c2'
branch_labels = None
depends_on = None


def upgrade():
    op.drop_constraint(
        'organization_members_id_fkey', 'organization', type_='foreignkey'
    )
    op.drop_column('organization', 'members_id')


def downgrade():
    op.add_column(
        'organization',
        sa.Column('members_id', sa.INTEGER(), autoincrement=False, nullable=True),
    )
    op.create_foreign_key(
        'organization_members_id_fkey', 'organization', 'team', ['members_id'], ['id']
    )
