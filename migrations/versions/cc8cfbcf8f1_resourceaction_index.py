# -*- coding: utf-8 -*-
"""ResourceAction index

Revision ID: cc8cfbcf8f1
Revises: f7f0f385f6b
Create Date: 2015-02-24 21:02:32.123830

"""

# revision identifiers, used by Alembic.
revision = 'cc8cfbcf8f1'
down_revision = 'f7f0f385f6b'

from alembic import op


def upgrade():
    op.drop_index('resourceaction_resource_id_name_key', table_name='resourceaction')
    op.create_unique_constraint(
        'resourceaction_resource_id_name_key', 'resourceaction', ['resource_id', 'name']
    )


def downgrade():
    op.drop_constraint(
        'resourceaction_resource_id_name_key', 'resourceaction', type_='unique'
    )
    op.create_index(
        'resourceaction_resource_id_name_key',
        'resourceaction',
        ['resource_id', 'name'],
        unique=True,
    )
