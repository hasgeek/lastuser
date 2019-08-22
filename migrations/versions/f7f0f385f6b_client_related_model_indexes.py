# -*- coding: utf-8 -*-
"""Client related model indexes

Revision ID: f7f0f385f6b
Revises: 28eeea165ad
Create Date: 2015-01-23 19:07:39.480286

"""

# revision identifiers, used by Alembic.
revision = 'f7f0f385f6b'
down_revision = '28eeea165ad'

from alembic import op


def upgrade():
    op.drop_constraint(
        op.f('resourceaction_name_resource_id_key'), table_name='resourceaction'
    )
    op.create_index(
        op.f('resourceaction_resource_id_name_key'),
        'resourceaction',
        ['resource_id', 'name'],
        unique=True,
    )
    op.create_index(
        op.f('ix_authtoken_client_id'), 'authtoken', ['client_id'], unique=False
    )
    op.create_index(
        op.f('ix_teamclientpermissions_client_id'),
        'teamclientpermissions',
        ['client_id'],
        unique=False,
    )
    op.create_index(
        op.f('ix_userclientpermissions_client_id'),
        'userclientpermissions',
        ['client_id'],
        unique=False,
    )


def downgrade():
    op.drop_index(
        op.f('ix_userclientpermissions_client_id'), table_name='userclientpermissions'
    )
    op.drop_index(
        op.f('ix_teamclientpermissions_client_id'), table_name='teamclientpermissions'
    )
    op.drop_index(op.f('ix_authtoken_client_id'), table_name='authtoken')
    op.drop_constraint(
        op.f('resourceaction_resource_id_name_key'), table_name='resourceaction'
    )
    op.create_index(
        op.f('resourceaction_name_resource_id_key'),
        'resourceaction',
        ['resource_id', 'name'],
        unique=True,
    )
