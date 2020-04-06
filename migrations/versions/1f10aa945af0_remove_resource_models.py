# -*- coding: utf-8 -*-
"""Remove resource models

Revision ID: 1f10aa945af0
Revises: a4bea3d02a3d
Create Date: 2020-03-20 01:33:39.201555

"""
from alembic import op
from sqlalchemy.dialects import postgresql
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '1f10aa945af0'
down_revision = 'a4bea3d02a3d'
branch_labels = None
depends_on = None


def upgrade():
    op.drop_table('resourceaction')
    op.drop_table('resource')


def downgrade():
    op.create_table(
        'resource',
        sa.Column('id', sa.INTEGER(), autoincrement=True, nullable=False),
        sa.Column(
            'created_at',
            postgresql.TIMESTAMP(timezone=True),
            autoincrement=False,
            nullable=False,
        ),
        sa.Column(
            'updated_at',
            postgresql.TIMESTAMP(timezone=True),
            autoincrement=False,
            nullable=False,
        ),
        sa.Column('name', sa.VARCHAR(length=20), autoincrement=False, nullable=False),
        sa.Column('client_id', sa.INTEGER(), autoincrement=False, nullable=False),
        sa.Column('title', sa.VARCHAR(length=250), autoincrement=False, nullable=False),
        sa.Column('description', sa.TEXT(), autoincrement=False, nullable=False),
        sa.Column('siteresource', sa.BOOLEAN(), autoincrement=False, nullable=False),
        sa.Column('restricted', sa.BOOLEAN(), autoincrement=False, nullable=False),
        sa.ForeignKeyConstraint(
            ['client_id'], ['client.id'], name='resource_client_id_fkey'
        ),
        sa.PrimaryKeyConstraint('id', name='resource_pkey'),
        sa.UniqueConstraint('client_id', 'name', name='resource_client_id_name_key'),
        postgresql_ignore_search_path=False,
    )
    op.create_table(
        'resourceaction',
        sa.Column('id', sa.INTEGER(), autoincrement=True, nullable=False),
        sa.Column(
            'created_at',
            postgresql.TIMESTAMP(timezone=True),
            autoincrement=False,
            nullable=False,
        ),
        sa.Column(
            'updated_at',
            postgresql.TIMESTAMP(timezone=True),
            autoincrement=False,
            nullable=False,
        ),
        sa.Column('name', sa.VARCHAR(length=20), autoincrement=False, nullable=False),
        sa.Column('resource_id', sa.INTEGER(), autoincrement=False, nullable=False),
        sa.Column('title', sa.VARCHAR(length=250), autoincrement=False, nullable=False),
        sa.Column('description', sa.TEXT(), autoincrement=False, nullable=False),
        sa.ForeignKeyConstraint(
            ['resource_id'], ['resource.id'], name='resourceaction_resource_id_fkey'
        ),
        sa.PrimaryKeyConstraint('id', name='resourceaction_pkey'),
        sa.UniqueConstraint(
            'resource_id', 'name', name='resourceaction_resource_id_name_key'
        ),
    )
