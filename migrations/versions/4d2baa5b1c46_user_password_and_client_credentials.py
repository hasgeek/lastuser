# -*- coding: utf-8 -*-
"""User password and client credentials

Revision ID: 4d2baa5b1c46
Revises: d94bd59a2f0
Create Date: 2015-01-06 23:56:49.682531

"""

# revision identifiers, used by Alembic.
revision = '4d2baa5b1c46'
down_revision = 'd94bd59a2f0'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.create_table(
        'client_credential',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.Column('client_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=22), nullable=False),
        sa.Column('title', sa.Unicode(length=250), nullable=False),
        sa.Column('secret_hash', sa.String(length=71), nullable=False),
        sa.Column('accessed_at', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['client_id'], ['client.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name'),
    )
    op.add_column(u'user', sa.Column('pw_expires_at', sa.DateTime(), nullable=True))
    op.add_column(u'user', sa.Column('pw_set_at', sa.DateTime(), nullable=True))


def downgrade():
    op.drop_column(u'user', 'pw_set_at')
    op.drop_column(u'user', 'pw_expires_at')
    op.drop_table('client_credential')
