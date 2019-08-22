# -*- coding: utf-8 -*-
"""Email/phone type and private columns

Revision ID: 28eeea165ad
Revises: d055b3e2c89
Create Date: 2015-01-23 04:21:50.851050

"""

# revision identifiers, used by Alembic.
revision = '28eeea165ad'
down_revision = 'd055b3e2c89'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column(
        'useremail',
        sa.Column('private', sa.Boolean(), nullable=False, server_default='0'),
    )
    op.alter_column('useremail', 'private', server_default=None)
    op.add_column('useremail', sa.Column('type', sa.Unicode(length=30), nullable=True))

    op.add_column(
        'useremailclaim',
        sa.Column('private', sa.Boolean(), nullable=False, server_default='0'),
    )
    op.alter_column('useremailclaim', 'private', server_default=None)
    op.add_column(
        'useremailclaim', sa.Column('type', sa.Unicode(length=30), nullable=True)
    )

    op.add_column(
        'userphone',
        sa.Column('private', sa.Boolean(), nullable=False, server_default='0'),
    )
    op.alter_column('userphone', 'private', server_default=None)
    op.add_column('userphone', sa.Column('type', sa.Unicode(length=30), nullable=True))

    op.add_column(
        'userphoneclaim',
        sa.Column('private', sa.Boolean(), nullable=False, server_default='0'),
    )
    op.alter_column('userphoneclaim', 'private', server_default=None)
    op.add_column(
        'userphoneclaim', sa.Column('type', sa.Unicode(length=30), nullable=True)
    )


def downgrade():
    op.drop_column('userphoneclaim', 'type')
    op.drop_column('userphoneclaim', 'private')
    op.drop_column('userphone', 'type')
    op.drop_column('userphone', 'private')
    op.drop_column('useremailclaim', 'type')
    op.drop_column('useremailclaim', 'private')
    op.drop_column('useremail', 'type')
    op.drop_column('useremail', 'private')
