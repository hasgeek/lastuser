# -*- coding: utf-8 -*-
"""Email domain

Revision ID: 50c29617571d
Revises: 51eadbed921b
Create Date: 2015-01-23 00:45:59.172781

"""

# revision identifiers, used by Alembic.
revision = '50c29617571d'
down_revision = '51eadbed921b'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column(
        'useremail', sa.Column('domain', sa.Unicode(length=253), nullable=True)
    )
    op.execute(
        sa.text(
            "UPDATE \"useremail\" SET domain=substring(substring(email from '@.*$') from 2)"
        )
    )
    op.alter_column('useremail', 'domain', nullable=False)
    op.create_index(op.f('ix_useremail_domain'), 'useremail', ['domain'], unique=False)
    op.add_column(
        'useremailclaim', sa.Column('domain', sa.Unicode(length=253), nullable=True)
    )
    op.execute(
        sa.text(
            "UPDATE \"useremailclaim\" SET domain=substring(substring(email from '@.*$') from 2)"
        )
    )
    op.alter_column('useremailclaim', 'domain', nullable=False)
    op.create_index(
        op.f('ix_useremailclaim_domain'), 'useremailclaim', ['domain'], unique=False
    )


def downgrade():
    op.drop_index(op.f('ix_useremailclaim_domain'), table_name='useremailclaim')
    op.drop_column('useremailclaim', 'domain')
    op.drop_index(op.f('ix_useremail_domain'), table_name='useremail')
    op.drop_column('useremail', 'domain')
