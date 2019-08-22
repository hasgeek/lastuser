# -*- coding: utf-8 -*-
"""Count phone verification attempts

Revision ID: f1185c3c4505
Revises: 4171046d4f62
Create Date: 2018-09-20 21:45:28.425642

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'f1185c3c4505'
down_revision = '4171046d4f62'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        'userphoneclaim',
        sa.Column(
            'verification_attempts', sa.Integer(), nullable=False, server_default='0'
        ),
    )
    op.alter_column('userphoneclaim', 'verification_attempts', server_default=None)


def downgrade():
    op.drop_column('userphoneclaim', 'verification_attempts')
