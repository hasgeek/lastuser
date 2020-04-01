# -*- coding: utf-8 -*-
"""Fix team_membership columns

Revision ID: 77893cc3830a
Revises: 666cdfe6da55
Create Date: 2020-04-01 21:42:00.040097

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '77893cc3830a'
down_revision = '666cdfe6da55'
branch_labels = None
depends_on = None


def upgrade():
    op.drop_column('team_membership', 'updated_at')

    op.execute(
        sa.DDL(
            'ALTER TABLE team_membership ALTER COLUMN created_at '
            'TYPE TIMESTAMP WITH TIME ZONE USING created_at AT TIME ZONE \'UTC\''
        )
    )


def downgrade():
    op.execute(
        sa.DDL(
            'ALTER TABLE team_membership ALTER COLUMN created_at '
            'TYPE TIMESTAMP WITHOUT TIME ZONE'
        )
    )

    op.add_column(
        'team_membership', sa.Column('updated_at', sa.DateTime(), nullable=True)
    )
    op.execute(sa.DDL('UPDATE team_membership SET updated_at = created_at'))
    op.alter_column('team_membership', 'updated_at', nullable=False)
