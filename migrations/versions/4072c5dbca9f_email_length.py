"""Email length

Revision ID: 4072c5dbca9f
Revises: 25e7a9839cd4
Create Date: 2014-02-07 13:12:41.886046

"""

# revision identifiers, used by Alembic.
revision = '4072c5dbca9f'
down_revision = '25e7a9839cd4'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.alter_column('useremail', 'email', type_=sa.Unicode(254))
    op.alter_column('useremailclaim', 'email', type_=sa.Unicode(254))


def downgrade():
    op.alter_column('useremailclaim', 'email', type_=sa.Unicode(80))
    op.alter_column('useremail', 'email', type_=sa.Unicode(80))
