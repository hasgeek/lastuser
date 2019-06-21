"""User status flag

Revision ID: 25e7a9839cd4
Revises: 184ed1055383
Create Date: 2013-04-20 11:38:45.227518

"""

# revision identifiers, used by Alembic.
revision = '25e7a9839cd4'
down_revision = '184ed1055383'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.add_column('user', sa.Column('status', sa.SmallInteger(), nullable=False,
        server_default=sa.text('0')))
    op.alter_column('user', 'status', server_default=None)


def downgrade():
    op.drop_column('user', 'status')
