"""Remove user bio field

Revision ID: 7adaca745f63
Revises: 065146599a21
Create Date: 2018-10-01 23:27:22.883087

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '7adaca745f63'
down_revision = '065146599a21'
branch_labels = None
depends_on = None


def upgrade():
    op.drop_column('user', 'description')


def downgrade():
    op.add_column('user', sa.Column('description', sa.TEXT(), autoincrement=False, nullable=True, server_default=''))
    op.alter_column('user', 'description', server_default=None, nullable=False)
