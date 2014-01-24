"""resource namespace

Revision ID: 7b0ba76b89e
Revises: 25e7a9839cd4
Create Date: 2013-11-08 18:09:33.077996

"""

# revision identifiers, used by Alembic.
revision = '7b0ba76b89e'
down_revision = '25e7a9839cd4'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.drop_constraint('resource_name_key','resource')
    op.create_unique_constraint('resource_client_id_name_key', 'resource', ['client_id', 'name'])


def downgrade():
    op.drop_constraint('resource_client_id_name_key','resource')
    op.create_unique_constraint('resource_name_key', 'resource', ['name'])
