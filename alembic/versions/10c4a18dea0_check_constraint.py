"""Check constraint

Revision ID: 10c4a18dea0
Revises: 11a71745a9a8
Create Date: 2014-10-19 00:55:15.508120

"""

# revision identifiers, used by Alembic.
revision = '10c4a18dea0'
down_revision = '11a71745a9a8'

from alembic import op
import sqlalchemy as sa
from sqlalchemy.sql import column


def upgrade():
    op.create_check_constraint('client_user_id_or_org_id', 'client',
        sa.case([(column('user_id') != None, 1)], else_=0) + sa.case([(column('org_id') != None, 1)], else_=0) == 1  # NOQA
        )

    op.create_check_constraint('permission_user_id_or_org_id', 'permission',
        sa.case([(column('user_id') != None, 1)], else_=0) + sa.case([(column('org_id') != None, 1)], else_=0) == 1  # NOQA
        )


def downgrade():
    op.drop_constraint('permission_user_id_or_org_id', 'permission')
    op.drop_constraint('client_user_id_or_org_id', 'client')
