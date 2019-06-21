"""One claim per email and phone

Revision ID: 2dcc6f5ab4cf
Revises: 4072c5dbca9f
Create Date: 2014-02-09 03:47:17.404097

"""

# revision identifiers, used by Alembic.
revision = '2dcc6f5ab4cf'
down_revision = '4072c5dbca9f'

from alembic import op
import sqlalchemy as sa  # NOQA


def upgrade():
    op.create_unique_constraint('useremailclaim_user_id_email_key', 'useremailclaim', ['user_id', 'email'])
    op.create_unique_constraint('userphoneclaim_user_id_phone_key', 'userphoneclaim', ['user_id', 'phone'])


def downgrade():
    op.drop_constraint('userphoneclaim_user_id_phone_key', 'userphoneclaim', type_='unique')
    op.drop_constraint('useremailclaim_user_id_email_key', 'useremailclaim', type_='unique')
