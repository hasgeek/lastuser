"""Remove org and team ownership of email and phone

Revision ID: c446b9bc0691
Revises: f1185c3c4505
Create Date: 2018-09-27 15:58:24.149115

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.sql import column


# revision identifiers, used by Alembic.
revision = 'c446b9bc0691'
down_revision = 'f1185c3c4505'
branch_labels = None
depends_on = None


def upgrade():
    op.alter_column('useremail', 'user_id', existing_type=sa.INTEGER(), nullable=False)
    op.drop_constraint(u'useremail_team_id_fkey', 'useremail', type_='foreignkey')
    op.drop_constraint(u'useremail_org_id_fkey', 'useremail', type_='foreignkey')
    op.drop_column('useremail', 'team_id')
    op.drop_column('useremail', 'org_id')

    op.alter_column('useremailclaim', 'user_id', existing_type=sa.INTEGER(), nullable=False)
    op.drop_constraint(u'useremailclaim_org_id_email_key', 'useremailclaim', type_='unique')
    op.drop_constraint(u'useremailclaim_team_id_email_key', 'useremailclaim', type_='unique')
    op.drop_constraint(u'useremailclaim_team_id_fkey', 'useremailclaim', type_='foreignkey')
    op.drop_constraint(u'useremailclaim_org_id_fkey', 'useremailclaim', type_='foreignkey')
    op.drop_column('useremailclaim', 'team_id')
    op.drop_column('useremailclaim', 'org_id')

    op.alter_column('userphone', 'user_id', existing_type=sa.INTEGER(), nullable=False)
    op.drop_constraint(u'userphone_org_id_fkey', 'userphone', type_='foreignkey')
    op.drop_constraint(u'userphone_team_id_fkey', 'userphone', type_='foreignkey')
    op.drop_column('userphone', 'team_id')
    op.drop_column('userphone', 'org_id')

    op.alter_column('userphoneclaim', 'user_id', existing_type=sa.INTEGER(), nullable=False)
    op.drop_constraint(u'userphoneclaim_org_id_phone_key', 'userphoneclaim', type_='unique')
    op.drop_constraint(u'userphoneclaim_team_id_phone_key', 'userphoneclaim', type_='unique')
    op.drop_constraint(u'userphoneclaim_team_id_fkey', 'userphoneclaim', type_='foreignkey')
    op.drop_constraint(u'userphoneclaim_org_id_fkey', 'userphoneclaim', type_='foreignkey')
    op.drop_column('userphoneclaim', 'team_id')
    op.drop_column('userphoneclaim', 'org_id')


def downgrade():
    op.add_column('userphoneclaim', sa.Column('org_id', sa.INTEGER(), autoincrement=False, nullable=True))
    op.add_column('userphoneclaim', sa.Column('team_id', sa.INTEGER(), autoincrement=False, nullable=True))
    op.create_foreign_key(u'userphoneclaim_org_id_fkey', 'userphoneclaim', 'organization', ['org_id'], ['id'])
    op.create_foreign_key(u'userphoneclaim_team_id_fkey', 'userphoneclaim', 'team', ['team_id'], ['id'])
    op.create_unique_constraint(u'userphoneclaim_team_id_phone_key', 'userphoneclaim', ['team_id', 'phone'])
    op.create_unique_constraint(u'userphoneclaim_org_id_phone_key', 'userphoneclaim', ['org_id', 'phone'])
    op.alter_column('userphoneclaim', 'user_id', existing_type=sa.INTEGER(), nullable=True)
    op.create_check_constraint('userphoneclaim_user_id_or_org_id_or_team_id', 'userphoneclaim',
        sa.case([(column('user_id') != None, 1)], else_=0) +
        sa.case([(column('org_id') != None, 1)], else_=0) +
        sa.case([(column('team_id') != None, 1)], else_=0) == 1)  # NOQA

    op.add_column('userphone', sa.Column('org_id', sa.INTEGER(), autoincrement=False, nullable=True))
    op.add_column('userphone', sa.Column('team_id', sa.INTEGER(), autoincrement=False, nullable=True))
    op.create_foreign_key(u'userphone_team_id_fkey', 'userphone', 'team', ['team_id'], ['id'])
    op.create_foreign_key(u'userphone_org_id_fkey', 'userphone', 'organization', ['org_id'], ['id'])
    op.alter_column('userphone', 'user_id', existing_type=sa.INTEGER(), nullable=True)
    op.create_check_constraint('userphone_user_id_or_org_id_or_team_id', 'userphone',
        sa.case([(column('user_id') != None, 1)], else_=0) +
        sa.case([(column('org_id') != None, 1)], else_=0) +
        sa.case([(column('team_id') != None, 1)], else_=0) == 1)  # NOQA

    op.add_column('useremailclaim', sa.Column('org_id', sa.INTEGER(), autoincrement=False, nullable=True))
    op.add_column('useremailclaim', sa.Column('team_id', sa.INTEGER(), autoincrement=False, nullable=True))
    op.create_foreign_key(u'useremailclaim_org_id_fkey', 'useremailclaim', 'organization', ['org_id'], ['id'])
    op.create_foreign_key(u'useremailclaim_team_id_fkey', 'useremailclaim', 'team', ['team_id'], ['id'])
    op.create_unique_constraint(u'useremailclaim_team_id_email_key', 'useremailclaim', ['team_id', 'email'])
    op.create_unique_constraint(u'useremailclaim_org_id_email_key', 'useremailclaim', ['org_id', 'email'])
    op.alter_column('useremailclaim', 'user_id', existing_type=sa.INTEGER(), nullable=True)
    op.create_check_constraint('useremailclaim_user_id_or_org_id_or_team_id', 'useremailclaim',
        sa.case([(column('user_id') != None, 1)], else_=0) +
        sa.case([(column('org_id') != None, 1)], else_=0) +
        sa.case([(column('team_id') != None, 1)], else_=0) == 1)  # NOQA

    op.add_column('useremail', sa.Column('org_id', sa.INTEGER(), autoincrement=False, nullable=True))
    op.add_column('useremail', sa.Column('team_id', sa.INTEGER(), autoincrement=False, nullable=True))
    op.create_foreign_key(u'useremail_org_id_fkey', 'useremail', 'organization', ['org_id'], ['id'])
    op.create_foreign_key(u'useremail_team_id_fkey', 'useremail', 'team', ['team_id'], ['id'])
    op.alter_column('useremail', 'user_id', existing_type=sa.INTEGER(), nullable=True)
    op.create_check_constraint('useremail_user_id_or_org_id_or_team_id', 'useremail',
        sa.case([(column('user_id') != None, 1)], else_=0) +
        sa.case([(column('org_id') != None, 1)], else_=0) +
        sa.case([(column('team_id') != None, 1)], else_=0) == 1)  # NOQA
