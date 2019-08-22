# -*- coding: utf-8 -*-
"""Email and phone linked to org and team

Revision ID: d94bd59a2f0
Revises: 120ee669cc20
Create Date: 2015-01-05 02:22:32.686681

"""

# revision identifiers, used by Alembic.
revision = 'd94bd59a2f0'
down_revision = '120ee669cc20'

from alembic import op
from sqlalchemy.sql import column
import sqlalchemy as sa


def upgrade():
    op.add_column('useremail', sa.Column('org_id', sa.Integer(), nullable=True))
    op.add_column('useremail', sa.Column('team_id', sa.Integer(), nullable=True))
    op.alter_column('useremail', 'user_id', existing_type=sa.INTEGER(), nullable=True)
    op.create_foreign_key(
        'useremail_org_id_fkey', 'useremail', 'organization', ['org_id'], ['id']
    )
    op.create_foreign_key(
        'useremail_team_id_fkey', 'useremail', 'team', ['team_id'], ['id']
    )
    op.create_check_constraint(
        'useremail_user_id_or_org_id_or_team_id',
        'useremail',
        sa.case([(column('user_id').isnot(None), 1)], else_=0)
        + sa.case([(column('org_id').isnot(None), 1)], else_=0)
        + sa.case([(column('team_id').isnot(None), 1)], else_=0)
        == 1,
    )

    op.add_column('useremailclaim', sa.Column('org_id', sa.Integer(), nullable=True))
    op.add_column('useremailclaim', sa.Column('team_id', sa.Integer(), nullable=True))
    op.alter_column(
        'useremailclaim', 'user_id', existing_type=sa.INTEGER(), nullable=True
    )
    op.create_index(
        op.f('ix_useremailclaim_email'), 'useremailclaim', ['email'], unique=False
    )
    op.create_index(
        op.f('ix_useremailclaim_md5sum'), 'useremailclaim', ['md5sum'], unique=False
    )
    op.create_unique_constraint(
        'useremailclaim_org_id_email_key', 'useremailclaim', ['org_id', 'email']
    )
    op.create_unique_constraint(
        'useremailclaim_team_id_email_key', 'useremailclaim', ['team_id', 'email']
    )
    op.create_foreign_key(
        'useremailclaim_org_id_fkey',
        'useremailclaim',
        'organization',
        ['org_id'],
        ['id'],
    )
    op.create_foreign_key(
        'useremailclaim_team_id_fkey', 'useremailclaim', 'team', ['team_id'], ['id']
    )
    op.create_check_constraint(
        'useremailclaim_user_id_or_org_id_or_team_id',
        'useremailclaim',
        sa.case([(column('user_id').isnot(None), 1)], else_=0)
        + sa.case([(column('org_id').isnot(None), 1)], else_=0)
        + sa.case([(column('team_id').isnot(None), 1)], else_=0)
        == 1,
    )

    op.alter_column('userphone', 'phone', type_=sa.Unicode(16))
    op.add_column('userphone', sa.Column('org_id', sa.Integer(), nullable=True))
    op.add_column('userphone', sa.Column('team_id', sa.Integer(), nullable=True))
    op.alter_column('userphone', 'user_id', existing_type=sa.INTEGER(), nullable=True)
    op.create_foreign_key(
        'userphone_org_id_fkey', 'userphone', 'organization', ['org_id'], ['id']
    )
    op.create_foreign_key(
        'userphone_team_id_fkey', 'userphone', 'team', ['team_id'], ['id']
    )
    op.create_check_constraint(
        'userphone_user_id_or_org_id_or_team_id',
        'userphone',
        sa.case([(column('user_id').isnot(None), 1)], else_=0)
        + sa.case([(column('org_id').isnot(None), 1)], else_=0)
        + sa.case([(column('team_id').isnot(None), 1)], else_=0)
        == 1,
    )

    op.alter_column('userphoneclaim', 'phone', type_=sa.Unicode(16))
    op.add_column('userphoneclaim', sa.Column('org_id', sa.Integer(), nullable=True))
    op.add_column('userphoneclaim', sa.Column('team_id', sa.Integer(), nullable=True))
    op.alter_column(
        'userphoneclaim', 'user_id', existing_type=sa.INTEGER(), nullable=True
    )
    op.create_index(
        op.f('ix_userphoneclaim_phone'), 'userphoneclaim', ['phone'], unique=False
    )
    op.create_unique_constraint(
        'userphoneclaim_team_id_phone_key', 'userphoneclaim', ['team_id', 'phone']
    )
    op.create_unique_constraint(
        'userphoneclaim_org_id_phone_key', 'userphoneclaim', ['org_id', 'phone']
    )
    op.create_foreign_key(
        'userphoneclaim_org_id_fkey',
        'userphoneclaim',
        'organization',
        ['org_id'],
        ['id'],
    )
    op.create_foreign_key(
        'userphoneclaim_team_id_fkey', 'userphoneclaim', 'team', ['team_id'], ['id']
    )
    op.create_check_constraint(
        'userphoneclaim_user_id_or_org_id_or_team_id',
        'userphoneclaim',
        sa.case([(column('user_id').isnot(None), 1)], else_=0)
        + sa.case([(column('org_id').isnot(None), 1)], else_=0)
        + sa.case([(column('team_id').isnot(None), 1)], else_=0)
        == 1,
    )


def downgrade():
    op.drop_constraint('userphoneclaim_user_id_or_org_id_or_team_id', 'userphoneclaim')
    op.drop_constraint(
        'userphoneclaim_team_id_fkey', 'userphoneclaim', type_='foreignkey'
    )
    op.drop_constraint(
        'userphoneclaim_org_id_fkey', 'userphoneclaim', type_='foreignkey'
    )
    op.drop_constraint(
        'userphoneclaim_team_id_phone_key', 'userphoneclaim', type_='unique'
    )
    op.drop_constraint(
        'userphoneclaim_org_id_phone_key', 'userphoneclaim', type_='unique'
    )
    op.drop_index(op.f('ix_userphoneclaim_phone'), table_name='userphoneclaim')
    op.alter_column(
        'userphoneclaim', 'user_id', existing_type=sa.INTEGER(), nullable=False
    )
    op.drop_column('userphoneclaim', 'team_id')
    op.drop_column('userphoneclaim', 'org_id')
    op.alter_column('userphoneclaim', 'phone', type_=sa.Unicode(80))

    op.drop_constraint(
        'userphone_user_id_or_org_id_or_team_id', 'userphone', type_='check'
    )
    op.drop_constraint('userphone_team_id_fkey', 'userphone', type_='foreignkey')
    op.drop_constraint('userphone_org_id_fkey', 'userphone', type_='foreignkey')
    op.alter_column('userphone', 'user_id', existing_type=sa.INTEGER(), nullable=False)
    op.drop_column('userphone', 'team_id')
    op.drop_column('userphone', 'org_id')
    op.alter_column('userphone', 'phone', type_=sa.Unicode(80))

    op.drop_constraint(
        'useremailclaim_user_id_or_org_id_or_team_id', 'useremailclaim', type_='check'
    )
    op.drop_constraint(
        'useremailclaim_team_id_fkey', 'useremailclaim', type_='foreignkey'
    )
    op.drop_constraint(
        'useremailclaim_org_id_fkey', 'useremailclaim', type_='foreignkey'
    )
    op.drop_constraint(
        'useremailclaim_team_id_email_key', 'useremailclaim', type_='unique'
    )
    op.drop_constraint(
        'useremailclaim_org_id_email_key', 'useremailclaim', type_='unique'
    )
    op.drop_index(op.f('ix_useremailclaim_md5sum'), table_name='useremailclaim')
    op.drop_index(op.f('ix_useremailclaim_email'), table_name='useremailclaim')
    op.alter_column(
        'useremailclaim', 'user_id', existing_type=sa.INTEGER(), nullable=False
    )
    op.drop_column('useremailclaim', 'team_id')
    op.drop_column('useremailclaim', 'org_id')

    op.drop_constraint(
        'useremail_user_id_or_org_id_or_team_id', 'useremail', type_='check'
    )
    op.drop_constraint('useremail_team_id_fkey', 'useremail', type_='foreignkey')
    op.drop_constraint('useremail_org_id_fkey', 'useremail', type_='foreignkey')
    op.alter_column('useremail', 'user_id', existing_type=sa.INTEGER(), nullable=False)
    op.drop_column('useremail', 'team_id')
    op.drop_column('useremail', 'org_id')
