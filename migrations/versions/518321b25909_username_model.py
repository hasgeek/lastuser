# -*- coding: utf-8 -*-
"""Username model

Revision ID: 518321b25909
Revises: c446b9bc0691
Create Date: 2018-09-29 02:23:56.669605

"""
from alembic import op
from sqlalchemy_utils import UUIDType
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '518321b25909'
down_revision = 'c446b9bc0691'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'name',
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.Column('name', sa.Unicode(length=63), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('org_id', sa.Integer(), nullable=True),
        sa.Column('reserved', sa.Boolean(), nullable=False),
        sa.Column('id', UUIDType(binary=False), nullable=False),
        sa.CheckConstraint(
            u'CASE WHEN (user_id IS NOT NULL) THEN 1 ELSE 0 END + CASE WHEN (org_id IS NOT NULL) THEN 1 ELSE 0 END + CASE WHEN (reserved = true) THEN 1 ELSE 0 END = 1',
            name='username_owner_check',
        ),
        sa.ForeignKeyConstraint(['org_id'], ['organization.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['user_id'], ['user.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name'),
        sa.UniqueConstraint('org_id'),
        sa.UniqueConstraint('user_id'),
    )
    op.create_index(op.f('ix_name_reserved'), 'name', ['reserved'], unique=False)

    op.execute(
        sa.DDL(
            '''
        INSERT INTO "name" (reserved, id, created_at, updated_at, name, user_id)
        SELECT False, uuid, created_at, updated_at, username, id FROM "user"
        WHERE username IS NOT null
        ORDER BY created_at;
        '''
        )
    )
    op.execute(
        sa.DDL(
            '''
        INSERT INTO "name" (reserved, id, created_at, updated_at, name, org_id)
        SELECT False, uuid, created_at, updated_at, name, id FROM "organization"
        WHERE name IS NOT null
        ORDER BY created_at;
        '''
        )
    )

    op.drop_index(op.f('ix_user_username_lower'), table_name='user')
    op.execute(
        sa.DDL(
            '''CREATE UNIQUE INDEX ix_name_name_lower ON "name" (lower(name) varchar_pattern_ops);'''
        )
    )

    op.drop_constraint(u'organization_name_key', 'organization', type_='unique')
    op.drop_column(u'organization', 'name')
    op.drop_constraint(u'user_username_key', 'user', type_='unique')
    op.drop_column(u'user', 'username')


def downgrade():
    op.add_column(
        u'user',
        sa.Column(
            'username', sa.VARCHAR(length=80), autoincrement=False, nullable=True
        ),
    )
    op.create_unique_constraint(u'user_username_key', 'user', ['username'])
    op.add_column(
        u'organization',
        sa.Column('name', sa.VARCHAR(length=80), autoincrement=False, nullable=True),
    )
    op.create_unique_constraint(u'organization_name_key', 'organization', ['name'])

    op.drop_index(op.f('ix_name_name_lower'), table_name='name')
    op.execute(
        sa.DDL(
            '''CREATE INDEX ix_user_username_lower ON "user" (lower(username) varchar_pattern_ops);'''
        )
    )

    op.execute(
        sa.DDL(
            '''
        UPDATE "user" SET (username) = (SELECT name FROM "name" WHERE "name".user_id = "user".id)
        '''
        )
    )
    op.execute(
        sa.DDL(
            '''
        UPDATE "organization" SET (name) = (SELECT name FROM "name" WHERE "name".org_id = "organization".id)
        '''
        )
    )

    op.drop_index(op.f('ix_name_reserved'), table_name='name')
    op.drop_table('name')
