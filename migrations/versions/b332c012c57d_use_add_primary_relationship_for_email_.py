# -*- coding: utf-8 -*-
"""Use add_primary_relationship for email and phone

Revision ID: b332c012c57d
Revises: 3b17b62bf8e4
Create Date: 2017-08-17 14:25:25.709371

"""
from alembic import op
from sqlalchemy.sql import column, expression, table
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'b332c012c57d'
down_revision = '3b17b62bf8e4'
branch_labels = None
depends_on = None


useremail = table(
    'useremail',
    column('id', sa.Integer()),
    column('created_at', sa.DateTime()),
    column('updated_at', sa.DateTime()),
    column('user_id', sa.Integer()),
    column('primary', sa.BOOLEAN()),
)

userphone = table(
    'userphone',
    column('id', sa.Integer()),
    column('created_at', sa.DateTime()),
    column('updated_at', sa.DateTime()),
    column('user_id', sa.Integer()),
    column('primary', sa.BOOLEAN()),
)

user_useremail_primary = table(
    'user_useremail_primary',
    column('user_id', sa.Integer()),
    column('useremail_id', sa.Integer()),
    column('created_at', sa.DateTime()),
    column('updated_at', sa.DateTime()),
)

user_userphone_primary = table(
    'user_userphone_primary',
    column('user_id', sa.Integer()),
    column('userphone_id', sa.Integer()),
    column('created_at', sa.DateTime()),
    column('updated_at', sa.DateTime()),
)


def upgrade():
    op.create_table(
        'user_useremail_primary',
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('useremail_id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['user.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['useremail_id'], ['useremail.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('user_id'),
    )
    op.execute(
        sa.DDL(
            '''
        CREATE FUNCTION user_useremail_primary_validate() RETURNS TRIGGER AS $$
        DECLARE
            target RECORD;
        BEGIN
            SELECT user_id INTO target FROM useremail WHERE id = NEW.useremail_id;
            IF (target.user_id != NEW.user_id) THEN
                RAISE foreign_key_violation USING MESSAGE = 'The target is not affiliated with this parent';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        CREATE TRIGGER user_useremail_primary_trigger BEFORE INSERT OR UPDATE
        ON user_useremail_primary
        FOR EACH ROW EXECUTE PROCEDURE user_useremail_primary_validate();
        '''
        )
    )

    op.create_table(
        'user_userphone_primary',
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('userphone_id', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['user.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['userphone_id'], ['userphone.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('user_id'),
    )
    op.execute(
        sa.DDL(
            '''
        CREATE FUNCTION user_userphone_primary_validate() RETURNS TRIGGER AS $$
        DECLARE
            target RECORD;
        BEGIN
            SELECT user_id INTO target FROM userphone WHERE id = NEW.userphone_id;
            IF (target.user_id != NEW.user_id) THEN
                RAISE foreign_key_violation USING MESSAGE = 'The target is not affiliated with this parent';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        CREATE TRIGGER user_userphone_primary_trigger BEFORE INSERT OR UPDATE
        ON user_userphone_primary
        FOR EACH ROW EXECUTE PROCEDURE user_userphone_primary_validate();
        '''
        )
    )

    # Next: perform data migration

    # Problem: more than one primary email/phone may exist for each user because there
    # was no integrity check on the primary flag.
    # Solution: partition by user_id to only retrieve the first match, ignoring the rest.

    # Problem: Zero primaries may exist as well.
    # Solution: "Order by primary desc" instead of "where primary = true" to bump up
    # the first non-primary to primary status.

    op.execute(
        sa.DDL(
            '''
        INSERT INTO user_useremail_primary (user_id, useremail_id, created_at, updated_at)
        SELECT DISTINCT ON (user_id) user_id, id, created_at, updated_at
        FROM useremail
        ORDER BY user_id, "primary" DESC;
    '''
        )
    )
    op.execute(
        sa.DDL(
            '''
        INSERT INTO user_userphone_primary (user_id, userphone_id, created_at, updated_at)
        SELECT DISTINCT ON (user_id) user_id, id, created_at, updated_at
        FROM userphone
        ORDER BY user_id, "primary" DESC;
    '''
        )
    )

    # Finally: drop old 'primary' columns
    op.drop_column('useremail', 'primary')
    op.drop_column('userphone', 'primary')


def downgrade():
    # 1. Add primary columns
    op.add_column(
        'userphone',
        sa.Column(
            'primary',
            sa.BOOLEAN(),
            autoincrement=False,
            nullable=False,
            server_default=expression.false(),
        ),
    )
    op.add_column(
        'useremail',
        sa.Column(
            'primary',
            sa.BOOLEAN(),
            autoincrement=False,
            nullable=False,
            server_default=expression.false(),
        ),
    )
    op.alter_column('userphone', 'primary', server_default=None)
    op.alter_column('useremail', 'primary', server_default=None)

    # 2. Update primary flags
    op.execute(
        sa.DDL(
            '''
        UPDATE useremail SET "primary" = true
        FROM user_useremail_primary WHERE useremail.id = user_useremail_primary.useremail_id;
        '''
        )
    )
    op.execute(
        sa.DDL(
            '''
        UPDATE userphone SET "primary" = true
        FROM user_userphone_primary WHERE userphone.id = user_userphone_primary.userphone_id;
        '''
        )
    )

    # 3. Drop primary tables
    op.execute(
        sa.DDL(
            '''
        DROP TRIGGER user_userphone_primary_trigger ON user_userphone_primary;
        DROP FUNCTION user_userphone_primary_validate();
        '''
        )
    )
    op.execute(
        sa.DDL(
            '''
        DROP TRIGGER user_useremail_primary_trigger ON user_useremail_primary;
        DROP FUNCTION user_useremail_primary_validate();
        '''
        )
    )
    op.drop_table('user_userphone_primary')
    op.drop_table('user_useremail_primary')
