# -*- coding: utf-8 -*-
"""Updated primary trigger

Revision ID: 3506dcc19f7a
Revises: b332c012c57d
Create Date: 2017-08-23 09:15:59.855718

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '3506dcc19f7a'
down_revision = 'b332c012c57d'
branch_labels = None
depends_on = None


def upgrade():
    op.execute(
        sa.DDL(
            '''
        DROP TRIGGER user_useremail_primary_trigger ON user_useremail_primary;
        DROP FUNCTION user_useremail_primary_validate();
        '''
        )
    )
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
        CREATE FUNCTION user_useremail_primary_validate() RETURNS TRIGGER AS $$
        DECLARE
            target RECORD;
        BEGIN
            IF (NEW.useremail_id IS NOT NULL) THEN
                SELECT user_id INTO target FROM useremail WHERE id = NEW.useremail_id;
                IF (target.user_id != NEW.user_id) THEN
                    RAISE foreign_key_violation USING MESSAGE = 'The target is not affiliated with this parent';
                END IF;
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
    op.execute(
        sa.DDL(
            '''
        CREATE FUNCTION user_userphone_primary_validate() RETURNS TRIGGER AS $$
        DECLARE
            target RECORD;
        BEGIN
            IF (NEW.userphone_id IS NOT NULL) THEN
                SELECT user_id INTO target FROM userphone WHERE id = NEW.userphone_id;
                IF (target.user_id != NEW.user_id) THEN
                    RAISE foreign_key_violation USING MESSAGE = 'The target is not affiliated with this parent';
                END IF;
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


def downgrade():
    op.execute(
        sa.DDL(
            '''
        DROP TRIGGER user_useremail_primary_trigger ON user_useremail_primary;
        DROP FUNCTION user_useremail_primary_validate();
        '''
        )
    )
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
