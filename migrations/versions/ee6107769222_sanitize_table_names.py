# -*- coding: utf-8 -*-
"""Sanitize table names

Revision ID: ee6107769222
Revises: cefeae5ffcf9
Create Date: 2020-03-26 02:14:26.581575

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'ee6107769222'
down_revision = 'cefeae5ffcf9'
branch_labels = None
depends_on = None


# (old, new)
renamed_tables = [
    ('authcode', 'auth_code'),
    ('authtoken', 'auth_token'),
    ('client', 'auth_client'),
    ('client_credential', 'auth_client_credential'),
    ('name', 'account_name'),
    ('passwordresetrequest', 'auth_password_reset_request'),
    ('session_client', 'auth_client_user_session'),
    ('smsmessage', 'sms_message'),
    ('teamclientpermissions', 'auth_client_team_permissions'),
    ('user_useremail_primary', 'user_user_email_primary'),
    ('user_userphone_primary', 'user_user_phone_primary'),
    ('userclientpermissions', 'auth_client_user_permissions'),
    ('useremail', 'user_email'),
    ('useremailclaim', 'user_email_claim'),
    ('userexternalid', 'user_externalid'),
    ('userflashmessage', 'user_flash_message'),
    ('useroldid', 'user_oldid'),
    ('userphone', 'user_phone'),
    ('userphoneclaim', 'user_phone_claim'),
]


# (old, new)
renamed_sequences = [
    ('authcode_id_seq', 'auth_code_id_seq'),
    ('authtoken_id_seq', 'auth_token_id_seq'),
    ('client_id_seq', 'auth_client_id_seq'),
    ('client_credential_id_seq', 'auth_client_credential_id_seq'),
    ('passwordresetrequest_id_seq', 'auth_password_reset_request_id_seq'),
    ('smsmessage_id_seq', 'sms_message_id_seq'),
    ('teamclientpermissions_id_seq', 'auth_client_team_permissions_id_seq'),
    ('userclientpermissions_id_seq', 'auth_client_user_permissions_id_seq'),
    ('useremail_id_seq', 'user_email_id_seq'),
    ('useremailclaim_id_seq', 'user_email_claim_id_seq'),
    ('userexternalid_id_seq', 'user_externalid_id_seq'),
    ('userflashmessage_id_seq', 'user_flash_message_id_seq'),
    ('userphone_id_seq', 'user_phone_id_seq'),
    ('userphoneclaim_id_seq', 'user_phone_claim_id_seq'),
]


# (table, old, new)
renamed_columns = [
    ('auth_code', 'client_id', 'auth_client_id'),
    ('auth_code', 'session_id', 'user_session_id'),
    ('auth_token', 'client_id', 'auth_client_id'),
    ('auth_client', 'org_id', 'organization_id'),
    ('auth_client_credential', 'client_id', 'auth_client_id'),
    ('account_name', 'org_id', 'organization_id'),
    ('auth_client_user_session', 'client_id', 'auth_client_id'),
    ('auth_client_team_permissions', 'client_id', 'auth_client_id'),
    ('user_user_email_primary', 'useremail_id', 'user_email_id'),
    ('user_user_phone_primary', 'userphone_id', 'user_phone_id'),
    ('auth_client_user_permissions', 'client_id', 'auth_client_id'),
    ('sms_message', 'transaction_id', 'transactionid'),
    ('team', 'org_id', 'organization_id'),
]


# (table, old, new)
renamed_constraints = [
    ('auth_code', 'authcode_pkey', 'auth_code_pkey'),
    ('auth_code', 'authcode_client_id_fkey', 'auth_code_auth_client_id_fkey'),
    ('auth_code', 'authcode_session_id_fkey', 'auth_code_user_session_id_fkey'),
    ('auth_code', 'authcode_user_id_fkey', 'auth_code_user_id_fkey'),
    ('auth_token', 'authtoken_pkey', 'auth_token_pkey'),
    ('auth_token', 'authtoken_refresh_token_key', 'auth_token_refresh_token_key'),
    ('auth_token', 'authtoken_token_key', 'auth_token_token_key'),
    (
        'auth_token',
        'authtoken_user_id_client_id_key',
        'auth_token_user_id_auth_client_id_key',
    ),
    (
        'auth_token',
        'authtoken_user_session_id_client_id_key',
        'auth_token_user_session_id_auth_client_id_key',
    ),
    ('auth_token', 'authtoken_client_id_fkey', 'auth_token_auth_client_id_fkey'),
    ('auth_token', 'authtoken_user_id_fkey', 'auth_token_user_id_fkey'),
    ('auth_token', 'authtoken_user_session_id_fkey', 'auth_token_user_session_id_fkey'),
    ('auth_client', 'client_pkey', 'auth_client_pkey'),
    ('auth_client', 'client_namespace_key', 'auth_client_namespace_key'),
    ('auth_client', 'client_uuid_key', 'auth_client_uuid_key'),
    ('auth_client', 'client_user_id_or_org_id', 'auth_client_owner_check'),
    ('auth_client', 'client_org_id_fkey', 'auth_client_organization_id_fkey'),
    ('auth_client', 'client_user_id_fkey', 'auth_client_user_id_fkey'),
    ('auth_client_credential', 'client_credential_pkey', 'auth_client_credential_pkey'),
    (
        'auth_client_credential',
        'client_credential_name_key',
        'auth_client_credential_name_key',
    ),
    (
        'auth_client_credential',
        'client_credential_client_id_fkey',
        'auth_client_credential_auth_client_id_fkey',
    ),
    ('account_name', 'name_pkey', 'account_name_pkey'),
    ('account_name', 'name_name_key', 'account_name_name_key'),
    ('account_name', 'name_org_id_key', 'account_name_organization_id_key'),
    ('account_name', 'name_user_id_key', 'account_name_user_id_key'),
    ('account_name', 'username_owner_check', 'account_name_owner_check'),
    ('account_name', 'name_org_id_fkey', 'account_name_organization_id_fkey'),
    ('account_name', 'name_user_id_fkey', 'account_name_user_id_fkey'),
    (
        'auth_password_reset_request',
        'passwordresetrequest_pkey',
        'auth_password_reset_request_pkey',
    ),
    (
        'auth_password_reset_request',
        'passwordresetrequest_user_id_fkey',
        'auth_password_reset_request_user_id_fkey',
    ),
    (
        'auth_client_user_session',
        'session_client_pkey',
        'auth_client_user_session_pkey',
    ),
    (
        'auth_client_user_session',
        'session_client_client_id_fkey',
        'auth_client_user_session_auth_client_id_fkey',
    ),
    (
        'auth_client_user_session',
        'session_client_user_session_id_fkey',
        'auth_client_user_session_user_session_id_fkey',
    ),
    ('sms_message', 'smsmessage_pkey', 'sms_message_pkey'),
    ('sms_message', 'smsmessage_transaction_id_key', 'sms_message_transactionid_key'),
    ('team', 'team_org_id_fkey', 'team_organization_id_fkey'),
    (
        'auth_client_team_permissions',
        'teamclientpermissions_pkey',
        'auth_client_team_permissions_pkey',
    ),
    (
        'auth_client_team_permissions',
        'teamclientpermissions_team_id_client_id_key',
        'auth_client_team_permissions_team_id_client_id_key',
    ),
    (
        'auth_client_team_permissions',
        'teamclientpermissions_client_id_fkey',
        'auth_client_team_permissions_client_id_fkey',
    ),
    (
        'auth_client_team_permissions',
        'teamclientpermissions_team_id_fkey',
        'auth_client_team_permissions_team_id_fkey',
    ),
    (
        'user_user_email_primary',
        'user_useremail_primary_pkey',
        'user_user_email_primary_pkey',
    ),
    (
        'user_user_email_primary',
        'user_useremail_primary_user_id_fkey',
        'user_user_email_primary_user_id_fkey',
    ),
    (
        'user_user_email_primary',
        'user_useremail_primary_useremail_id_fkey',
        'user_user_email_primary_user_email_id_fkey',
    ),
    (
        'user_user_phone_primary',
        'user_userphone_primary_pkey',
        'user_user_phone_primary_pkey',
    ),
    (
        'user_user_phone_primary',
        'user_userphone_primary_user_id_fkey',
        'user_user_phone_primary_user_id_fkey',
    ),
    (
        'user_user_phone_primary',
        'user_userphone_primary_userphone_id_fkey',
        'user_user_phone_primary_user_phone_id_fkey',
    ),
    (
        'auth_client_user_permissions',
        'userclientpermissions_pkey',
        'auth_client_user_permissions_pkey',
    ),
    (
        'auth_client_user_permissions',
        'userclientpermissions_user_id_client_id_key',
        'auth_client_user_permissions_user_id_auth_client_id_key',
    ),
    (
        'auth_client_user_permissions',
        'userclientpermissions_client_id_fkey',
        'auth_client_user_permissions_auth_client_id_fkey',
    ),
    (
        'auth_client_user_permissions',
        'userclientpermissions_user_id_fkey',
        'auth_client_user_permissions_user_id_fkey',
    ),
    ('user_email', 'useremail_pkey', 'user_email_pkey'),
    ('user_email', 'useremail_email_key', 'user_email_email_key'),
    ('user_email', 'useremail_md5sum_key', 'user_email_md5sum_key'),
    ('user_email', 'useremail_user_id_fkey', 'user_email_user_id_fkey'),
    ('user_email_claim', 'useremailclaim_pkey', 'user_email_claim_pkey'),
    (
        'user_email_claim',
        'useremailclaim_user_id_email_key',
        'user_email_claim_user_id_email_key',
    ),
    (
        'user_email_claim',
        'useremailclaim_user_id_fkey',
        'user_email_claim_user_id_fkey',
    ),
    ('user_externalid', 'userexternalid_pkey', 'user_externalid_pkey'),
    (
        'user_externalid',
        'userexternalid_service_userid_key',
        'user_externalid_service_userid_key',
    ),
    ('user_externalid', 'userexternalid_user_id_fkey', 'user_externalid_user_id_fkey'),
    ('user_flash_message', 'userflashmessage_pkey', 'user_flash_message_pkey'),
    (
        'user_flash_message',
        'userflashmessage_user_id_fkey',
        'user_flash_message_user_id_fkey',
    ),
    ('user_oldid', 'useroldid_pkey', 'user_oldid_pkey'),
    ('user_oldid', 'useroldid_user_id_fkey', 'user_oldid_user_id_fkey'),
    ('user_phone', 'userphone_pkey', 'user_phone_pkey'),
    ('user_phone', 'userphone_phone_key', 'user_phone_phone_key'),
    ('user_phone', 'userphone_user_id_fkey', 'user_phone_user_id_fkey'),
    ('user_phone_claim', 'userphoneclaim_pkey', 'user_phone_claim_pkey'),
    (
        'user_phone_claim',
        'userphoneclaim_user_id_phone_key',
        'user_phone_claim_user_id_phone_key',
    ),
    (
        'user_phone_claim',
        'userphoneclaim_user_id_fkey',
        'user_phone_claim_user_id_fkey',
    ),
]


# (old, new)
renamed_indexes = [
    ('ix_authtoken_client_id', 'ix_auth_token_auth_client_id'),
    ('ix_name_name_lower', 'ix_account_name_name_lower'),
    ('ix_name_reserved', 'ix_account_name_reserved'),
    (
        'ix_teamclientpermissions_client_id',
        'ix_auth_client_team_permissions_auth_client_id',
    ),
    (
        'ix_userclientpermissions_client_id',
        'ix_auth_client_user_permissions_auth_client_id',
    ),
    ('ix_useremail_email_lower', 'ix_user_email_email_lower'),
    ('ix_useremail_domain', 'ix_user_email_domain'),
    ('ix_useremailclaim_domain', 'ix_user_email_claim_domain'),
    ('ix_useremailclaim_email', 'ix_user_email_claim_email'),
    ('ix_useremailclaim_md5sum', 'ix_user_email_claim_md5sum'),
    ('ix_userexternalid_username_lower', 'ix_user_externalid_username_lower'),
    ('ix_userphoneclaim_phone', 'ix_user_phone_claim_phone'),
]


# (table, old, new)
renamed_triggers = [
    (
        'user_user_email_primary',
        'user_useremail_primary_trigger',
        'user_user_email_primary_trigger',
    ),
    (
        'user_user_phone_primary',
        'user_userphone_primary_trigger',
        'user_user_phone_primary_trigger',
    ),
]


# (old, new)
renamed_functions = [
    ('user_useremail_primary_validate', 'user_user_email_primary_validate'),
    ('user_userphone_primary_validate', 'user_user_phone_primary_validate'),
]


old_func = '''
CREATE OR REPLACE FUNCTION public.user_useremail_primary_validate()
 RETURNS trigger
 LANGUAGE plpgsql
AS $function$
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
$function$;

CREATE OR REPLACE FUNCTION public.user_userphone_primary_validate()
 RETURNS trigger
 LANGUAGE plpgsql
AS $function$
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
$function$
'''


new_func = '''
CREATE OR REPLACE FUNCTION public.user_user_email_primary_validate()
 RETURNS trigger
 LANGUAGE plpgsql
AS $function$
DECLARE
    target RECORD;
BEGIN
    IF (NEW.user_email_id IS NOT NULL) THEN
        SELECT user_id INTO target FROM user_email WHERE id = NEW.user_email_id;
        IF (target.user_id != NEW.user_id) THEN
            RAISE foreign_key_violation USING MESSAGE = 'The target is not affiliated with this parent';
        END IF;
    END IF;
    RETURN NEW;
END;
$function$;

CREATE OR REPLACE FUNCTION public.user_user_phone_primary_validate()
 RETURNS trigger
 LANGUAGE plpgsql
AS $function$
DECLARE
    target RECORD;
BEGIN
    IF (NEW.user_phone_id IS NOT NULL) THEN
        SELECT user_id INTO target FROM user_phone WHERE id = NEW.user_phone_id;
        IF (target.user_id != NEW.user_id) THEN
            RAISE foreign_key_violation USING MESSAGE = 'The target is not affiliated with this parent';
        END IF;
    END IF;
    RETURN NEW;
END;
$function$
'''


def upgrade():
    for old, new in renamed_tables:
        op.rename_table(old, new)

    for old, new in renamed_sequences:
        op.execute(sa.DDL(f'ALTER SEQUENCE {old} RENAME TO {new}'))

    for table, old, new in renamed_columns:
        op.alter_column(table, old, new_column_name=new)

    for table, old, new in renamed_constraints:
        op.execute(sa.DDL(f'ALTER TABLE {table} RENAME CONSTRAINT {old} TO {new}'))

    for old, new in renamed_indexes:
        op.execute(sa.DDL(f'ALTER INDEX {old} RENAME TO {new}'))

    for table, old, new in renamed_triggers:
        op.execute(sa.DDL(f'ALTER TRIGGER {old} ON {table} RENAME TO {new}'))

    for old, new in renamed_functions:
        op.execute(sa.DDL(f'ALTER FUNCTION {old}() RENAME TO {new}'))
    # Replace function body after rename
    op.execute(sa.DDL(new_func))


def downgrade():
    for old, new in renamed_functions:
        op.execute(sa.DDL(f'ALTER FUNCTION {new}() RENAME TO {old}'))
    # Replace function body after rename
    op.execute(sa.DDL(old_func))

    for table, old, new in renamed_triggers:
        op.execute(sa.DDL(f'ALTER TRIGGER {new} ON {table} RENAME TO {old}'))

    for old, new in renamed_indexes:
        op.execute(sa.DDL(f'ALTER INDEX {new} RENAME TO {old}'))

    for table, old, new in renamed_constraints:
        op.execute(sa.DDL(f'ALTER TABLE {table} RENAME CONSTRAINT {new} TO {old}'))

    for table, old, new in renamed_columns:
        op.alter_column(table, new, new_column_name=old)

    for old, new in renamed_sequences:
        op.execute(sa.DDL(f'ALTER SEQUENCE {new} RENAME TO {old}'))

    for old, new in renamed_tables:
        op.rename_table(new, old)
