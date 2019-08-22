# -*- coding: utf-8 -*-
"""Members team

Revision ID: d055b3e2c89
Revises: 50c29617571d
Create Date: 2015-01-23 01:58:07.712054

"""

# revision identifiers, used by Alembic.
revision = 'd055b3e2c89'
down_revision = '50c29617571d'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.drop_constraint('fk_organization_owners_id', 'organization', type_='foreignkey')
    op.create_foreign_key(
        'organization_owners_id_fkey', 'organization', 'team', ['owners_id'], ['id']
    )
    op.add_column('organization', sa.Column('members_id', sa.Integer(), nullable=True))
    op.create_foreign_key(
        'organization_members_id_fkey', 'organization', 'team', ['members_id'], ['id']
    )
    op.add_column('team', sa.Column('domain', sa.Unicode(length=253), nullable=True))
    op.create_index(op.f('ix_team_domain'), 'team', ['domain'], unique=False)


def downgrade():
    op.drop_index(op.f('ix_team_domain'), table_name='team')
    op.drop_column('team', 'domain')
    op.drop_constraint(
        'organization_members_id_fkey', 'organization', type_='foreignkey'
    )
    op.drop_column('organization', 'members_id')
    op.drop_constraint(
        'organization_owners_id_fkey', 'organization', type_='foreignkey'
    )
    op.create_foreign_key(
        'fk_organization_owners_id', 'organization', 'team', ['owners_id'], ['id']
    )
