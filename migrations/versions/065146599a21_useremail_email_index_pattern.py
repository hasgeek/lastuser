"""UserEmail email index pattern

Revision ID: 065146599a21
Revises: 518321b25909
Create Date: 2018-10-01 11:41:56.346902

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '065146599a21'
down_revision = '518321b25909'
branch_labels = None
depends_on = None


# This revision fixes a bug introduced in revision 3b17b62bf8e4,
# where text_pattern_ops was used instead of varchar_pattern_ops

def upgrade():
    op.drop_index('ix_useremail_email_lower')
    op.execute(sa.DDL(
        'CREATE UNIQUE INDEX ix_useremail_email_lower ON useremail (lower(email) varchar_pattern_ops);'))


def downgrade():
    op.drop_index('ix_useremail_email_lower')
    op.execute(sa.DDL(
        'CREATE UNIQUE INDEX ix_useremail_email_lower ON useremail (lower(email) text_pattern_ops);'))
