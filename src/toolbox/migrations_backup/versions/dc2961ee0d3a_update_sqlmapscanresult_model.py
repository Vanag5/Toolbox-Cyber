"""Update SQLMapScanResult model

Revision ID: dc2961ee0d3a
Revises: 1f89b98d4499
Create Date: 2025-05-31 09:38:34.098310

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'dc2961ee0d3a'
down_revision = '1f89b98d4499'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('sql_map_scan_results', schema=None) as batch_op:
        batch_op.alter_column('results_json',
               existing_type=sa.TEXT(),
               nullable=True)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('sql_map_scan_results', schema=None) as batch_op:
        batch_op.alter_column('results_json',
               existing_type=sa.TEXT(),
               nullable=False)

    # ### end Alembic commands ###
