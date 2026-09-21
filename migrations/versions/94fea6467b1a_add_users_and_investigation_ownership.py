"""add users and investigation ownership

Revision ID: 94fea6467b1a
Revises: ce38c853f27c
Create Date: 2026-09-10 22:29:26.216175

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '94fea6467b1a'
down_revision: Union[str, Sequence[str], None] = 'ce38c853f27c'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    bind = op.get_bind()
    insp = sa.inspect(bind)

    if not insp.has_table('users'):
        op.create_table('users',
            sa.Column('user_id', sa.String(length=64), nullable=False),
            sa.Column('email', sa.String(length=255), nullable=False),
            sa.Column('password_hash', sa.String(length=255), nullable=False),
            sa.Column('full_name', sa.String(length=255), nullable=False),
            sa.Column('role', sa.String(length=32), nullable=True),
            sa.Column('is_active', sa.Boolean(), nullable=True),
            sa.Column('created_at', sa.DateTime(), nullable=True),
            sa.PrimaryKeyConstraint('user_id')
        )
        op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)
        op.create_index(op.f('ix_users_user_id'), 'users', ['user_id'], unique=False)

    existing_cols = [c['name'] for c in insp.get_columns('investigations')]
    if 'user_id' not in existing_cols:
        with op.batch_alter_table('investigations') as batch_op:
            batch_op.add_column(sa.Column('user_id', sa.String(length=64), nullable=True))
            batch_op.create_index(batch_op.f('ix_investigations_user_id'), ['user_id'], unique=False)
            batch_op.create_foreign_key('fk_investigations_user_id', 'users', ['user_id'], ['user_id'], ondelete='SET NULL')


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('investigations') as batch_op:
        batch_op.drop_constraint('fk_investigations_user_id', type_='foreignkey')
        batch_op.drop_index(batch_op.f('ix_investigations_user_id'))
        batch_op.drop_column('user_id')

    op.drop_index(op.f('ix_users_user_id'), table_name='users')
    op.drop_index(op.f('ix_users_email'), table_name='users')
    op.drop_table('users')
