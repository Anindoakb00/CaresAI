"""baseline CareShield schema

Revision ID: 0001_initial
"""
from alembic import op

from app.db import Base
from app import models  # noqa: F401

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # The local prototype and the migration share SQLAlchemy metadata so the
    # baseline stays portable across SQLite and PostgreSQL.
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)


def downgrade() -> None:
    Base.metadata.drop_all(bind=op.get_bind())

