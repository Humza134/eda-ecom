"""Store secure email verification state.

Revision ID: c5b84f9d2a31
Revises: aafd42dd5968
Create Date: 2026-10-16
"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa
import sqlmodel


revision: str = "c5b84f9d2a31"
down_revision: str | Sequence[str] | None = "aafd42dd5968"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Existing plaintext OTPs are intentionally discarded. Affected users must
    # request a new code, which prevents old codes from being treated as hashes.
    op.add_column(
        "user",
        sa.Column(
            "email_verification_code_hash",
            sqlmodel.sql.sqltypes.AutoString(length=64),
            nullable=True,
        ),
    )
    op.add_column(
        "user",
        sa.Column(
            "email_verification_attempts",
            sa.Integer(),
            nullable=False,
            server_default="0",
        ),
    )
    op.drop_column("user", "email_verification_code")
    op.alter_column("user", "email_verification_attempts", server_default=None)


def downgrade() -> None:
    op.add_column(
        "user",
        sa.Column(
            "email_verification_code",
            sqlmodel.sql.sqltypes.AutoString(length=6),
            nullable=True,
        ),
    )
    op.drop_column("user", "email_verification_attempts")
    op.drop_column("user", "email_verification_code_hash")
