"""Alembic environment for RECON-X.

Reads the database URL from ``app.config.settings.DATABASE_URL`` (so SQLite and
Postgres both work) and targets ``app.database.Base.metadata`` for autogenerate.
Supports both offline (``--sql``) and online migration modes.
"""

import os
import sys
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

# Ensure the backend/ directory (which contains the ``app`` package) is on the
# path regardless of where alembic is invoked from.
_HERE = os.path.dirname(os.path.abspath(__file__))
_BACKEND = os.path.dirname(_HERE)
if _BACKEND not in sys.path:
    sys.path.insert(0, _BACKEND)

from app.config import settings  # noqa: E402
from app.database import Base  # noqa: E402
from app import models  # noqa: E402,F401  (register mappers on Base.metadata)

config = context.config
config.set_main_option("sqlalchemy.url", settings.DATABASE_URL)

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Emit SQL to stdout without a live DB connection."""
    context.configure(
        url=settings.DATABASE_URL,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=settings.is_sqlite,
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations against a live database connection."""
    section = config.get_section(config.config_ini_section, {})
    section["sqlalchemy.url"] = settings.DATABASE_URL
    connectable = engine_from_config(
        section,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=settings.is_sqlite,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
