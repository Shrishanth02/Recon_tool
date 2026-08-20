"""SQLAlchemy engine, session factory, and FastAPI DB dependency.

Supports both the local default (SQLite) and production (Postgres via psycopg
v3) purely through ``settings.DATABASE_URL`` — no code changes required to
switch. ``check_same_thread`` is disabled for SQLite because the FastAPI
threadpool and the WebSocket event loop touch the same connection pool.
"""

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import settings


class Base(DeclarativeBase):
    """Declarative base for all ORM models (SQLAlchemy 2.0 style)."""


_connect_args: dict = {}
if settings.is_sqlite:
    # SQLite would otherwise refuse cross-thread use of a connection. The busy
    # ``timeout`` lets independent Sessions (each owned by exactly one thread —
    # e.g. the pipeline worker thread's persistence Session and the WebSocket
    # coroutine's Session) briefly wait for each other's write lock instead of
    # failing with "database is locked". Postgres uses MVCC and ignores this.
    _connect_args = {"check_same_thread": False, "timeout": 30}

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=_connect_args,
    pool_pre_ping=True,
    future=True,
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
    class_=Session,
)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that yields a request-scoped SQLAlchemy session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_models() -> None:
    """Bootstrap the schema for local/dev SQLite ONLY (idempotent).

    Importing ``models`` here (rather than at module top) avoids a circular
    import: ``models`` imports ``Base`` from this module.

    P1-H4 — schema-drift guard: ``create_all`` runs only when
    ``settings.db_auto_create`` is true (by default: SQLite only). For Postgres
    the schema is authoritative via Alembic migrations (``alembic upgrade head``,
    run by entrypoint.sh in production and by CI), so create_all is intentionally
    NOT run — otherwise a model added without a parity migration would be silently
    created, hiding the drift that migrations are supposed to catch.
    """
    import logging

    from . import models  # noqa: F401  (registers mappers on Base.metadata)

    log = logging.getLogger("reconx.startup")
    if not settings.db_auto_create:
        log.info(
            "Schema auto-create is OFF (DATABASE_URL=%s); the database schema is "
            "managed by Alembic migrations (`alembic upgrade head`). Not calling "
            "create_all.",
            "postgres" if not settings.is_sqlite else "sqlite",
        )
        return
    Base.metadata.create_all(bind=engine)
