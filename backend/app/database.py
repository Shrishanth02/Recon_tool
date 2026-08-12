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
    # SQLite would otherwise refuse cross-thread use of a connection.
    _connect_args = {"check_same_thread": False}

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
    """Create every table for dev/bootstrap use (idempotent).

    Importing ``models`` here (rather than at module top) avoids a circular
    import: ``models`` imports ``Base`` from this module.
    """
    from . import models  # noqa: F401  (registers mappers on Base.metadata)

    Base.metadata.create_all(bind=engine)
