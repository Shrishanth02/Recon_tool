"""Backward-compatibility shim for the legacy single-user persistence module.

.. deprecated::
    The original SQLite ``db.py`` has been superseded by the SQLAlchemy-based
    :mod:`app.database`, :mod:`app.models`, and :mod:`app.crud` modules. This
    shim exists only so that any lingering ``from . import db`` imports keep
    working. New code should use ``crud`` (session-aware) directly.

The two pieces of logic worth re-exporting are ``derive_findings`` (pure) and
``save_scan`` (now session-based). ``init_db`` is aliased to ``init_models``.
"""

from .crud import derive_findings, save_scan  # noqa: F401  (re-exported)
from .database import init_models

# Legacy name for table bootstrap.
init_db = init_models

__all__ = ["derive_findings", "save_scan", "init_db", "init_models"]
