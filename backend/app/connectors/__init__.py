"""Detection connectors (Purple-Team P3, BLUE side).

This package is the platform's integration layer to defender SIEM/EDR systems.
Each connector answers one question per emulated ATT&CK technique — "did you
detect it?" — over a common :class:`~app.connectors.base.Connector` interface, so
the correlation engine (:mod:`app.detection`) can score detection coverage
without knowing which backend it's talking to.

Public surface
--------------
* :data:`CONNECTOR_TYPES` — mapping of type slug -> connector class.
* :func:`get_connector` — factory: ``get_connector(ctype, config) -> Connector``.
* :class:`Connector` — the ABC (re-exported for typing/`isinstance`).
* :data:`DEFAULT_MARKER` — the canonical emulation marker header value.

All third-party SIEM clients are imported lazily inside the connectors'
``query_detections`` methods, so importing this package (and therefore the whole
app) never requires ``requests`` or any vendor SDK to be installed.
"""

from __future__ import annotations

from typing import Any

from .base import DEFAULT_MARKER, Connector
from .elastic import ElasticConnector
from .http import HttpConnector
from .mock import MockConnector
from .splunk import SplunkConnector

__all__ = [
    "Connector",
    "DEFAULT_MARKER",
    "CONNECTOR_TYPES",
    "get_connector",
    "MockConnector",
    "HttpConnector",
    "SplunkConnector",
    "ElasticConnector",
]


#: Registry of selectable connector types. Keys are the stable ``ctype`` slugs
#: persisted on :class:`~app.models.DetectionConnector`; values are the classes.
CONNECTOR_TYPES: dict[str, type[Connector]] = {
    MockConnector.ctype: MockConnector,
    HttpConnector.ctype: HttpConnector,
    SplunkConnector.ctype: SplunkConnector,
    ElasticConnector.ctype: ElasticConnector,
}


def get_connector(ctype: str, config: dict[str, Any] | None = None) -> Connector:
    """Instantiate the connector registered under ``ctype`` with ``config``.

    Parameters
    ----------
    ctype:
        A key of :data:`CONNECTOR_TYPES` (``"mock"``, ``"http"``, ``"splunk"``,
        ``"elastic"``).
    config:
        The connector-specific configuration dict (see each connector's module
        docstring). ``None`` is treated as an empty config.

    Raises
    ------
    ValueError
        If ``ctype`` is not a known connector type. (This is a programmer/config
        error surfaced to the router, distinct from a *runtime* SIEM failure,
        which connectors swallow into ``detected=False``.)
    """
    key = (ctype or "").strip().lower()
    cls = CONNECTOR_TYPES.get(key)
    if cls is None:
        known = ", ".join(sorted(CONNECTOR_TYPES)) or "(none)"
        raise ValueError(f"Unknown connector type '{ctype}'. Known types: {known}")
    return cls(config or {})
