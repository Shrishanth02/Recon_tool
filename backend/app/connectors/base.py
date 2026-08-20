"""The detection-connector abstraction (Purple-Team P3, BLUE side).

A *connector* is the platform's bridge to a defender's SIEM/EDR. After the SAFE
emulation engine (P2) fires an ATT&CK-mapped technique at an authorized target,
the correlation engine (:mod:`app.detection`) asks a connector, per technique,
"did you detect this?" and records detected/missed. That question — asked of the
defender's own telemetry — is what turns the platform *purple*.

Every concrete connector subclasses :class:`Connector` and implements
:meth:`Connector.query_detections`. The single hard rule of this layer is that a
connector **never raises**: real SIEM queries hit the network and time out, get
401s, or return garbage, and none of that must ever abort a validation run. All
such failures are swallowed and reported as ``detected=False`` with the error in
the ``evidence`` string, so a broken connector degrades to "missed" rather than
crashing the run.
"""

from __future__ import annotations

import abc
from typing import Any


# The header the SAFE emulation engine stamps on every request so a defender can
# attribute the benign traffic. It is re-exported here as the canonical marker
# the correlation engine hands to connectors (see app.detection.MARKER).
DEFAULT_MARKER: str = "X-RECONX-EMULATION"


class Connector(abc.ABC):
    """Abstract base for a SIEM/EDR detection connector.

    Construct with a free-form ``config`` dict (shape is connector-specific;
    documented on each subclass). The one method subclasses must provide is
    :meth:`query_detections`.

    Contract for :meth:`query_detections`:

    * It is given a single emulated ATT&CK ``technique_id``, the ``marker``
      string the emulation stamped on its traffic, an ISO-8601 ``since_iso``
      lower time bound, and the ``target`` that was emulated against.
    * It returns a plain dict ``{"detected": bool, "count": int, "evidence":
      str, "source": str}``.
    * It **must not raise.** Network/parse/auth errors are caught and returned as
      ``detected=False`` with a human-readable ``evidence`` describing the error.
    """

    #: Stable connector type slug (``"mock"``, ``"http"``, ...). Set by subclass.
    ctype: str = "base"

    def __init__(self, config: dict[str, Any] | None = None) -> None:
        self.config: dict[str, Any] = dict(config or {})

    @abc.abstractmethod
    def query_detections(
        self,
        technique_id: str,
        marker: str,
        since_iso: str,
        target: str,
    ) -> dict[str, Any]:
        """Ask the backing SIEM/EDR whether ``technique_id`` was detected.

        Parameters
        ----------
        technique_id:
            The ATT&CK technique id that was emulated (e.g. ``"T1046"``).
        marker:
            The signature/marker header value the emulation stamped on its
            requests (normally :data:`DEFAULT_MARKER`), used to attribute the
            benign traffic in the defender's logs.
        since_iso:
            ISO-8601 timestamp; only detections at/after this time count. Bounds
            the search to the emulation window so stale alerts don't false-positive.
        target:
            The emulated target host/URL (informational — some backends can scope
            the query to it).

        Returns
        -------
        dict
            ``{"detected": bool, "count": int, "evidence": str, "source": str}``.
        """
        raise NotImplementedError

    # --- shared helpers ---------------------------------------------------- #
    def _result(
        self,
        detected: bool,
        count: int = 0,
        evidence: str = "",
        source: str | None = None,
    ) -> dict[str, Any]:
        """Build a well-formed, normalized result dict.

        Centralizes the return shape so every connector (and every error path)
        yields exactly the four contract keys with coerced types.
        """
        return {
            "detected": bool(detected),
            "count": int(count or 0),
            "evidence": str(evidence or ""),
            "source": source or self.ctype,
        }
