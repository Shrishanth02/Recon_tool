"""Pluggable OAST (out-of-band application security testing) interface.

Confirming BLIND server-side vulnerabilities (blind SSRF, blind RCE, blind SQLi)
requires an attacker-controlled callback the target can reach out to — a
Collaborator / interactsh-style listener. RECON-X does NOT ship one yet, so
:func:`get_provider` returns ``None`` and callers must treat blind cases as
``possible`` (SIGNAL) and NEVER as ``validated``.

The interface exists so an OAST provider can be added later WITHOUT touching any
scanner: implement :class:`OASTProvider` and return an instance from
``get_provider()``. Scanners already branch on ``get_provider() is None``.
"""

from typing import Optional, Protocol, runtime_checkable


@runtime_checkable
class OASTProvider(Protocol):
    """A minimal out-of-band callback provider.

    ``new_canary`` returns ``(url, token)`` — a unique URL to plant in a payload
    and the token used later to check for an interaction. ``polled_hit`` reports
    whether the target contacted that canary (a positive confirmation of a blind
    server-side request).
    """

    def new_canary(self) -> tuple[str, str]:  # pragma: no cover - interface
        ...

    def polled_hit(self, token: str) -> bool:  # pragma: no cover - interface
        ...


# No provider is configured. Wire a real one here (or via a setter) later.
_PROVIDER: Optional[OASTProvider] = None


def get_provider() -> Optional[OASTProvider]:
    """Return the configured OAST provider, or ``None`` when unavailable.

    ``None`` means blind out-of-band confirmation is impossible — callers keep
    such findings at ``possible``/SIGNAL rather than pretending they are proven.
    """
    return _PROVIDER


def available() -> bool:
    return _PROVIDER is not None
