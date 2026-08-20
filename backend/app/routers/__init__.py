"""API routers for the RECON-X platform.

Each module exposes an ``APIRouter`` named ``router`` that ``app.main`` mounts
onto the application. Import them here so ``from .routers import auth`` (and the
aggregate ``ROUTERS`` tuple) work cleanly.
"""

from . import (
    assets,
    attack,
    auth,
    billing,
    detection,
    emulation,
    enterprise,
    exploit,
    intel,
    orgs,
    pipeline_ws,
    purple,
    scans,
    sso,
    workspaces,
    ws,
)

# Ordered list of the REST/WebSocket routers main.py includes.
ROUTERS = (
    auth.router,
    orgs.router,
    workspaces.router,
    assets.router,
    scans.router,
    intel.router,
    attack.router,
    emulation.router,
    detection.router,
    purple.router,
    exploit.router,
    billing.router,
    sso.router,
    enterprise.router,
    ws.router,
    pipeline_ws.router,
)

__all__ = [
    "auth",
    "orgs",
    "workspaces",
    "assets",
    "scans",
    "intel",
    "attack",
    "emulation",
    "detection",
    "purple",
    "exploit",
    "billing",
    "sso",
    "enterprise",
    "ws",
    "pipeline_ws",
    "ROUTERS",
]
