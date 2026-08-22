"""OAST out-of-band collaborator (blind-SSRF confirmation) — service, public
callback route, SSRF integration, tenant isolation, expiration, and gating.

No real network: the SSRF reader is monkeypatched and the callback is driven via
the in-process TestClient. OAST is OFF by default, so tests opt in explicitly.
"""

from datetime import datetime, timedelta, timezone

import app.config as cfg
from app import crud, models, oast
from app.database import SessionLocal
from app.scanners import ssrf

TOK32 = "a" * 32


def _enable(monkeypatch):
    monkeypatch.setattr(cfg.settings, "OAST_ENABLED", True)
    monkeypatch.setattr(cfg.settings, "OAST_BASE_URL", "https://oob.test")


def _ws_id(email):
    db = SessionLocal()
    try:
        _u, _o, ws = crud.create_user_with_org(db, email, "password123")
        db.commit()
        return ws.id
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# Config gating (secure-by-default OFF)
# --------------------------------------------------------------------------- #
def test_available_off_by_default():
    assert oast.available() is False


def test_mint_returns_none_when_unconfigured():
    db = SessionLocal()
    try:
        _u, _o, ws = crud.create_user_with_org(db, "oast-off@example.com", "password123")
        db.commit()
        assert oast.mint_probe(db, ws.id) is None
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# Service: mint / record / correlate / tenant isolation
# --------------------------------------------------------------------------- #
def test_mint_probe_binds_token_and_url(monkeypatch):
    _enable(monkeypatch)
    ws_id = _ws_id("oast-mint@example.com")
    db = SessionLocal()
    try:
        minted = oast.mint_probe(db, ws_id)
        db.commit()
        assert minted and oast.is_valid_token(minted[0])
        assert minted[1] == f"https://oob.test/oast/{minted[0]}"
        row = db.execute(
            models.OastProbe.__table__.select().where(models.OastProbe.token == minted[0])
        ).first()
        assert row is not None
    finally:
        db.close()


def test_record_and_hits_are_tenant_isolated(monkeypatch):
    _enable(monkeypatch)
    ws_a = _ws_id("oast-a@example.com")
    ws_b = _ws_id("oast-b@example.com")
    db = SessionLocal()
    try:
        tok_a = oast.mint_probe(db, ws_a)[0]
        tok_b = oast.mint_probe(db, ws_b)[0]
        db.commit()
        assert oast.record_interaction(db, tok_a, source_ip="1.2.3.4",
                                       method="GET", path=f"/oast/{tok_a}") is True
        db.commit()
        # A sees its own hit ...
        assert oast.hits_for(db, ws_a, [tok_a]) == {tok_a}
        # ... B cannot see A's token even when asking for it (cross-tenant blocked)
        assert oast.hits_for(db, ws_b, [tok_a]) == set()
        # B's own probe had no interaction
        assert oast.hits_for(db, ws_b, [tok_b]) == set()
    finally:
        db.close()


def test_unknown_and_malformed_tokens_ignored(monkeypatch):
    _enable(monkeypatch)
    db = SessionLocal()
    try:
        assert oast.record_interaction(db, "f" * 32) is False   # valid format, unknown
        assert oast.record_interaction(db, "not-hex-token") is False
        assert oast.record_interaction(db, "") is False
    finally:
        db.close()


def test_expired_probe_not_recorded_then_cleaned(monkeypatch):
    _enable(monkeypatch)
    ws_id = _ws_id("oast-exp@example.com")
    db = SessionLocal()
    try:
        tok = oast.mint_probe(db, ws_id)[0]
        db.commit()
        probe = db.execute(
            models.OastProbe.__table__.select().where(models.OastProbe.token == tok)
        ).first()
        db.query(models.OastProbe).filter(models.OastProbe.id == probe.id).update(
            {"expires_at": datetime.now(timezone.utc) - timedelta(minutes=5)}
        )
        db.commit()
        assert oast.record_interaction(db, tok) is False        # expired -> ignored
        assert oast.cleanup(db) >= 1
        db.commit()
        gone = db.execute(
            models.OastProbe.__table__.select().where(models.OastProbe.token == tok)
        ).first()
        assert gone is None
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# Public callback route
# --------------------------------------------------------------------------- #
def test_callback_route_records_and_reflects_nothing(client, monkeypatch):
    _enable(monkeypatch)
    ws_id = _ws_id("oast-route@example.com")
    db = SessionLocal()
    try:
        tok = oast.mint_probe(db, ws_id)[0]
        db.commit()
    finally:
        db.close()

    r = client.post(f"/oast/{tok}", json={"leak": "nothing"})
    assert r.status_code == 200 and r.text == ""     # empty body — reflects nothing

    db = SessionLocal()
    try:
        assert oast.hits_for(db, ws_id, [tok]) == {tok}    # correlated
    finally:
        db.close()


def test_callback_unknown_or_malformed_token_no_leak(client, monkeypatch):
    _enable(monkeypatch)
    assert client.get("/oast/" + "b" * 32).status_code == 200          # valid format, unknown
    assert client.get("/oast/" + "b" * 32).text == ""
    assert client.get("/oast/not-a-real-token").status_code == 200     # malformed
    assert client.get("/oast/not-a-real-token").text == ""


# --------------------------------------------------------------------------- #
# SSRF scanner integration
# --------------------------------------------------------------------------- #
def test_ssrf_plants_oast_probe_and_reports_token(monkeypatch):
    seen = []
    monkeypatch.setattr(ssrf, "_http_get", lambda u: (seen.append(u), (200, "body"))[1])
    probes = [{"token": TOK32, "url": f"https://oob.test/oast/{TOK32}"}]
    events = list(ssrf.stream("https://app.test/fetch?url=http://example", oast_probes=probes))
    res = next(e["data"] for e in events if e["type"] == "result")
    assert res["oast_injected"] == [{"parameter": "url", "token": TOK32}]
    assert any(TOK32 in u for u in seen)             # callback URL (token) was planted
    assert res["findings"][0]["evidence"].get("oast_token") == TOK32


def test_ssrf_without_oast_probes_is_unchanged(monkeypatch):
    monkeypatch.setattr(ssrf, "_http_get", lambda u: (200, "body"))
    events = list(ssrf.stream("https://app.test/fetch?url=http://example"))
    res = next(e["data"] for e in events if e["type"] == "result")
    assert res["oast_injected"] == []
