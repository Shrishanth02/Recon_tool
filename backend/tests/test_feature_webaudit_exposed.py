"""Web-audit exposed/sensitive-file detection (STEP 3 #3) — read-only, HTTP mocked.

Covers a positive + negative case for every detection family (VCS, secrets,
config, backups, debug endpoints, API docs, directory listings, binaries) and the
false-positive guards the expansion is built around: custom soft-404 pages,
redirects, empty responses, login pages, harmless static files, and weak-signature
matches on HTML. Also asserts the configurable probe cap and that NO secret content
leaks into the finding evidence. Network is fully mocked (``webaudit._get``).
"""

import json

from urllib.parse import urlsplit

from app import crud
from app.scanners import webaudit

BASE = "https://site.test/"


class Resp:
    """Minimal requests.Response stand-in for the sensitive-file probes."""

    def __init__(self, status=200, ctype="text/plain", text="", content=None):
        self.status_code = status
        self.text = text
        self.content = content if content is not None else (text or "").encode()
        self.headers = {"Content-Type": ctype}
        self.reason = "OK"


_NOT_FOUND = Resp(404, "text/html", "<h1>404 Not Found</h1>")


def _router(exposed, baseline=_NOT_FOUND):
    """Route by EXACT path: baseline for the random soft-404 probe, ``exposed``
    entries by exact path, a proper 404 for everything else."""
    def _r(url, **kw):
        path = urlsplit(url).path
        if path.endswith(".notfound"):
            return baseline
        return exposed.get(path, _NOT_FOUND)
    return _r


def _probe(monkeypatch, exposed, baseline=_NOT_FOUND, max_probes=webaudit._MAX_FILE_PROBES):
    monkeypatch.setattr(webaudit, "_get", _router(exposed, baseline))
    findings = []
    list(webaudit._check_sensitive_files(BASE, findings, None, max_probes))
    return findings


def _at(findings, path):
    return [f for f in findings if f["location"].endswith(path)]


# --------------------------------------------------------------------------- #
# Positive: one real exposure per family
# --------------------------------------------------------------------------- #
def test_git_config_exposed(monkeypatch):
    f = _probe(monkeypatch, {"/.git/config": Resp(200, "text/plain",
        '[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = git@x\n')})
    hit = _at(f, "/.git/config")
    assert len(hit) == 1
    assert hit[0]["severity"] == "high" and hit[0]["cwe"] == "CWE-527"
    assert hit[0]["evidence"]["family"] == "vcs"


def test_env_secret_exposed(monkeypatch):
    f = _probe(monkeypatch, {"/.env": Resp(200, "text/plain",
        "DB_PASSWORD=supersecret123\nAPI_KEY=abcdef0123\nSTRIPE_TOKEN=sk_live_x\n")})
    hit = _at(f, "/.env")
    assert len(hit) == 1 and hit[0]["severity"] == "high" and hit[0]["cwe"] == "CWE-538"


def test_private_key_exposed(monkeypatch):
    f = _probe(monkeypatch, {"/.ssh/id_rsa": Resp(200, "text/plain",
        "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk...\n-----END OPENSSH PRIVATE KEY-----\n")})
    assert len(_at(f, "/.ssh/id_rsa")) == 1


def test_sql_backup_exposed(monkeypatch):
    f = _probe(monkeypatch, {"/db_backup.sql": Resp(200, "application/sql",
        "-- MySQL dump 10.13\nCREATE TABLE users (id INT);\nINSERT INTO users VALUES (1);\n")})
    hit = _at(f, "/db_backup.sql")
    assert len(hit) == 1 and hit[0]["severity"] == "high"


def test_phpinfo_debug_endpoint_exposed(monkeypatch):
    # phpinfo() output is legitimately HTML — the strong signature carries it.
    f = _probe(monkeypatch, {"/phpinfo.php": Resp(200, "text/html",
        "<html><head><title>phpinfo()</title></head><body>PHP Version 8.1.2 Zend Engine</body></html>")})
    hit = _at(f, "/phpinfo.php")
    assert len(hit) == 1 and hit[0]["name"].startswith("Exposed debug endpoint")


def test_swagger_apidoc_exposed(monkeypatch):
    f = _probe(monkeypatch, {"/swagger.json": Resp(200, "application/json",
        '{"swagger":"2.0","info":{"title":"x"},"paths":{"/a":{}}}')})
    hit = _at(f, "/swagger.json")
    assert len(hit) == 1 and hit[0]["severity"] == "low"
    assert hit[0]["name"].startswith("Exposed apidoc endpoint")


def test_actuator_env_exposed(monkeypatch):
    f = _probe(monkeypatch, {"/actuator/env": Resp(200, "application/json",
        '{"activeProfiles":["prod"],"propertySources":[{"name":"systemEnvironment"}]}')})
    hit = _at(f, "/actuator/env")
    assert len(hit) == 1 and hit[0]["severity"] == "high"


def test_binary_zip_backup_exposed_by_magic(monkeypatch):
    f = _probe(monkeypatch, {"/backup.zip": Resp(200, "application/zip",
        content=b"PK\x03\x04\x14\x00\x00\x00\x08\x00rest-of-archive")})
    assert len(_at(f, "/backup.zip")) == 1


def test_directory_listing_exposed(monkeypatch):
    f = _probe(monkeypatch, {"/backup/": Resp(200, "text/html",
        '<html><head><title>Index of /backup</title></head><body>'
        '<h1>Index of /backup</h1><a href="?C=N;O=D">Name</a></body></html>')})
    hit = _at(f, "/backup/")
    assert len(hit) == 1 and hit[0]["cwe"] == "CWE-548"
    assert hit[0]["name"].startswith("Directory listing exposed")


# --------------------------------------------------------------------------- #
# Negative / false-positive guards
# --------------------------------------------------------------------------- #
def test_custom_soft404_site_reports_nothing(monkeypatch):
    """A site that returns HTTP 200 + a themed 'not found' page for EVERYTHING
    (including the probe paths) yields no findings."""
    catchall = Resp(200, "text/html",
        "<html><body><h1>Oops</h1> the page you requested was not found here</body></html>")
    monkeypatch.setattr(webaudit, "_get", lambda url, **kw: catchall)
    findings = []
    list(webaudit._check_sensitive_files(BASE, findings, None))
    assert findings == []


def test_soft404_site_still_reports_a_real_distinct_file(monkeypatch):
    """Soft-404 detection must not suppress a genuine file whose content differs
    from the catch-all page."""
    catchall = Resp(200, "text/html", "<h1>Welcome</h1> nothing to see, not found")
    f = _probe(
        monkeypatch,
        {"/.env": Resp(200, "text/plain", "SECRET_KEY=zzz\nDB_HOST=db.internal\n")},
        baseline=catchall,
    )
    assert len(_at(f, "/.env")) == 1


def test_redirect_not_reported(monkeypatch):
    f = _probe(monkeypatch, {"/.env": Resp(302, "text/html", "")})
    assert _at(f, "/.env") == []


def test_login_page_not_reported(monkeypatch):
    """A config path that returns an HTML login page (200) is a wall, not the
    file — the content-type guard rejects it even though 'password' appears."""
    f = _probe(monkeypatch, {"/.git/config": Resp(200, "text/html",
        "<html><form>Username <input> Password <input type=password></form></html>")})
    assert _at(f, "/.git/config") == []


def test_empty_response_not_reported(monkeypatch):
    f = _probe(monkeypatch, {"/.env": Resp(200, "text/plain", "")})
    assert _at(f, "/.env") == []


def test_harmless_static_file_not_reported(monkeypatch):
    """200 text with no matching signature (a normal page served at the path)."""
    f = _probe(monkeypatch, {"/.env": Resp(200, "text/plain",
        "Welcome to our site. This is a friendly readme with no secrets at all.")})
    assert _at(f, "/.env") == []


def test_weak_signature_on_html_not_reported(monkeypatch):
    """The old '=' substring FP: an HTML page containing 'PASSWORD' must NOT be
    reported as an exposed .env — the never-HTML content-type guard blocks it."""
    f = _probe(monkeypatch, {"/.env": Resp(200, "text/html",
        "<html><body>Reset your PASSWORD here: FORM=submit</body></html>")})
    assert _at(f, "/.env") == []


def test_directory_listing_normal_page_not_reported(monkeypatch):
    f = _probe(monkeypatch, {"/uploads/": Resp(200, "text/html",
        "<html><body><h1>Uploads</h1> our gallery app</body></html>")})
    assert _at(f, "/uploads/") == []


def test_binary_wrong_magic_not_reported(monkeypatch):
    """A 200 at /backup.zip that is actually an HTML page (wrong magic) -> skip."""
    f = _probe(monkeypatch, {"/backup.zip": Resp(200, "text/html",
        "<html><body>Not found</body></html>")})
    assert _at(f, "/backup.zip") == []


# --------------------------------------------------------------------------- #
# Limits, evidence safety, helpers, derivation
# --------------------------------------------------------------------------- #
def test_probe_limit_caps_requests(monkeypatch):
    calls = []

    def _get(url, **kw):
        calls.append(urlsplit(url).path)
        return _NOT_FOUND

    monkeypatch.setattr(webaudit, "_get", _get)
    findings = []
    list(webaudit._check_sensitive_files(BASE, findings, None, max_probes=3))
    assert len(calls) == 4        # 1 soft-404 baseline + 3 probes
    assert findings == []


def test_stream_option_limits_sensitive_probes(monkeypatch):
    calls = []

    def _get(url, **kw):
        calls.append(urlsplit(url).path)
        return Resp(404, "text/plain", "x")

    monkeypatch.setattr(webaudit, "_get", _get)
    events = list(webaudit.stream("http://site.test/", max_file_probes=2))
    res = next(e["data"] for e in events if e["type"] == "result")
    assert isinstance(res["findings"], list)
    sens_paths = {p for p, *_ in webaudit._SENSITIVE_PROBES}
    probed = [c for c in calls if c in sens_paths]
    assert len(probed) <= 2


def test_evidence_never_leaks_secret_content(monkeypatch):
    f = _probe(monkeypatch, {"/.env": Resp(200, "text/plain",
        "DB_PASSWORD=TOPSECRETvalue999\nAPI_KEY=leakme_abc\n")})
    hit = _at(f, "/.env")[0]
    blob = json.dumps(hit)
    assert "TOPSECRETvalue999" not in blob and "leakme_abc" not in blob
    # confirmed_by is the matched regex PATTERN, not the file content.
    assert "confirmed_by" in hit["evidence"] and "sample" not in hit["evidence"]


def test_norm_collapses_digits_and_whitespace():
    assert webaudit._norm("Not Found: /abc123   page") == "not found: /abc page"


def test_finding_name_by_family():
    assert webaudit._finding_name("secret", "/.env") == "Exposed sensitive file: /.env"
    assert webaudit._finding_name("debug", "/actuator") == "Exposed debug endpoint: /actuator"
    assert webaudit._finding_name("dirlist", "/backup/") == "Directory listing exposed: /backup/"


def test_derive_webaudit_exposed_file_is_vuln():
    result = {"findings": [{
        "severity": "high", "name": "Exposed sensitive file: /.env",
        "location": "https://site.test/.env", "cwe": "CWE-538",
        "description": "x", "evidence": {"path": "/.env", "family": "secret",
                                         "confirmed_by": r"(?mi)^\s*[A-Z]+="}}]}
    out = crud.derive_findings("webaudit", result)
    assert out and out[0]["kind"] == "vuln" and out[0]["detection_tier"] == "validated"
    assert out[0]["confidence"] == 80 and "CWE-538" in str(out[0]["cwe"])
