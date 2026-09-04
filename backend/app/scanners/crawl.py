"""Attack-surface expansion — endpoint & parameter discovery (deep-vuln-scan P1).

This scanner widens the attack surface *before* the heavier scanners run, so
downstream tools (nuclei, fuzzers, param scanners) have far more to chew on. It
combines active crawling, historical-URL mining, passive JS/endpoint scraping,
and hidden-parameter discovery into a single streamed pass:

    1. katana  — active crawl of the live site (bounded depth), if installed.
    2. gau     — historical URLs from web archives, if installed.
    3. passive — pure-Python fetch of the page + linked .js, regexing out
                 endpoints and obvious leaked secrets. Always runs, so the
                 module is useful even when no external tool is present.
    4. arjun   — hidden-parameter brute force on the most interesting handful
                 of endpoints, if installed.

Every external tool degrades gracefully: if katana / gau / arjun are not on
PATH the stage logs a note and is skipped — the pass always returns a valid
``result`` built from whatever stages did run.

Like every scanner here it is a generator that ``yield``s ``log`` / ``result``
/ ``error`` events (see ``base.py``). It is detection-only: it reads pages and
lists URLs, it never submits data or exploits anything.
"""

import json
import os
import re
import shutil
import site
import subprocess
import sysconfig
import tempfile
import threading
import time
from html.parser import HTMLParser
from typing import Iterator, List, Optional
from urllib.parse import urljoin, urlparse, urlsplit, parse_qs

import requests

from .. import safe_http, sandbox
from .base import clean_target, ensure_url, error, log, reachable, result, stream_command

# ---------------------------------------------------------------------------
# Caps / limits — keep the pass bounded no matter how large the target is.
# ---------------------------------------------------------------------------
KATANA_DEPTH = 3
KATANA_MAX_SECONDS = 240
GAU_CAP = 500
GAU_MAX_SECONDS = 120
JS_FILE_CAP = 12
JS_FETCH_TIMEOUT = 10
PAGE_FETCH_TIMEOUT = 12
URL_CAP = 3000
ARJUN_ENDPOINT_CAP = 5
ARJUN_TIMEOUT_EACH = 90
#: Bounds for the passive, same-origin form / API-endpoint discovery. Keeps the
#: unauthenticated attack surface useful without letting it explode.
FORM_CAP = 25
FORM_INPUT_CAP = 30
API_ENDPOINT_CAP = 50

_UA = {"User-Agent": "Mozilla/5.0 (RedOpsX crawl / attack-surface expander)"}

# Binaries installed by `go install` (katana/gau) and by `pip install` (arjun)
# frequently land in directories that are not on the interpreter's PATH. Probe
# those explicitly in addition to shutil.which so a fresh install is still found.
def _extra_bin_dirs() -> List[str]:
    dirs = [os.path.join(os.path.expanduser("~"), "go", "bin")]
    gopath = os.environ.get("GOPATH")
    if gopath:  # honour a custom GOPATH if set
        dirs.append(os.path.join(gopath, "bin"))
    # pip console-script locations (base + per-user install schemes). On Windows
    # the user scheme adds the PythonXY component (e.g. ...\Roaming\Python\
    # Python313\Scripts) that site.getuserbase() alone omits, so resolve it via
    # sysconfig's user scheme.
    getters = [lambda: sysconfig.get_path("scripts")]
    try:
        user_scheme = sysconfig.get_preferred_scheme("user")
        getters.append(lambda: sysconfig.get_path("scripts", user_scheme))
    except (AttributeError, ValueError):
        getters.append(lambda: os.path.join(site.getuserbase(), "Scripts"))
        getters.append(lambda: os.path.join(site.getuserbase(), "bin"))
    for getter in getters:
        try:
            p = getter()
            if p:
                dirs.append(p)
        except Exception:
            pass
    # Dedupe, keep only existing dirs.
    seen, out = set(), []
    for d in dirs:
        if d and d not in seen and os.path.isdir(d):
            seen.add(d)
            out.append(d)
    return out


_EXTRA_BIN_DIRS = _extra_bin_dirs()

# ---------------------------------------------------------------------------
# Extraction patterns
# ---------------------------------------------------------------------------
# Endpoints referenced from HTML/JS: absolute URLs, quoted root-relative paths,
# and the argument of fetch()/axios.*()/XHR.open().
_RE_ABS_URL = re.compile(r"""https?://[^\s"'`<>()\[\]{}]+""")
_RE_QUOTED_PATH = re.compile(r"""["'`](/[A-Za-z0-9_\-./~]+(?:\?[^"'`\s]*)?)["'`]""")
_RE_CALL_URL = re.compile(
    r"""(?:fetch|axios(?:\.(?:get|post|put|delete|patch|request))?|\.open)\s*\(\s*["'`]([^"'`]+)["'`]""",
    re.IGNORECASE,
)

# Obvious secret shapes. Kept conservative to limit false positives; each hit is
# reported with a type so a human can triage.
_SECRET_PATTERNS = [
    ("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("stripe_secret_key", re.compile(r"\bsk_live_[0-9a-zA-Z]{16,}\b")),
    ("stripe_pub_key", re.compile(r"\bpk_live_[0-9a-zA-Z]{16,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    (
        "generic_secret_assignment",
        re.compile(
            r"""(?i)(?:api[_-]?key|apikey|secret|access[_-]?token|auth[_-]?token|client[_-]?secret|password)"""
            r"""["'`]?\s*[:=]\s*["'`]([A-Za-z0-9\-_./+]{16,})["'`]"""
        ),
    ),
]


def _which(name: str) -> Optional[str]:
    """Locate a binary on PATH or in the Go bin dir (Windows .exe aware)."""
    found = shutil.which(name)
    if found:
        return found
    for d in _EXTRA_BIN_DIRS:
        for ext in ("", ".exe", ".bat", ".cmd"):
            cand = os.path.join(d, name + ext)
            if os.path.isfile(cand):
                return cand
    return None


def _cancelled(cancel: Optional[threading.Event]) -> bool:
    return cancel is not None and cancel.is_set()


def _mask(value: str) -> str:
    """Partially redact a leaked secret so the report is safe to read/share."""
    value = value.strip()
    if len(value) <= 8:
        return value[:2] + "…"
    return f"{value[:4]}…{value[-4:]} (len {len(value)})"


#: Path shapes that mark a URL as an API endpoint (JWT/API + GraphQL scanning).
_API_PATH_RE = re.compile(r"(?:^|/)(?:api|graphql|graphiql|rest|v[0-9]+)(?:/|$)", re.I)


class _FormExtractor(HTMLParser):
    """Collect ``<form>`` action/method/input-names from one HTML page.

    Pure parsing — no script execution, no network. Used for passive,
    non-destructive CSRF-surface discovery on the unauthenticated crawl.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: List[dict] = []
        self._cur: Optional[dict] = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._cur = {"action": a.get("action", ""),
                         "method": (a.get("method") or "GET").strip().upper() or "GET",
                         "inputs": []}
        elif self._cur is not None and tag in ("input", "textarea", "select", "button"):
            name = a.get("name")
            if name:
                self._cur["inputs"].append(name)

    def handle_endtag(self, tag):
        if tag == "form" and self._cur is not None:
            self.forms.append(self._cur)
            self._cur = None


def _extract_forms(html: str, base_url: str, domain: str) -> List[dict]:
    """Same-origin ``{action, method, inputs}`` forms from one HTML page (bounded)."""
    parser = _FormExtractor()
    try:
        parser.feed(html or "")
    except Exception:  # noqa: BLE001 - malformed HTML must never break the crawl
        return []
    out: List[dict] = []
    seen: set = set()
    for f in parser.forms:
        try:
            action = urljoin(base_url, f["action"]) if f["action"] else base_url
        except ValueError:
            continue
        if not action.startswith(("http://", "https://")) or not _same_site(action, domain):
            continue
        key = (action, f["method"])
        if key in seen:
            continue
        seen.add(key)
        out.append({"action": action, "method": f["method"],
                    "inputs": f["inputs"][:FORM_INPUT_CAP]})
        if len(out) >= FORM_CAP:
            break
    return out


def _looks_like_api(url: str) -> bool:
    path = urlsplit(url).path.lower()
    return bool(_API_PATH_RE.search(path)) or path.endswith(".json")


def _api_endpoints_from(norm_urls: List[str], domain: str) -> List[str]:
    """Same-origin API-shaped endpoints drawn from the already-collected URLs."""
    out: List[str] = []
    seen: set = set()
    for u in norm_urls:
        if not _same_site(u, domain) or not _looks_like_api(u):
            continue
        base = u.split("#")[0]
        if base in seen:
            continue
        seen.add(base)
        out.append(base)
        if len(out) >= API_ENDPOINT_CAP:
            break
    return out


def _same_site(url: str, domain: str) -> bool:
    try:
        host = urlparse(url).hostname or ""
    except ValueError:
        return False
    host = host.lower()
    domain = (domain or "").lower()
    return bool(host) and (host == domain or host.endswith("." + domain))


def _collect_from_text(text: str, base_url: str, urls: set, secrets: list, seen_secrets: set,
                       source: str) -> None:
    """Pull endpoints and secrets out of one blob of HTML/JS text."""
    for m in _RE_ABS_URL.finditer(text):
        urls.add(m.group(0).rstrip(".,);\"'"))
    for m in _RE_QUOTED_PATH.finditer(text):
        try:
            urls.add(urljoin(base_url, m.group(1)))
        except ValueError:
            continue
    for m in _RE_CALL_URL.finditer(text):
        ref = m.group(1)
        if ref.startswith(("http://", "https://", "/")):
            try:
                urls.add(urljoin(base_url, ref))
            except ValueError:
                continue
    for label, pat in _SECRET_PATTERNS:
        for m in pat.finditer(text):
            raw = m.group(1) if m.groups() else m.group(0)
            key = (label, raw)
            if key in seen_secrets:
                continue
            seen_secrets.add(key)
            secrets.append({"type": label, "preview": _mask(raw), "source": source})


# ---------------------------------------------------------------------------
# Stage 1 — active crawl (katana)
# ---------------------------------------------------------------------------
def _run_katana(url: str, cancel: Optional[threading.Event], urls: set) -> Iterator[dict]:
    binp = _which("katana")
    if not binp:
        yield log("katana not installed (skipping deep crawl).")
        return
    yield log(f"katana: crawling {url} (depth {KATANA_DEPTH}) ...")
    cmd = [binp, "-u", url, "-jc", "-silent", "-d", str(KATANA_DEPTH), "-kf", "all"]
    found = 0
    for ev in stream_command(cmd, cancel=cancel, merge_stderr=True, max_seconds=KATANA_MAX_SECONDS):
        if ev["type"] == "returncode":
            continue
        if ev["type"] == "error":
            yield ev
            continue
        line = ev.get("data", "")
        if not isinstance(line, str) or line.startswith("$ "):
            continue
        line = line.strip()
        if line.startswith(("http://", "https://")):
            if line not in urls:
                urls.add(line)
                found += 1
        elif line.startswith("[") and ("[INF]" in line or "[WRN]" in line):
            yield log(line)
    yield log(f"katana: found {found} URL(s).")


# ---------------------------------------------------------------------------
# Stage 2 — historical URLs (gau)
# ---------------------------------------------------------------------------
def _run_gau(domain: str, cancel: Optional[threading.Event], urls: set) -> Iterator[dict]:
    binp = _which("gau")
    if not binp:
        yield log("gau not installed (skipping historical URL mining).")
        return
    yield log(f"gau: mining archived URLs for {domain} (cap {GAU_CAP}) ...")
    cmd = [binp, "--subs", domain]
    found = 0
    for ev in stream_command(cmd, cancel=cancel, merge_stderr=True, max_seconds=GAU_MAX_SECONDS):
        if ev["type"] == "returncode":
            continue
        if ev["type"] == "error":
            yield ev
            continue
        line = ev.get("data", "")
        if not isinstance(line, str) or line.startswith("$ "):
            continue
        line = line.strip()
        if line.startswith(("http://", "https://")):
            if line not in urls:
                urls.add(line)
                found += 1
            if found >= GAU_CAP:
                yield log(f"gau: reached cap of {GAU_CAP} URLs — stopping.")
                break
    yield log(f"gau: found {found} URL(s).")


# ---------------------------------------------------------------------------
# Stage 3 — passive fetch + regex (pure Python, always runs)
# ---------------------------------------------------------------------------
def _run_passive(url: str, domain: str, cancel: Optional[threading.Event],
                 urls: set, secrets: list, seen_secrets: set,
                 forms: list) -> Iterator[dict]:
    yield log("passive: fetching page and linked scripts ...")
    session = requests.Session()
    session.headers.update(_UA)
    try:
        resp = safe_http.safe_request("GET", url, session=session,
                                      timeout=PAGE_FETCH_TIMEOUT, allow_redirects=True)
    except requests.RequestException as exc:
        yield log(f"passive: could not fetch {url} ({exc.__class__.__name__}) — continuing.")
        return
    base_url = resp.url
    html = resp.text or ""
    _collect_from_text(html, base_url, urls, secrets, seen_secrets, source=base_url)
    # Same-origin form discovery for the CSRF stage (pure HTML parse, no exec).
    forms.extend(_extract_forms(html, base_url, domain))

    # Discover linked .js files from <script src=...>.
    js_srcs = re.findall(r"""<script[^>]+src=["']([^"']+)["']""", html, flags=re.IGNORECASE)
    js_urls = []
    for src in js_srcs:
        try:
            full = urljoin(base_url, src)
        except ValueError:
            continue
        if full.lower().split("?")[0].endswith(".js") or ".js" in full.lower():
            if full not in js_urls:
                js_urls.append(full)
    js_urls = js_urls[:JS_FILE_CAP]
    yield log(f"passive: page yielded {len(urls)} reference(s); fetching {len(js_urls)} script(s).")

    for jsu in js_urls:
        if _cancelled(cancel):
            return
        try:
            jr = safe_http.safe_request("GET", jsu, session=session,
                                        timeout=JS_FETCH_TIMEOUT, allow_redirects=True)
        except requests.RequestException:
            continue
        if jr.status_code == 200 and jr.text:
            _collect_from_text(jr.text, base_url, urls, secrets, seen_secrets, source=jsu)
    if secrets:
        yield log(f"passive: [WARN] {len(secrets)} possible secret(s) matched in page/JS.")


# ---------------------------------------------------------------------------
# Stage 4 — hidden parameter discovery (arjun)
# ---------------------------------------------------------------------------
def _interesting_endpoints(urls: List[str], domain: str) -> List[str]:
    """Pick a handful of param-less, same-site, dynamic-looking endpoints."""
    scored = []
    for u in urls:
        if not _same_site(u, domain):
            continue
        parts = urlsplit(u)
        if parts.query:  # already parameterized — arjun targets hidden params
            continue
        path = parts.path.lower()
        if path.endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".ico",
                          ".woff", ".woff2", ".ttf", ".map", ".webp", ".mp4", ".pdf")):
            continue
        score = 0
        for kw in ("api", "search", "query", "id", "user", "product", "item",
                   "page", "action", "php", "json", "graphql", "v1", "v2"):
            if kw in path:
                score += 1
        if path.endswith((".php", ".asp", ".aspx", ".jsp", ".do")):
            score += 2
        scored.append((score, u))
    # Highest score first; keep order stable for equal scores.
    scored.sort(key=lambda t: t[0], reverse=True)
    picked, seen = [], set()
    for _, u in scored:
        base = u.split("#")[0]
        if base in seen:
            continue
        seen.add(base)
        picked.append(base)
        if len(picked) >= ARJUN_ENDPOINT_CAP:
            break
    return picked


def _parse_arjun_json(obj, params: set) -> None:
    """Defensively pull discovered param names out of arjun's JSON output."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "params" and isinstance(v, list):
                for p in v:
                    if isinstance(p, str):
                        params.add(p)
                    elif isinstance(p, dict) and isinstance(p.get("name"), str):
                        params.add(p["name"])
            else:
                _parse_arjun_json(v, params)
    elif isinstance(obj, list):
        for item in obj:
            _parse_arjun_json(item, params)


def _run_arjun(endpoints: List[str], cancel: Optional[threading.Event],
               params: set) -> Iterator[dict]:
    binp = _which("arjun")
    if not binp:
        yield log("arjun not installed (skipping hidden-parameter discovery).")
        return
    if not endpoints:
        yield log("arjun: no suitable param-less endpoints to probe.")
        return
    # Fail-closed isolation gate. arjun runs via a direct subprocess.run (it is not
    # routed through base.stream_command), so unlike every other scanner it would
    # otherwise execute on the HOST even under container isolation — a silent
    # non-isolated path. It is not container-wrapped yet, so when the active policy
    # is CONTAINER (everything else is isolated) or UNAVAILABLE (isolation required
    # but absent → other scanners refuse), we SKIP this optional hidden-parameter
    # pass rather than run it unisolated. NONE/PROCESS behaviour is unchanged.
    iso_mode, iso_note = sandbox.effective_isolation()
    if iso_mode in (sandbox.ISOLATION_CONTAINER, sandbox.ISOLATION_UNAVAILABLE):
        yield log(
            f"arjun: skipped — hidden-parameter discovery is not container-isolated "
            f"yet and the active isolation policy ({iso_mode}"
            + (f"; {iso_note}" if iso_note else "")
            + ") forbids host execution."
        )
        return
    yield log(f"arjun: probing {len(endpoints)} endpoint(s) for hidden parameters ...")
    for ep in endpoints:
        if _cancelled(cancel):
            return
        outfd, outpath = tempfile.mkstemp(suffix=".json", prefix="arjun_")
        os.close(outfd)
        cmd = [binp, "-u", ep, "-oJ", outpath, "-t", "10"]
        yield log(f"arjun: {ep}")
        try:
            subprocess.run(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=ARJUN_TIMEOUT_EACH,
                check=False,
                env=sandbox.sandboxed_env(),  # P1-H1: never leak app secrets to arjun
            )
        except subprocess.TimeoutExpired:
            yield log(f"arjun: {ep} timed out after {ARJUN_TIMEOUT_EACH}s — skipping.")
            _safe_unlink(outpath)
            continue
        except (OSError, ValueError) as exc:
            yield log(f"arjun: failed on {ep} ({exc.__class__.__name__}) — skipping.")
            _safe_unlink(outpath)
            continue
        try:
            with open(outpath, "r", encoding="utf-8", errors="replace") as fh:
                data = json.load(fh)
            before = len(params)
            _parse_arjun_json(data, params)
            gained = len(params) - before
            if gained:
                yield log(f"arjun: {ep} → {gained} new param(s).")
        except (OSError, json.JSONDecodeError):
            pass
        finally:
            _safe_unlink(outpath)


def _safe_unlink(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------
def stream(target: str, cancel: Optional[threading.Event] = None, **options) -> Iterator[dict]:
    """Discover endpoints & parameters for ``target`` (a URL or host).

    Yields ``log`` events for progress and exactly one ``result`` event with the
    structured attack-surface. On a fatal input problem it yields ``error``.
    """
    if not (target or "").strip():
        yield error("A target URL or host is required.")
        return

    # Sanitize: reject option-like targets (argument-injection guard) and derive
    # both a fetchable URL and a bare domain. ensure_url / clean_target raise
    # ValueError on a leading-dash token.
    try:
        url = ensure_url(target)
        domain = clean_target(target)
    except ValueError as exc:
        yield error(str(exc))
        return

    yield log(f"Attack-surface expansion for {url} (domain: {domain})")

    # Tool inventory up front so the operator sees what will actually run.
    inventory = {name: bool(_which(name)) for name in ("katana", "gau", "arjun")}
    present = [n for n, ok in inventory.items() if ok] or ["none"]
    yield log("External tools available: " + ", ".join(present)
              + " | pure-Python passive stage always runs.")

    # A quick reachability note (non-fatal — archive/JS data can still be useful).
    try:
        if reachable(url):
            yield log("Target is reachable.")
        else:
            yield log("[WARN] Target did not respond to a probe — active stages may find little.")
    except Exception:
        pass

    urls: set = set()
    secrets: list = []
    seen_secrets: set = set()
    params: set = set()
    forms: list = []

    started = time.monotonic()

    # Stage 1 — katana
    if not _cancelled(cancel):
        yield from _run_katana(url, cancel, urls)
    # Stage 2 — gau
    if not _cancelled(cancel):
        yield from _run_gau(domain, cancel, urls)
    # Stage 3 — passive (always)
    if not _cancelled(cancel):
        yield from _run_passive(url, domain, cancel, urls, secrets, seen_secrets, forms)

    if _cancelled(cancel):
        yield log("[STOPPED] Cancelled — returning partial attack surface.")

    # ---- Normalize / dedupe -------------------------------------------------
    norm_urls = sorted(u for u in urls if isinstance(u, str) and u.startswith(("http://", "https://")))
    if len(norm_urls) > URL_CAP:
        norm_urls = norm_urls[:URL_CAP]

    # Parameterized URLs + query-string param names.
    parameterized = []
    for u in norm_urls:
        q = urlsplit(u).query
        if not q:
            continue
        names = sorted(parse_qs(q, keep_blank_values=True).keys())
        if names:
            parameterized.append({"url": u, "params": names})
            params.update(names)

    # Stage 4 — arjun on the most interesting param-less endpoints.
    if not _cancelled(cancel):
        endpoints = _interesting_endpoints(norm_urls, domain)
        yield from _run_arjun(endpoints, cancel, params)

    params_discovered = sorted(params)

    # Same-origin API endpoints for the JWT/API + GraphQL stage, drawn from the
    # URLs already collected above (no extra fetching).
    api_endpoints = _api_endpoints_from(norm_urls, domain)

    counts = {
        "urls": len(norm_urls),
        "parameterized_urls": len(parameterized),
        "params_discovered": len(params_discovered),
        "forms": len(forms),
        "api_endpoints": len(api_endpoints),
        "js_secrets": len(secrets),
    }
    elapsed = int(time.monotonic() - started)
    yield log(
        f"[OK] Attack surface: {counts['urls']} URLs, "
        f"{counts['parameterized_urls']} parameterized, "
        f"{counts['params_discovered']} params, "
        f"{counts['js_secrets']} secret hit(s) — in {elapsed}s."
    )

    yield result({
        "target": url,
        "domain": domain,
        "tools_used": inventory,
        "urls": norm_urls,
        "parameterized_urls": parameterized,
        "params_discovered": params_discovered,
        "forms": forms,
        "api_endpoints": api_endpoints,
        "js_secrets": secrets,
        "counts": counts,
    })
