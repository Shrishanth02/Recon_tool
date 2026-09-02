"""Authenticated deep crawler — mapping the attack surface behind the login
(deep-vuln-scan P3).

The unauthenticated crawler (``crawl.py``) can only see the public shell of an
app. The serious application vulnerabilities — IDOR, broken access control,
injection in privileged handlers, mass-assignment — live *behind the login*.
This scanner logs in with a real browser session and then maps everything the
authenticated user can reach.

It drives a headless Chromium via Playwright's **sync** API (the scanner runs in
a worker thread, so a sync driver is fine). Three login methods are supported,
in priority order:

    cookie       — a raw "k=v; k2=v2" cookie string set on the browser context.
    header       — an "Authorization: Bearer …"-style header sent on every
                   request via a route/extra-header hook.
    credentials  — navigate to a login page, fill user/pass, submit, wait.

The big win over a static crawler: **every network request the page makes is
captured** via ``page.on("request")`` — so XHR/fetch/GraphQL/API endpoints that
never appear as an ``<a href>`` are discovered, along with the parameters in
their query strings and request bodies.

Like every scanner here it is a generator that ``yield``s ``log`` / ``result`` /
``error`` events (see ``base.py``). It NEVER crashes: any failure degrades to a
valid (possibly empty) ``result``. If Playwright/Chromium is unavailable it logs
that and returns an empty valid result.

The result mirrors ``crawl.py``'s ``parameterized_urls`` shape so the pipeline's
Injection stage consumes the two crawlers' output identically.
"""

import json
import re
import threading
import time
from typing import Iterator, List, Optional
from urllib.parse import urljoin, urlparse, urlsplit, parse_qs

from .. import netguard
from .base import clean_target, ensure_url, error, log, result

# ---------------------------------------------------------------------------
# Caps / limits — keep the crawl bounded no matter how large the app is.
# ---------------------------------------------------------------------------
MAX_PAGES = 25            # hard cap on distinct pages visited
MAX_DEPTH = 3             # BFS depth from the entry point
WALL_CLOCK_SECONDS = 120  # hard ceiling on the whole crawl
NAV_TIMEOUT_MS = 20000    # per-navigation timeout
SETTLE_MS = 1200          # let XHR/fetch fire after load before scraping
URL_CAP = 3000            # cap on total collected reference URLs
REQ_CAP = 4000            # cap on captured network requests kept
SECRET_CAP = 100          # cap on reported secret hits

_UA = "Mozilla/5.0 (RedOpsX auth-crawl / authenticated attack-surface mapper)"


# --------------------------------------------------------------------------- #
# SSRF navigation guard — every browser request is netguard-checked before it
# leaves. A page on an authorized target CANNOT redirect Chromium to a
# private/loopback/link-local/CGNAT/cloud-metadata endpoint: such a request is
# ABORTED, so the page never loads and its body is never scraped for secrets.
# Split out as pure functions so the security decision is unit-testable without
# a real browser.
# --------------------------------------------------------------------------- #
def _navigation_allowed(url: str) -> "tuple[bool, str]":
    """Return ``(allowed, reason)`` for a browser request destination.

    Non-network schemes (``about:``, ``data:``, ``blob:``) make no egress and are
    allowed. http(s) destinations are resolved + vetted through netguard (which
    blocks private/loopback/link-local/reserved/CGNAT/metadata, incl. IPv4-mapped
    & NAT64 forms). Never raises — a validation error fails CLOSED.
    """
    low = (url or "").strip().lower()
    if not low.startswith(("http://", "https://")):
        return True, "non-network scheme"
    try:
        allowed, reason, _ips = netguard.resolve_and_validate(url)
    except Exception as exc:  # noqa: BLE001 - must never crash the driver; fail closed
        return False, f"validation error: {exc.__class__.__name__}"
    return allowed, reason


def _guard_route(route, blocked: list) -> None:
    """Playwright route handler: abort SSRF-unsafe requests, continue the rest."""
    try:
        url = route.request.url
    except Exception:  # noqa: BLE001
        url = ""
    allowed, reason = _navigation_allowed(url)
    if not allowed:
        try:
            blocked.append({"url": url, "reason": reason})
        except Exception:  # noqa: BLE001
            pass
        try:
            route.abort()
        except Exception:  # noqa: BLE001
            pass
        return
    try:
        route.continue_()
    except Exception:  # noqa: BLE001
        pass

# Default login-form selectors, used when the caller doesn't supply their own.
_DEFAULT_USER_SEL = "input[type=email], input[name*=user i], input[name*=email i], input[id*=user i]"
_DEFAULT_PASS_SEL = "input[type=password]"
_DEFAULT_SUBMIT_SEL = "button[type=submit], input[type=submit], button"

# Static asset extensions we don't bother enqueueing as crawl targets.
_ASSET_EXT = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".ico", ".woff", ".woff2",
    ".ttf", ".otf", ".eot", ".map", ".webp", ".mp4", ".webm", ".pdf", ".zip",
    ".gz", ".mp3", ".avi", ".mov",
)

# Obvious secret shapes (kept conservative; each hit is masked before reporting).
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


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def _cancelled(cancel: Optional[threading.Event]) -> bool:
    return cancel is not None and cancel.is_set()


def _mask(value: str) -> str:
    """Partially redact a leaked secret so the report is safe to read/share."""
    value = (value or "").strip()
    if len(value) <= 8:
        return value[:2] + "…"
    return f"{value[:4]}…{value[-4:]} (len {len(value)})"


def _same_site(url: str, domain: str) -> bool:
    try:
        host = (urlparse(url).hostname or "").lower()
    except ValueError:
        return False
    # ``host`` is a bare hostname (urlparse drops the port), but ``domain`` comes
    # from clean_target and may carry a port for a non-standard-port target
    # ("127.0.0.1:8201", "app.internal:8080"). Comparing the two directly would
    # reject EVERY same-host link on such a target, collapsing the authenticated
    # deep-crawl to a single page — so normalize the domain to a bare hostname too.
    dom = (domain or "").lower()
    dom_host = (urlparse("//" + dom).hostname or dom) if dom else dom
    return bool(host) and bool(dom_host) and (
        host == dom_host or host.endswith("." + dom_host)
    )


def _is_asset(url: str) -> bool:
    path = urlsplit(url).path.lower()
    return path.endswith(_ASSET_EXT)


def _strip_fragment(url: str) -> str:
    return url.split("#", 1)[0]


def _parse_cookie_string(cookie: str, domain: str) -> List[dict]:
    """Turn "k=v; k2=v2" into Playwright cookie dicts scoped to ``domain``."""
    cookies = []
    for part in (cookie or "").split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        name, _, value = part.partition("=")
        name = name.strip()
        if not name:
            continue
        cookies.append({
            "name": name,
            "value": value.strip(),
            "domain": domain,
            "path": "/",
        })
    return cookies


def _parse_header_option(auth_header: str) -> Optional[tuple]:
    """Parse "Header-Name: value" into (name, value)."""
    if not auth_header or ":" not in auth_header:
        return None
    name, _, value = auth_header.partition(":")
    name = name.strip()
    value = value.strip()
    if not name or not value:
        return None
    return name, value


def _collect_secrets(text: str, source: str, secrets: list, seen_secrets: set) -> None:
    if not text or len(secrets) >= SECRET_CAP:
        return
    for label, pat in _SECRET_PATTERNS:
        for m in pat.finditer(text):
            raw = m.group(1) if m.groups() else m.group(0)
            key = (label, raw)
            if key in seen_secrets:
                continue
            seen_secrets.add(key)
            secrets.append({"type": label, "preview": _mask(raw), "source": source})
            if len(secrets) >= SECRET_CAP:
                return


def _params_from_body(body: str) -> List[str]:
    """Pull parameter names out of a request body (JSON object or form-encoded)."""
    if not body:
        return []
    names: set = set()
    body = body.strip()
    # Try JSON first.
    if body[:1] in "{[":
        try:
            obj = json.loads(body)
            if isinstance(obj, dict):
                names.update(str(k) for k in obj.keys())
            elif isinstance(obj, list):
                for item in obj:
                    if isinstance(item, dict):
                        names.update(str(k) for k in item.keys())
            return sorted(names)
        except (ValueError, TypeError):
            pass
    # Fall back to form-encoded (a=1&b=2).
    if "=" in body:
        try:
            names.update(parse_qs(body, keep_blank_values=True).keys())
        except ValueError:
            pass
    return sorted(names)


# ---------------------------------------------------------------------------
# Login-state verification
# ---------------------------------------------------------------------------
def _looks_authenticated(page) -> tuple:
    """Best-effort check that we're past the login wall.

    Returns (authenticated: bool, note: str). We treat the presence of a visible
    password field as "still on a login form" (not authenticated), and the
    presence of a logout/account affordance as a positive signal.
    """
    try:
        # A visible password input strongly implies we're still at a login form.
        pw = page.query_selector("input[type=password]")
        if pw is not None:
            try:
                if pw.is_visible():
                    return False, "a visible password field is present (still at login)"
            except Exception:
                # If visibility can't be determined, fall through to positive signals.
                pass
    except Exception:
        pass

    # Positive signals: a logout / account / dashboard affordance.
    try:
        html = (page.content() or "").lower()
    except Exception:
        html = ""
    for kw in ("logout", "log out", "sign out", "signout", "my account",
               "dashboard", "profile"):
        if kw in html:
            return True, f"found a '{kw}' affordance"

    # No login form and no explicit signal — assume the session is usable but
    # say so honestly.
    return True, "no login form detected (assumed authenticated)"


def _perform_credential_login(page, target_url, options, log_events) -> tuple:
    """Fill and submit a login form. Returns (attempted: bool, note: str).

    Appends log() events to ``log_events``. Never raises.
    """
    login_url = options.get("login_url") or target_url
    username = options.get("username")
    password = options.get("password")
    user_sel = options.get("user_sel") or _DEFAULT_USER_SEL
    pass_sel = options.get("pass_sel") or _DEFAULT_PASS_SEL
    submit_sel = options.get("submit_sel") or _DEFAULT_SUBMIT_SEL

    if not (username and password):
        return False, "no credentials supplied"

    log_events.append(log(f"credentials: navigating to login page {login_url}"))
    try:
        page.goto(login_url, timeout=NAV_TIMEOUT_MS, wait_until="domcontentloaded")
    except Exception as exc:
        log_events.append(log(f"credentials: could not open login page ({exc.__class__.__name__})."))
        return True, "login page navigation failed"

    try:
        page.fill(user_sel, str(username), timeout=8000)
    except Exception as exc:
        log_events.append(log(f"credentials: username field not found via selector ({exc.__class__.__name__})."))
        return True, "username field not found"
    try:
        page.fill(pass_sel, str(password), timeout=8000)
    except Exception as exc:
        log_events.append(log(f"credentials: password field not found via selector ({exc.__class__.__name__})."))
        return True, "password field not found"

    log_events.append(log("credentials: submitting login form ..."))
    try:
        # Submit and wait for the resulting navigation/settle. We race a
        # navigation wait against a short sleep so SPA logins (no full nav) also work.
        try:
            with page.expect_navigation(timeout=NAV_TIMEOUT_MS):
                page.click(submit_sel, timeout=8000)
        except Exception:
            # No navigation (SPA) or click via selector failed — try pressing Enter.
            try:
                page.press(pass_sel, "Enter", timeout=4000)
            except Exception:
                pass
            page.wait_for_timeout(SETTLE_MS)
    except Exception as exc:
        log_events.append(log(f"credentials: submit encountered an issue ({exc.__class__.__name__})."))
    page.wait_for_timeout(SETTLE_MS)
    return True, "login form submitted"


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------
def stream(target: str, cancel: Optional[threading.Event] = None, **options) -> Iterator[dict]:
    """Authenticated deep-crawl of ``target``.

    Yields ``log`` events for progress and exactly one ``result`` event with the
    authenticated attack-surface. On a fatal input problem it yields ``error``.
    Never raises; a runtime failure degrades to a valid (possibly empty) result.
    """
    if not (target or "").strip():
        yield error("A target URL or host is required.")
        return

    # Sanitize: reject option-like targets (argument-injection guard) and derive
    # both a fetchable URL and a bare domain.
    try:
        url = ensure_url(target)
        domain = clean_target(target)
    except ValueError as exc:
        yield error(str(exc))
        return

    # Decide the login method from the supplied options (priority order).
    cookie = options.get("cookie")
    auth_header = options.get("auth_header")
    has_creds = bool(options.get("username") and options.get("password"))
    if cookie:
        login_method = "cookie"
    elif auth_header:
        login_method = "header"
    elif has_creds:
        login_method = "credentials"
    else:
        login_method = "none"

    yield log(f"Authenticated deep-crawl of {url} (domain: {domain})")
    yield log(f"Login method: {login_method}")

    # ---- Import Playwright lazily so its absence is graceful ----------------
    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:
        yield log(f"⚠ Playwright is not available ({exc.__class__.__name__}) — "
                  "returning empty result (install playwright + chromium to enable).")
        yield result(_empty_result(url, domain, login_method))
        return

    # Shared collectors.
    urls: set = set()             # <a href> + captured request URLs (same-site)
    api_endpoints: set = set()    # XHR/fetch/other non-navigation request URLs
    forms: list = []              # {action, method, inputs}
    seen_forms: set = set()
    body_params: set = set()      # param names seen in request bodies
    secrets: list = []
    seen_secrets: set = set()
    endpoints_log: list = []      # workflow model: {url, method, params}
    seen_ep: set = set()
    captured_requests = {"count": 0}

    authenticated = False
    auth_note = "not verified"
    pages_visited = 0
    started = time.monotonic()

    playwright = None
    browser = None
    try:
        playwright = sync_playwright().start()
        try:
            browser = playwright.chromium.launch(headless=True)
        except Exception as exc:
            yield log(f"⚠ Could not launch headless Chromium ({exc.__class__.__name__}) — "
                      "returning empty result (try `playwright install chromium`).")
            yield result(_empty_result(url, domain, login_method))
            return

        context_kwargs = {"user_agent": _UA, "ignore_https_errors": True}
        # Header auth applies to every request in the context.
        header_pair = _parse_header_option(auth_header) if auth_header else None
        if header_pair:
            context_kwargs["extra_http_headers"] = {header_pair[0]: header_pair[1]}
        context = browser.new_context(**context_kwargs)
        context.set_default_navigation_timeout(NAV_TIMEOUT_MS)
        context.set_default_timeout(NAV_TIMEOUT_MS)

        # SSRF guard: netguard-validate EVERY request (initial nav, redirects,
        # subresources, XHR/fetch) BEFORE Chromium connects; abort unsafe ones.
        # Registered on the context so it applies to every page/redirect. Does NOT
        # rely on the initial target validation alone.
        blocked_navigations: list = []
        try:
            context.route("**/*", lambda route: _guard_route(route, blocked_navigations))
        except Exception as exc:  # noqa: BLE001
            yield log(f"⚠ could not install navigation SSRF guard ({exc.__class__.__name__}).")

        # Cookie auth: set the raw cookie string on the target domain.
        if cookie:
            try:
                cookies = _parse_cookie_string(cookie, domain)
                if cookies:
                    context.add_cookies(cookies)
                    yield log(f"cookie: applied {len(cookies)} cookie(s) to {domain}.")
                else:
                    yield log("cookie: no valid name=value pairs parsed from cookie string.")
            except Exception as exc:
                yield log(f"cookie: failed to apply cookies ({exc.__class__.__name__}).")

        page = context.new_page()

        # ---- Network capture: the key win over a static crawler ------------
        def _on_request(request):
            try:
                if captured_requests["count"] >= REQ_CAP:
                    return
                req_url = request.url
                if not req_url.startswith(("http://", "https://")):
                    return
                if not _same_site(req_url, domain):
                    return
                captured_requests["count"] += 1
                urls.add(req_url)
                rtype = ""
                try:
                    rtype = request.resource_type or ""
                except Exception:
                    rtype = ""
                # Non-navigation, non-asset requests are the interesting API calls.
                if rtype in ("xhr", "fetch") or (
                    rtype not in ("document", "image", "media", "font", "stylesheet")
                    and not _is_asset(req_url)
                ):
                    if not _is_asset(req_url):
                        api_endpoints.add(req_url)
                # Body params (POST/PUT/PATCH).
                try:
                    if request.method in ("POST", "PUT", "PATCH"):
                        post = request.post_data
                        if post:
                            for name in _params_from_body(post):
                                body_params.add(name)
                except Exception:
                    pass
                # Workflow node: method + url + params (names only — never values).
                try:
                    rmethod = (request.method or "GET").upper()
                    qnames = list(parse_qs(urlsplit(req_url).query).keys())
                    bnames = []
                    if rmethod in ("POST", "PUT", "PATCH"):
                        post = request.post_data
                        if post:
                            bnames = _params_from_body(post)
                    params = sorted(set(qnames) | set(bnames))
                    ekey = (rmethod, urlsplit(req_url).path, tuple(params))
                    if ekey not in seen_ep and len(endpoints_log) < 300:
                        seen_ep.add(ekey)
                        endpoints_log.append({"url": req_url, "method": rmethod, "params": params})
                except Exception:
                    pass
            except Exception:
                # Capture handlers must never raise into the driver.
                pass

        try:
            page.on("request", _on_request)
        except Exception:
            pass

        # ---- Authenticate --------------------------------------------------
        login_log: list = []
        if login_method == "credentials":
            _perform_credential_login(page, url, options, login_log)
            for ev in login_log:
                yield ev
        else:
            # cookie / header / none: just load the entry point.
            try:
                page.goto(url, timeout=NAV_TIMEOUT_MS, wait_until="domcontentloaded")
                page.wait_for_timeout(SETTLE_MS)
            except Exception as exc:
                yield log(f"⚠ Could not open entry point ({exc.__class__.__name__}) — "
                          "continuing with whatever loaded.")

        # ---- Verify auth ---------------------------------------------------
        if login_method == "none":
            authenticated = False
            auth_note = "no auth supplied (unauthenticated crawl)"
            yield log("No auth supplied — crawling unauthenticated.")
        else:
            try:
                authenticated, auth_note = _looks_authenticated(page)
            except Exception:
                authenticated, auth_note = False, "verification error"
            state = "authenticated" if authenticated else "NOT authenticated"
            yield log(f"Auth check: {state} — {auth_note}")

        # ---- BFS crawl -----------------------------------------------------
        try:
            entry = _strip_fragment(page.url or url)
        except Exception:
            entry = url
        queue: List[tuple] = [(entry, 0)]
        enqueued = {entry}

        while queue:
            if _cancelled(cancel):
                yield log("⏹ Cancelled — returning partial attack surface.")
                break
            if pages_visited >= MAX_PAGES:
                yield log(f"Reached page cap ({MAX_PAGES}) — stopping crawl.")
                break
            if (time.monotonic() - started) > WALL_CLOCK_SECONDS:
                yield log(f"⏱ Reached the {WALL_CLOCK_SECONDS}s wall-clock cap — stopping crawl.")
                break

            current, depth = queue.pop(0)
            # We may already have loaded the entry page during login; still
            # re-visit to scrape links/forms consistently.
            try:
                page.goto(current, timeout=NAV_TIMEOUT_MS, wait_until="domcontentloaded")
                page.wait_for_timeout(SETTLE_MS)
            except Exception as exc:
                yield log(f"crawl: skip {current} ({exc.__class__.__name__}).")
                continue
            pages_visited += 1
            urls.add(current)

            # Scrape page content for secrets.
            try:
                content = page.content() or ""
            except Exception:
                content = ""
            _collect_secrets(content, current, secrets, seen_secrets)

            # Extract <a href> links.
            hrefs: List[str] = []
            try:
                hrefs = page.eval_on_selector_all(
                    "a[href]", "els => els.map(e => e.href)"
                ) or []
            except Exception:
                hrefs = []

            # Extract forms.
            try:
                page_forms = page.eval_on_selector_all(
                    "form",
                    """els => els.map(f => ({
                        action: f.action || '',
                        method: (f.method || 'get'),
                        inputs: Array.from(f.querySelectorAll('input,select,textarea'))
                                     .map(i => i.name || i.id || '')
                                     .filter(n => n)
                    }))""",
                ) or []
            except Exception:
                page_forms = []
            for f in page_forms:
                try:
                    action = urljoin(current, f.get("action") or current)
                    method = (f.get("method") or "get").upper()
                    inputs = [i for i in (f.get("inputs") or []) if i]
                    fkey = (action, method, tuple(sorted(inputs)))
                    if fkey in seen_forms:
                        continue
                    seen_forms.add(fkey)
                    forms.append({"action": action, "method": method, "inputs": inputs})
                except Exception:
                    continue

            # Enqueue same-site links.
            if depth < MAX_DEPTH:
                for h in hrefs:
                    if not isinstance(h, str):
                        continue
                    h = _strip_fragment(h)
                    if not h.startswith(("http://", "https://")):
                        continue
                    urls.add(h)
                    if not _same_site(h, domain) or _is_asset(h):
                        continue
                    if h in enqueued:
                        continue
                    if len(enqueued) >= URL_CAP:
                        continue
                    enqueued.add(h)
                    queue.append((h, depth + 1))

        yield log(f"Crawled {pages_visited} page(s); captured "
                  f"{captured_requests['count']} network request(s).")

    except Exception as exc:
        # Absolute backstop — never let the scanner crash the run.
        yield log(f"⚠ Auth-crawl encountered an error ({exc.__class__.__name__}: {exc}); "
                  "returning what was collected.")
    finally:
        try:
            if browser is not None:
                browser.close()
        except Exception:
            pass
        try:
            if playwright is not None:
                playwright.stop()
        except Exception:
            pass

    # ---- Normalize / build the result --------------------------------------
    norm_urls = sorted(
        u for u in urls
        if isinstance(u, str) and u.startswith(("http://", "https://"))
    )
    if len(norm_urls) > URL_CAP:
        norm_urls = norm_urls[:URL_CAP]

    # Parameterized URLs + query-string param names — same shape as crawl.py.
    parameterized = []
    params: set = set(body_params)
    for u in norm_urls:
        q = urlsplit(u).query
        if not q:
            continue
        names = sorted(parse_qs(q, keep_blank_values=True).keys())
        if names:
            parameterized.append({"url": u, "params": names})
            params.update(names)

    api_list = sorted(api_endpoints)
    params_discovered = sorted(params)

    counts = {
        "urls": len(norm_urls),
        "parameterized_urls": len(parameterized),
        "forms": len(forms),
        "api_endpoints": len(api_list),
        "params_discovered": len(params_discovered),
        "js_secrets": len(secrets),
        "pages_visited": pages_visited,
        "requests_captured": captured_requests["count"],
    }
    elapsed = int(time.monotonic() - started)
    yield log(
        f"✔ Authenticated attack surface: {counts['urls']} URLs, "
        f"{counts['parameterized_urls']} parameterized, {counts['forms']} form(s), "
        f"{counts['api_endpoints']} API endpoint(s), "
        f"{counts['params_discovered']} params, {counts['js_secrets']} secret hit(s) "
        f"— in {elapsed}s."
    )

    if blocked_navigations:
        yield log(
            f"⚠ SSRF guard aborted {len(blocked_navigations)} request(s) to "
            "private/metadata destination(s) — never contacted, never scraped."
        )

    yield result({
        "target": url,
        "domain": domain,
        "ssrf_blocked": len(blocked_navigations),
        "authenticated": authenticated,
        "login_method": login_method,
        "auth_note": auth_note,
        "urls": norm_urls,
        "parameterized_urls": parameterized,
        "forms": forms,
        "api_endpoints": api_list,
        # Workflow model for the business-logic foundation: each captured request
        # as {url, method, params, authenticated} — param NAMES only, no values.
        "endpoints": [{**e, "authenticated": authenticated} for e in endpoints_log],
        "params_discovered": params_discovered,
        "js_secrets": secrets,
        "counts": counts,
    })


def _empty_result(url: str, domain: str, login_method: str) -> dict:
    """A valid, empty result for graceful-degradation paths."""
    return {
        "target": url,
        "domain": domain,
        "authenticated": False,
        "login_method": login_method,
        "auth_note": "playwright/chromium unavailable",
        "urls": [],
        "parameterized_urls": [],
        "forms": [],
        "api_endpoints": [],
        "endpoints": [],
        "params_discovered": [],
        "js_secrets": [],
        "counts": {
            "urls": 0,
            "parameterized_urls": 0,
            "forms": 0,
            "api_endpoints": 0,
            "params_discovered": 0,
            "js_secrets": 0,
            "pages_visited": 0,
            "requests_captured": 0,
        },
    }
