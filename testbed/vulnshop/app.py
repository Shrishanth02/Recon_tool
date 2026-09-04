"""
VulnShop — an INTENTIONALLY VULNERABLE e-commerce web app.

Purpose: a local, dynamic (SQLite-backed) target so the RECON-X scanners have
concrete things to find. Every weakness marked "VULN:" below is deliberate.

⚠️  LOCAL / ISOLATED TESTING ONLY. Never expose this to a public network.
See README.md for the full vulnerability -> scanner map.
"""

import base64
import hashlib
import hmac
import json as _json
import os
import sqlite3
import urllib.error
import urllib.request
from datetime import datetime, timezone

from flask import (
    Flask,
    Response,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "vulnshop.db")
UPLOADS_DIR = os.path.join(BASE_DIR, "static", "uploads")

app = Flask(__name__)
# VULN: hard-coded, weak, committed secret key.
app.secret_key = "sup3r-s3cr3t-flask-key-please-change-me"

STORE = {
    "name": "VoltMart",
    "tagline": "Gadgets, gear & good deals",
}

# --------------------------------------------------------------------------- #
# Database
# --------------------------------------------------------------------------- #
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def _close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


PRODUCTS_SEED = [
    # name, category, price, stock, emoji, badge, description, image
    ("Aurora Wireless Earbuds", "Audio", 79.99, 42, "🎧", "Bestseller",
     "Active noise cancelling earbuds with 30-hour battery and USB-C fast charge.", "earbuds"),
    ("Nimbus Mechanical Keyboard", "Accessories", 119.00, 18, "⌨️", "New",
     "Hot-swappable 75% mechanical keyboard with per-key RGB and gasket mount.", "keyboard"),
    ("Solaris 27\" 4K Monitor", "Displays", 329.50, 9, "🖥️", "",
     "27-inch 4K IPS display, 144Hz, HDR400, USB-C 90W power delivery.", "monitor"),
    ("Pulse Smartwatch S3", "Wearables", 199.99, 25, "⌚", "Deal",
     "AMOLED smartwatch with GPS, SpO2, and 7-day battery life.", "smartwatch"),
    ("Vertex Gaming Mouse", "Accessories", 49.99, 60, "🖱️", "",
     "26K DPI optical sensor, 60g lightweight shell, 8 programmable buttons.", "mouse"),
    ("Photon 4K Action Camera", "Cameras", 249.00, 14, "📷", "",
     "Waterproof 4K/120fps action cam with hypersmooth stabilization.", "camera"),
    ("Titan Power Bank 20K", "Power", 39.99, 80, "🔋", "",
     "20,000mAh power bank, 65W USB-C PD, charges a laptop and two phones.", "powerbank"),
    ("Orbit Bluetooth Speaker", "Audio", 89.99, 33, "🔊", "",
     "360° room-filling sound, IPX7 waterproof, 24-hour playtime.", "speaker"),
    ("Nova Ultrabook 14", "Computers", 999.00, 6, "💻", "Premium",
     "14-inch ultrabook, 16GB RAM, 1TB SSD, all-day battery, 1.1kg.", "laptop"),
    ("Glide Wireless Charger", "Power", 29.99, 120, "🔌", "",
     "15W Qi2 magnetic wireless charger with cooling fan and stand.", "charger"),
    ("Echo Studio Microphone", "Audio", 139.00, 21, "🎙️", "",
     "USB condenser microphone with cardioid pickup and zero-latency monitoring.", "microphone"),
    ("Pixel Game Controller", "Gaming", 59.99, 47, "🎮", "",
     "Low-latency wireless controller with hall-effect sticks and back paddles.", "controller"),
]

USERS_SEED = [
    # username, password (VULN: plaintext), email, is_admin
    ("admin", "admin123", "admin@voltmart.test", 1),
    ("alice", "password1", "alice@example.test", 0),
    ("bob", "hunter2", "bob@example.test", 0),
]

ORDERS_SEED = [
    # user_id, product_id, qty, total, customer_name, address
    (2, 1, 1, 79.99, "Alice Nguyen", "12 Maple St, Springfield"),
    (3, 9, 1, 999.00, "Bob Carter", "7 Oak Ave, Rivertown"),
    (2, 7, 2, 79.98, "Alice Nguyen", "12 Maple St, Springfield"),
]


def init_db():
    """Create the schema, and seed whenever the products table is empty.

    Seeding on emptiness (rather than on a missing file) is robust against the
    debug reloader's two processes and against a half-created database.
    """
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS products(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT, category TEXT, price REAL, stock INTEGER,
            emoji TEXT, badge TEXT, description TEXT, image TEXT
        );
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT, password TEXT, email TEXT, is_admin INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS orders(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER, product_id INTEGER, qty INTEGER, total REAL,
            customer_name TEXT, address TEXT, created_at TEXT
        );
        """
    )
    empty = db.execute("SELECT COUNT(*) FROM products").fetchone()[0] == 0
    if empty:
        db.executemany(
            "INSERT INTO products(name,category,price,stock,emoji,badge,description,image)"
            " VALUES (?,?,?,?,?,?,?,?)",
            PRODUCTS_SEED,
        )
        db.executemany(
            "INSERT INTO users(username,password,email,is_admin) VALUES (?,?,?,?)",
            USERS_SEED,
        )
        now = datetime.now(timezone.utc).isoformat()
        db.executemany(
            "INSERT INTO orders(user_id,product_id,qty,total,customer_name,address,created_at)"
            " VALUES (?,?,?,?,?,?,'" + now + "')",
            ORDERS_SEED,
        )
    db.commit()
    db.close()


def categories():
    db = get_db()
    rows = db.execute("SELECT DISTINCT category FROM products ORDER BY category").fetchall()
    return [r["category"] for r in rows]


def cart_count():
    return sum((session.get("cart") or {}).values())


@app.context_processor
def inject_globals():
    return {"store": STORE, "cart_count": cart_count(), "categories": categories(),
            "current_user": session.get("username")}


# --------------------------------------------------------------------------- #
# VULN: deliberately-insecure response headers on every response
# --------------------------------------------------------------------------- #
@app.after_request
def insecure_headers(resp):
    # VULN: spoof an outdated PHP stack so version-based scanners bite. The
    # Server banner (Apache/2.4.7) is spoofed at the WSGI layer in __main__ so
    # only one Server header is emitted.
    resp.headers["X-Powered-By"] = "PHP/5.6.40"
    # VULN: intentionally NOT setting Content-Security-Policy, X-Frame-Options,
    # Strict-Transport-Security, X-Content-Type-Options, Referrer-Policy, etc.
    return resp


# --------------------------------------------------------------------------- #
# Storefront
# --------------------------------------------------------------------------- #
@app.route("/")
def index():
    db = get_db()
    cat = request.args.get("category")
    if cat:
        products = db.execute(
            "SELECT * FROM products WHERE category=? ORDER BY id", (cat,)
        ).fetchall()
    else:
        products = db.execute("SELECT * FROM products ORDER BY id").fetchall()
    return render_template("index.html", products=products, active_cat=cat)


@app.route("/product/<int:pid>")
def product(pid):
    db = get_db()
    p = db.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
    if not p:
        return render_template("404.html"), 404
    related = db.execute(
        "SELECT * FROM products WHERE category=? AND id<>? LIMIT 4",
        (p["category"], pid),
    ).fetchall()
    return render_template("product.html", p=p, related=related)


@app.route("/search")
def search():
    q = request.args.get("q", "")
    db = get_db()
    rows, sql_error = [], None
    # VULN: SQL injection — the query is built by string interpolation.
    #   try:  /search?q=' OR '1'='1
    #         /search?q=' UNION SELECT username,password,email,4,5,6,7 FROM users--
    sql = (
        "SELECT * FROM products WHERE name LIKE '%" + q + "%' "
        "OR description LIKE '%" + q + "%'"
    )
    try:
        rows = db.execute(sql).fetchall()
    except Exception as exc:  # noqa: BLE001 — surface the DB error (info leak, on purpose)
        sql_error = str(exc)
    # VULN: reflected XSS — `q` is rendered unescaped in the template.
    return render_template("search.html", products=rows, q=q, sql_error=sql_error)


# --------------------------------------------------------------------------- #
# Cart & checkout
# --------------------------------------------------------------------------- #
@app.route("/cart")
def cart():
    db = get_db()
    cart = session.get("cart") or {}
    items, total = [], 0.0
    for pid, qty in cart.items():
        p = db.execute("SELECT * FROM products WHERE id=?", (int(pid),)).fetchone()
        if p:
            line = p["price"] * qty
            total += line
            items.append({"p": p, "qty": qty, "line": round(line, 2)})
    return render_template("cart.html", items=items, total=round(total, 2))


@app.route("/cart/add/<int:pid>", methods=["POST", "GET"])
def cart_add(pid):
    cart = session.get("cart") or {}
    cart[str(pid)] = cart.get(str(pid), 0) + int(request.values.get("qty", 1))
    session["cart"] = cart
    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return jsonify({"ok": True, "count": cart_count()})
    return redirect(request.referrer or url_for("index"))


@app.route("/cart/remove/<int:pid>", methods=["POST", "GET"])
def cart_remove(pid):
    cart = session.get("cart") or {}
    cart.pop(str(pid), None)
    session["cart"] = cart
    return redirect(url_for("cart"))


@app.route("/checkout", methods=["GET", "POST"])
def checkout():
    db = get_db()
    cart = session.get("cart") or {}
    if not cart:
        return redirect(url_for("index"))
    if request.method == "POST":
        name = request.form.get("name", "Guest")
        address = request.form.get("address", "")
        uid = session.get("uid")
        now = datetime.now(timezone.utc).isoformat()
        last_id = None
        for pid, qty in cart.items():
            p = db.execute("SELECT * FROM products WHERE id=?", (int(pid),)).fetchone()
            if not p:
                continue
            cur = db.execute(
                "INSERT INTO orders(user_id,product_id,qty,total,customer_name,address,created_at)"
                " VALUES (?,?,?,?,?,?,?)",
                (uid, p["id"], qty, round(p["price"] * qty, 2), name, address, now),
            )
            last_id = cur.lastrowid
        db.commit()
        session["cart"] = {}
        return redirect(url_for("order_detail", oid=last_id))
    # summary
    items, total = [], 0.0
    for pid, qty in cart.items():
        p = db.execute("SELECT * FROM products WHERE id=?", (int(pid),)).fetchone()
        if p:
            total += p["price"] * qty
            items.append({"p": p, "qty": qty})
    return render_template("checkout.html", items=items, total=round(total, 2))


@app.route("/order/<int:oid>")
def order_detail(oid):
    db = get_db()
    # VULN: IDOR — any order id is viewable, no ownership/authorization check.
    o = db.execute(
        "SELECT o.*, p.name AS product_name, p.emoji AS emoji "
        "FROM orders o LEFT JOIN products p ON p.id=o.product_id WHERE o.id=?",
        (oid,),
    ).fetchone()
    if not o:
        return render_template("404.html"), 404
    return render_template("order.html", o=o)


# --------------------------------------------------------------------------- #
# Auth & account
# --------------------------------------------------------------------------- #
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    nxt = request.values.get("next", "/")
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        db = get_db()
        # VULN: SQL injection in authentication — try  admin' --  as username.
        sql = "SELECT * FROM users WHERE username='%s' AND password='%s'" % (u, p)
        try:
            row = db.execute(sql).fetchone()
        except Exception:
            row = None
        if row:
            session["uid"] = row["id"]
            session["username"] = row["username"]
            session["is_admin"] = bool(row["is_admin"])
            return redirect(nxt or url_for("index"))
        error = "Invalid credentials."
    return render_template("login.html", error=error, next=nxt)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/account")
def account():
    if not session.get("uid"):
        return redirect(url_for("login", next="/account"))
    db = get_db()
    orders = db.execute(
        "SELECT o.*, p.name AS product_name FROM orders o "
        "LEFT JOIN products p ON p.id=o.product_id WHERE o.user_id=? ORDER BY o.id DESC",
        (session["uid"],),
    ).fetchall()
    return render_template("account.html", orders=orders)


@app.route("/admin")
def admin():
    db = get_db()
    # VULN: exposed admin panel. Even unauthenticated, it returns 200 with an
    # obvious admin login (scanners flag the panel); once "logged in" it dumps
    # every user (including plaintext passwords) and every order.
    if not session.get("is_admin"):
        return render_template("admin.html", authed=False, users=[], orders=[])
    users = db.execute("SELECT * FROM users").fetchall()
    orders = db.execute(
        "SELECT o.*, p.name AS product_name FROM orders o "
        "LEFT JOIN products p ON p.id=o.product_id ORDER BY o.id DESC"
    ).fetchall()
    return render_template("admin.html", authed=True, users=users, orders=orders)


# --------------------------------------------------------------------------- #
# JSON API
# --------------------------------------------------------------------------- #
@app.route("/api/products")
def api_products():
    db = get_db()
    rows = db.execute("SELECT * FROM products ORDER BY id").fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/swagger.json")
@app.route("/api-docs")
def swagger():
    # VULN: exposed API documentation.
    return jsonify({
        "openapi": "3.0.0",
        "info": {"title": "VoltMart Internal API", "version": "1.0.0"},
        "paths": {
            "/api/products": {"get": {"summary": "List products"}},
            "/api/users": {"get": {"summary": "List users (admin token required)"}},
            "/api/orders": {"get": {"summary": "List orders"}},
        },
    })


# --------------------------------------------------------------------------- #
# VULN: application-logic lab (planted for scanner validation)
#   JWT weaknesses, SSRF, open redirect, discoverable params, and a
#   broken-access-control (role-differential) endpoint. All deliberate.
# --------------------------------------------------------------------------- #
def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _make_jwt(header: dict, payload: dict, secret):
    h = _b64url(_json.dumps(header, separators=(",", ":")).encode())
    p = _b64url(_json.dumps(payload, separators=(",", ":")).encode())
    if secret is None:  # VULN: alg:none -> unsigned token
        return f"{h}.{p}."
    sig = hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url(sig)}"


@app.route("/api/token")
def api_token():
    # VULN: HS256 signed with the trivial secret 'secret'; no exp; a sensitive
    # claim ('password') sits in the (base64, non-encrypted) payload.
    token = _make_jwt(
        {"alg": "HS256", "typ": "JWT"},
        {"sub": "alice", "role": "user", "password": "password1"},
        "secret",
    )
    return jsonify({"token": token})


@app.route("/api/token/none")
def api_token_none():
    # VULN: server issues an UNSIGNED (alg:none) token, no exp, admin claim.
    token = _make_jwt(
        {"alg": "none", "typ": "JWT"},
        {"sub": "admin", "role": "admin", "admin": True},
        None,
    )
    return jsonify({"token": token})


@app.route("/fetch")
def fetch_url():
    # VULN: SSRF — the server fetches an arbitrary user-supplied URL and reflects
    # the response body straight back to the caller.
    url = request.args.get("url", "")
    if not url:
        return _text("Provide ?url=<target> to fetch.")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "VoltMart-Fetcher"})
        with urllib.request.urlopen(req, timeout=5) as r:  # noqa: S310 - intentional SSRF
            body = r.read(200000).decode("utf-8", "replace")
    except (urllib.error.URLError, ValueError, OSError) as exc:
        body = f"fetch error: {exc}"
    return _text(body)


@app.route("/go")
def go_redirect():
    # VULN: open redirect (CWE-601) — 'next' (or 'url') is passed straight to
    # redirect() with no allow-list / same-origin check. 'url' is referenced
    # nowhere on the site (a hidden param — needs active discovery to find).
    nxt = request.args.get("next") or request.args.get("url") or "/"
    return redirect(nxt)


@app.route("/promo/redirect")
def promo_redirect():
    # VULN: open redirect reachable via a LINKED 'next' param (discoverable by
    # passive crawling / parameter discovery).
    return redirect(request.args.get("next") or "/")


@app.route("/lab")
def lab():
    # A crawlable page that links a parameterized endpoint (so parameter
    # discovery has something to extract) and references it again from JS. It also
    # links /api/lookup with NO parameter — the endpoint honours a HIDDEN 'debug'
    # param referenced nowhere, so only active brute-forcing (arjun) finds it.
    return Response(
        "<!doctype html><html><body><h1>Promotions</h1>"
        "<a href='/promo/redirect?next=/account'>Continue to your account</a>"
        "<a href='/api/lookup'>Lookup</a>"
        "<script>var promo = '/promo/redirect?next=/deals';</script>"
        "</body></html>",
        mimetype="text/html",
    )


@app.route("/api/lookup")
def api_lookup():
    # Discoverable endpoint that honours a HIDDEN 'debug' query param (referenced
    # nowhere on the site) and reflects it — so hidden-parameter brute force
    # (arjun) can discover 'debug' via the response differential.
    debug = request.args.get("debug")
    if debug is not None:
        return jsonify({"ok": True, "debug_echo": debug, "trace": "enabled"})
    return jsonify({"ok": True})


@app.route("/admin/users.json")
def admin_users_json():
    # VULN: broken access control (role-differential / missing function-level
    # authorization). Looks admin-only and DENIES anonymous callers, but returns
    # the full user table to ANY logged-in user — no is_admin check.
    if not session.get("uid"):
        return redirect(url_for("login", next="/admin/users.json"))
    db = get_db()
    users = db.execute("SELECT id, username, email, is_admin FROM users").fetchall()
    return jsonify([dict(u) for u in users])


# --------------------------------------------------------------------------- #
# VULN: exposed sensitive files / endpoints
# --------------------------------------------------------------------------- #
DOTENV = (
    "APP_ENV=production\n"
    "APP_DEBUG=true\n"
    "APP_KEY=base64:R4nD0mLyG3n3r4t3dK3yTh4tSh0uldNotL3ak==\n"
    "DB_CONNECTION=mysql\n"
    "DB_HOST=127.0.0.1\n"
    "DB_PORT=3306\n"
    "DB_DATABASE=voltmart\n"
    "DB_USERNAME=voltmart_app\n"
    "DB_PASSWORD=Sup3rS3cr3tDbP4ss!\n"
    "STRIPE_SECRET=sk_live_51Hxxx_fake_do_not_use\n"
    "JWT_SECRET=an0th3r-l3ak3d-s3cr3t\n"
)

GIT_CONFIG = (
    "[core]\n"
    "\trepositoryformatversion = 0\n"
    "\tfilemode = false\n"
    "\tbare = false\n"
    "[remote \"origin\"]\n"
    "\turl = https://github.com/voltmart/shop.git\n"
    "\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
    "[user]\n"
    "\temail = devops@voltmart.test\n"
)

SQL_DUMP = (
    "-- VoltMart database backup (INTENTIONALLY EXPOSED)\n"
    "-- generated by nightly cron\n\n"
    "INSERT INTO users VALUES (1,'admin','admin123','admin@voltmart.test',1);\n"
    "INSERT INTO users VALUES (2,'alice','password1','alice@example.test',0);\n"
    "INSERT INTO users VALUES (3,'bob','hunter2','bob@example.test',0);\n"
)

CONFIG_BAK = (
    "<?php\n"
    "// backup of config.php — should not be here\n"
    "$DB_HOST='127.0.0.1';\n"
    "$DB_USER='voltmart_app';\n"
    "$DB_PASS='Sup3rS3cr3tDbP4ss!';\n"
    "$ADMIN_TOKEN='c0ffee-d34db33f-adm1n-t0k3n';\n"
    "?>\n"
)

HTPASSWD = "admin:$apr1$dh3h1x9k$Q6c5b0m0mF2s9Xr0hJfBv0\n"


def _text(body):
    return Response(body, mimetype="text/plain")


@app.route("/.env")
def dotenv():
    return _text(DOTENV)  # VULN: exposed .env


@app.route("/.git/config")
def git_config():
    return _text(GIT_CONFIG)  # VULN: exposed .git/config


@app.route("/.git/HEAD")
def git_head():
    return _text("ref: refs/heads/main\n")  # VULN: exposed .git/HEAD


@app.route("/db_backup.sql")
@app.route("/backup/db_backup.sql")
@app.route("/backup/")
def db_backup():
    if request.path.rstrip("/") == "/backup":
        return _dir_listing("/backup", ["db_backup.sql", "uploads.tar.gz"])
    return _text(SQL_DUMP)  # VULN: exposed DB backup


@app.route("/config.php.bak")
def config_bak():
    return _text(CONFIG_BAK)  # VULN: exposed backup config


@app.route("/.htpasswd")
def htpasswd():
    return _text(HTPASSWD)  # VULN: exposed .htpasswd


@app.route("/server-status")
def server_status():
    # VULN: Apache mod_status-style page exposed.
    body = (
        "Apache Server Status for 127.0.0.1 (via Apache/2.4.7)\n\n"
        "Server Version: Apache/2.4.7 (Ubuntu) PHP/5.6.40\n"
        "Current Time: %s\n"
        "Total accesses: 48213 - Total Traffic: 1.2 GB\n"
        "CPU Usage: u2.1 s0.9\n"
        "3 requests currently being processed, 7 idle workers\n"
    ) % datetime.now(timezone.utc).strftime("%A, %d-%b-%Y %H:%M:%S UTC")
    return _text(body)


@app.route("/info.php")
@app.route("/phpinfo.php")
def info_php():
    # VULN: phpinfo-style disclosure page.
    return render_template("phpinfo.html")


@app.route("/uploads/")
def uploads_index():
    # VULN: directory listing of the uploads folder.
    try:
        files = sorted(os.listdir(UPLOADS_DIR))
    except OSError:
        files = []
    return _dir_listing("/uploads", files)


def _dir_listing(path, files):
    return render_template("dirlisting.html", path=path, files=files)


@app.route("/robots.txt")
def robots():
    # VULN: robots.txt advertising sensitive paths.
    return _text(
        "User-agent: *\n"
        "Disallow: /admin\n"
        "Disallow: /backup/\n"
        "Disallow: /.git/\n"
        "Disallow: /uploads/\n"
        "Disallow: /db_backup.sql\n"
        "Disallow: /config.php.bak\n"
        "Disallow: /server-status\n"
    )


@app.route("/sitemap.xml")
def sitemap():
    urls = ["/", "/search", "/login", "/cart", "/api/products"]
    body = '<?xml version="1.0" encoding="UTF-8"?>\n<urlset>\n'
    for u in urls:
        body += "  <url><loc>http://127.0.0.1:8100%s</loc></url>\n" % u
    body += "</urlset>\n"
    return Response(body, mimetype="application/xml")


@app.errorhandler(404)
def not_found(_e):
    return render_template("404.html"), 404


if __name__ == "__main__":
    init_db()
    # VULN: make the dev server advertise a single, spoofed outdated banner
    # (otherwise Werkzeug appends its own Server header next to ours).
    from werkzeug.serving import WSGIRequestHandler

    WSGIRequestHandler.server_version = "Apache/2.4.7 (Ubuntu)"
    WSGIRequestHandler.sys_version = ""

    # Bind to localhost only. debug=True is itself an intentional exposure
    # (Werkzeug debugger), but keep it off the public interface.
    print(" * VulnShop (VoltMart) running on http://127.0.0.1:8100")
    print(" * INTENTIONALLY VULNERABLE - local testing only.")
    app.run(host="127.0.0.1", port=8100, debug=True)
