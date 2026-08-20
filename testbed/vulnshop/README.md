# 🛒 VulnShop — intentionally vulnerable e-commerce test target

A small, **dynamic (SQLite-backed), responsive** e-commerce web app whose only
purpose is to give the RECON-X scanners something concrete to detect. Every
"weakness" in here is **planted on purpose**.

> ## ⚠️ SAFETY — read this
> This app is **deliberately insecure**. Run it **only** on a local, isolated
> machine, bound to `127.0.0.1`. **Never** deploy it to a public network, a
> shared server, or the internet. It stores plaintext passwords, is trivially
> SQL-injectable, and exposes secrets on purpose. When you're done testing,
> stop it and (optionally) delete `vulnshop.db`.

---

## Run it

```bash
cd testbed/vulnshop
python -m pip install -r requirements.txt
python app.py
```

It serves on **http://127.0.0.1:8100** and creates `vulnshop.db` on first run
(re-seeded automatically if missing). Nothing outside this folder is touched.

Demo logins (also stored in the DB in plaintext — that's one of the vulns):

| user    | password    | role  |
|---------|-------------|-------|
| `admin` | `admin123`  | admin |
| `alice` | `password1` | user  |

---

## What's real (so it's a fair test)

It's a genuine dynamic app, not a static mock:

- SQLite-backed **product catalog** with categories, search, stock, prices.
- **Session cart** (add / remove / quantity) and a **checkout** that writes real orders.
- **Login** with server-side sessions, a **user account** page, and an **admin dashboard**.
- A small **JSON API** (`/api/products`).
- Fully **responsive** layout (mobile-first CSS grid/flex), no external assets — self-contained.

## The planted vulnerabilities → which scanner should catch each

| # | Planted issue | Where | Expected detector |
|---|---------------|-------|-------------------|
| 1 | Exposed environment file with secrets | `GET /.env` | nuclei `exposed-env`, ffuf |
| 2 | Exposed git metadata | `GET /.git/config`, `/.git/HEAD` | nuclei `git-config`, ffuf |
| 3 | Database backup left in web root | `GET /db_backup.sql`, `/backup/db_backup.sql` | nuclei backup templates, ffuf |
| 4 | Directory listing enabled | `GET /uploads/` | nuclei `directory-listing`, httpx, ffuf |
| 5 | Exposed admin panel | `GET /admin` | ffuf, nuclei exposed-panel |
| 6 | Missing security headers (no CSP/XFO/HSTS/nosniff) | all responses | nuclei http misconfig (info) |
| 7 | `robots.txt` leaking sensitive paths | `GET /robots.txt` | httpx, ffuf, nuclei robots endpoint |
| 8 | Spoofed outdated server banner | `Server: Apache/2.4.7`, `X-Powered-By: PHP/5.6.40` | httpx, tech-detect (maps to known CVEs) |
| 9 | Apache-style status page | `GET /server-status` | nuclei, ffuf |
| 10 | phpinfo-style info page | `GET /info.php` | nuclei phpinfo, ffuf |
| 11 | Backup config file | `GET /config.php.bak`, `/.htpasswd` | nuclei backup/config, ffuf |
| 12 | Exposed API docs | `GET /api/swagger.json`, `/api-docs` | nuclei swagger, ffuf |
| 13 | **SQL injection** | `GET /search?q=`, login form | manual/educational (dynamic proof) |
| 14 | **Reflected XSS** | `GET /search?q=` | manual/educational |
| 15 | **IDOR** — any order viewable | `GET /order/<id>` | manual/educational |
| 16 | Plaintext password storage + weak creds | DB / login | manual/educational |
| 17 | Several open service ports | host | nmap |

Items 13–16 are classic app-logic bugs our **recon/nuclei** scanners won't
auto-flag — they're here to prove the app is genuinely dynamic and to give a
manual-testing surface. Items 1–12 and 17 are what the tool should light up.

## How to test with RECON-X

1. Start VulnShop (above).
2. In RECON-X, use a workspace whose **scope** includes `127.0.0.1` (dev `.env`
   has `RECONX_BLOCK_PRIVATE_TARGETS=false`, so the netguard allows localhost).
3. Point the scanners at `http://127.0.0.1:8100`:
   - **httpx** → banner, title, spoofed server/PHP versions
   - **ffuf / content discovery** → `/admin`, `/backup`, `/.git`, `/.env`, `/uploads`, `db_backup.sql`, …
   - **nuclei** (run with `-severity info,low,medium,high,critical`, not just critical) → the exposed-file / misconfig findings
   - **nmap** → open ports
   - **tech-detect** → Apache/PHP fingerprint
4. Compare what the tool found against the table above → that's your scorecard.

## Layout

```
testbed/vulnshop/
├── app.py               # Flask app: routes, DB seed, planted vulns (all commented "VULN:")
├── requirements.txt
├── README.md            # this file
├── .gitignore           # keeps vulnshop.db out of version control
├── templates/           # Jinja2 responsive templates
└── static/
    ├── css/style.css    # mobile-first responsive design
    ├── js/main.js       # cart interactivity
    └── uploads/         # sample files behind the directory-listing vuln
```
