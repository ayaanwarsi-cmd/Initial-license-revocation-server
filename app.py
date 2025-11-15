# app.py
"""
License Revocation & Management Server with Admin Login Dashboard
Features:
- Admin login (session cookie) + optional API key header support for programmatic calls
- Licenses table with create/edit/suspend/revoke/unrevoke
- Activity logs
- API endpoints for revoke/unrevoke/status (works with session or header)
- CSV export of licenses + logs
- Dark admin UI
"""

from flask import (
    Flask, request, jsonify, render_template_string, redirect, url_for, flash,
    send_file, session, abort
)
from functools import wraps
import os, sqlite3, hmac, hashlib, json, csv, io, secrets, base64, time
from datetime import datetime, timezone, timedelta
from pathlib import Path
import requests
from werkzeug.security import generate_password_hash, check_password_hash

# ---------------- Config ----------------
DB_PATH = os.environ.get("DB_PATH", "revocations.db")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "change_me")  # plain; hashed on startup
FLASK_SECRET = os.environ.get("FLASK_SECRET", secrets.token_hex(32))
API_KEY_HEADER = "X-API-KEY"
ADMIN_KEY = os.environ.get("ADMIN_KEY", None) or os.environ.get("LEGACY_ADMIN_KEY") or ""  # legacy support for header-based admin auth
WEBHOOK_URLS = [u.strip() for u in (os.environ.get("WEBHOOK_URLS") or "").split(",") if u.strip()]

app = Flask(__name__)
app.secret_key = FLASK_SECRET

# Ensure DB parent exists (if DB_PATH contains directories)
_db_parent = Path(DB_PATH).parent
if str(_db_parent) not in (".", "") and not _db_parent.exists():
    try:
        _db_parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

# ---------------- DB helpers ----------------
def get_conn():
    c = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    """Create tables if missing (safe to call multiple times)."""
    with get_conn() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS licenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_id TEXT NOT NULL UNIQUE,
            hwid TEXT,
            email TEXT,
            created_at TIMESTAMP NOT NULL,
            expiry TIMESTAMP,
            features TEXT,
            status TEXT NOT NULL DEFAULT 'active', -- active, suspended, revoked
            revoked_at TIMESTAMP,
            revoked_reason TEXT,
            revoked_by TEXT
        );
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TIMESTAMP NOT NULL,
            event TEXT NOT NULL,
            details TEXT
        );
        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key_id TEXT NOT NULL UNIQUE,
            key_hash TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0
        );
        """)
        conn.commit()

def log_activity(event: str, details=None):
    """Insert an activity log row. If table missing, try init_db() and retry once."""
    try:
        with get_conn() as conn:
            conn.execute("INSERT INTO activity_logs (ts, event, details) VALUES (?,?,?)",
                         (datetime.now(timezone.utc), event, json.dumps(details) if details is not None else None))
            conn.commit()
    except sqlite3.OperationalError as e:
        if "no such table" in str(e).lower():
            try:
                init_db()
                with get_conn() as conn:
                    conn.execute("INSERT INTO activity_logs (ts, event, details) VALUES (?,?,?)",
                                 (datetime.now(timezone.utc), event, json.dumps(details) if details is not None else None))
                    conn.commit()
                return
            except Exception:
                pass
        raise

# Initialize DB at import-time (prevents first-request 500 errors)
try:
    init_db()
except Exception:
    pass

# ---------------- Auth helpers ----------------
# store hashed admin password in memory at startup
_ADMIN_PASS_HASH = generate_password_hash(ADMIN_PASS)

def is_api_admin():
    # Admin via header (legacy) — compare ADMIN_KEY / API keys
    header = request.headers.get(API_KEY_HEADER)
    if header:
        # If global ADMIN_KEY is set, allow comparing it
        if ADMIN_KEY and hmac.compare_digest(header, ADMIN_KEY):
            return True
        # Also support api_keys table (hashed)
        try:
            with get_conn() as conn:
                row = conn.execute("SELECT key_hash, revoked FROM api_keys WHERE key_id = ?", (header,)).fetchone()
                if row and not row["revoked"]:
                    # header value is key_id; treat as authenticated (server stores hash)
                    return True
        except Exception:
            pass
    return False

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if session.get("admin_authenticated"):
            return fn(*args, **kwargs)
        if is_api_admin():
            return fn(*args, **kwargs)
        return redirect(url_for("login", next=request.path))
    return wrapper

# ---------------- Utility ----------------
def generate_readable_license_id(prefix="LIC"):
    now = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    rnd = secrets.token_hex(3).upper()
    return f"{prefix}-{now}-{rnd}"

def _hash_key(k: str) -> str:
    return hashlib.sha256(k.encode()).hexdigest()

def notify_webhooks(payload: dict):
    for url in WEBHOOK_URLS:
        try:
            requests.post(url, json=payload, timeout=5)
        except Exception:
            try:
                log_activity("webhook_failed", {"url": url, "payload": payload})
            except Exception:
                pass

# ---------------- Public API endpoints ----------------
@app.route("/health")
def health():
    return jsonify({"ok": True})

@app.route("/status/<license_id>")
def status(license_id):
    """Return license status: revoked/suspended/active, server_time"""
    now = datetime.now(timezone.utc).isoformat()
    with get_conn() as conn:
        row = conn.execute("SELECT license_id, status, revoked_at, revoked_reason FROM licenses WHERE license_id = ?", (license_id,)).fetchone()
    if row:
        return jsonify({"revoked": row["status"] == "revoked", "suspended": row["status"] == "suspended",
                        "license_id": row["license_id"], "revoked_at": row["revoked_at"],
                        "reason": row["revoked_reason"], "server_time": now})
    # fallback: no record => not revoked
    return jsonify({"revoked": False, "suspended": False, "license_id": license_id, "server_time": now})

# ---------------- Programmatic admin API (header allowed) ----------------
@app.route("/revoke", methods=["POST"])
def revoke_api():
    # Accepts JSON: {"license_id": "...", "reason": "...", "by": "..."}
    if not (session.get("admin_authenticated") or is_api_admin()):
        return jsonify({"error": "unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    lid = data.get("license_id")
    reason = data.get("reason")
    by = data.get("by") or (session.get("admin_user") or "api")
    if not lid:
        return jsonify({"error": "license_id required"}), 400
    now = datetime.now(timezone.utc)
    with get_conn() as conn:
        # mark license revoked in licenses table (create row if missing)
        conn.execute("""
            INSERT INTO licenses (license_id, hwid, email, created_at, expiry, features, status, revoked_at, revoked_reason, revoked_by)
            VALUES (?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(license_id) DO UPDATE SET status='revoked', revoked_at=excluded.revoked_at, revoked_reason=excluded.revoked_reason, revoked_by=excluded.revoked_by
        """, (lid, None, None, now, None, None, "revoked", now, reason, by))
        conn.commit()
    log_activity("revoke", {"license_id": lid, "reason": reason, "by": by})
    notify_webhooks({"event": "revoke", "license_id": lid, "reason": reason, "revoked_at": now.isoformat()})
    return jsonify({"revoked": True, "license_id": lid, "revoked_at": now.isoformat(), "reason": reason})

@app.route("/unrevoke", methods=["POST"])
def unrevoke_api():
    if not (session.get("admin_authenticated") or is_api_admin()):
        return jsonify({"error": "unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    lid = data.get("license_id")
    by = data.get("by") or (session.get("admin_user") or "api")
    if not lid:
        return jsonify({"error": "license_id required"}), 400
    with get_conn() as conn:
        conn.execute("UPDATE licenses SET status='active', revoked_at=NULL, revoked_reason=NULL, revoked_by=NULL WHERE license_id = ?", (lid,))
        conn.commit()
    log_activity("unrevoke", {"license_id": lid, "by": by})
    notify_webhooks({"event": "unrevoke", "license_id": lid, "by": by, "time": datetime.now(timezone.utc).isoformat()})
    return jsonify({"revoked": False, "license_id": lid})

# ---------------- Admin web UI ----------------

# ---- Templates (dark CSS) ----
_LOGIN_HTML = """
<!doctype html><html><head><meta charset="utf-8"><title>Admin login</title>
<style>
body{background:#0b0f12;color:#d6e6f0;font-family:Inter,Segoe UI,Roboto,Arial;margin:0}
.box{max-width:420px;margin:6% auto;padding:28px;background:#07111a;border-radius:10px;box-shadow:0 6px 22px rgba(0,0,0,.6)}
h2{color:#cfe7ff;margin:0 0 12px 0}
label{display:block;margin-top:8px;color:#bcd}
input{width:100%;padding:10px;margin-top:6px;border-radius:6px;border:1px solid #1a2a35;background:#031016;color:#dff}
button{margin-top:16px;padding:10px 12px;border-radius:8px;border:0;background:#1f8cff;color:white;font-weight:600;cursor:pointer}
.small{font-size:0.9em;color:#9fb2c8;margin-top:8px}
a{color:#9fd}
</style></head>
<body>
<div class="box">
  <h2>Admin login</h2>
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% if messages %}{% for cat,msg in messages %}<div style="padding:8px;background:#112232;border-radius:6px;margin-bottom:8px">{{msg}}</div>{% endfor %}{% endif %}
  {% endwith %}
  <form method="post" action="{{ url_for('login') }}">
    <label>Username</label><input name="username" autofocus>
    <label>Password</label><input name="password" type="password">
    <button type="submit">Sign in</button>
  </form>
  <div class="small">Use your admin credentials. API automation may still use the API key header.</div>
</div>
</body></html>
"""

_DASH_HTML = """
<!doctype html><html><head><meta charset="utf-8"><title>Admin Dashboard</title>
<style>
:root{--bg:#071018;--panel:#09131a;--muted:#9fb2c8;--accent:#17a2ff;--card:#08121a}
body{background:var(--bg);color:#e6f3ff;font-family:Inter,Segoe UI,Roboto,Arial;margin:0;padding:12px}
.header{display:flex;align-items:center;justify-content:space-between}
.brand{font-weight:700;font-size:18px}
.controls{display:flex;gap:8px;align-items:center}
.btn{background:var(--accent);color:#012;border:0;padding:8px 10px;border-radius:8px;font-weight:600;cursor:pointer}
.card{background:var(--card);padding:12px;border-radius:10px;margin-top:12px}
.table{width:100%;border-collapse:collapse;margin-top:8px}
.table th,.table td{padding:8px;border-bottom:1px solid #0b394f;text-align:left}
.form-row{display:flex;gap:8px;align-items:center}
.input{padding:8px;border-radius:8px;border:1px solid #123;background:#031015;color:#dff}
.small{font-size:0.85em;color:var(--muted)}
.left{flex:1}
.actions button{margin-right:6px}
.search-row{display:flex;gap:8px;margin-bottom:8px}
.badge{padding:6px 8px;border-radius:8px;background:#0f3343;color:#bff;font-weight:600}
</style>
</head><body>
<div class="header">
  <div class="brand">License Management — Admin</div>
  <div class="controls">
    <form method="get" action="{{ url_for('export_csv') }}" style="display:inline"><button class="btn">Export CSV</button></form>
    <form method="post" action="{{ url_for('rotate_api_key_route') }}" style="display:inline">
      <input type="hidden" name="api_key" value="1">
      <button class="btn">Rotate API Key</button>
    </form>
    <form method="get" action="{{ url_for('logout') }}" style="display:inline"><button class="btn" style="background:#ff6b6b">Logout</button></form>
  </div>
</div>

<div class="card">
  <form method="get" action="{{ url_for('admin') }}" class="search-row">
    <input class="input left" name="q" placeholder="Search license id / email / hwid" value="{{ request.args.get('q','') }}">
    <select name="status" class="input">
      <option value="">Any status</option>
      <option value="active" {% if request.args.get('status')=='active' %}selected{% endif %}>Active</option>
      <option value="suspended" {% if request.args.get('status')=='suspended' %}selected{% endif %}>Suspended</option>
      <option value="revoked" {% if request.args.get('status')=='revoked' %}selected{% endif %}>Revoked</option>
    </select>
    <button class="btn">Search</button>
    <button class="btn" formaction="{{ url_for('admin_create') }}" formmethod="get">Create License</button>
  </form>

  <div class="small">Showing up to 200 results. Use CSV export to download full data.</div>

  {% if licenses %}
  <table class="table">
    <thead><tr><th>License ID</th><th>Email</th><th>HWID</th><th>Expiry</th><th>Status</th><th>Actions</th></tr></thead>
    <tbody>
      {% for L in licenses %}
      <tr>
        <td><code>{{ L.license_id }}</code></td>
        <td>{{ L.email or '-' }}</td>
        <td style="max-width:240px;overflow:hidden">{{ L.hwid or '-' }}</td>
        <td>{{ L.expiry or '-' }}</td>
        <td><span class="badge">{{ L.status }}</span></td>
        <td class="actions">
          <form style="display:inline" method="post" action="{{ url_for('admin_edit', license_id=L.license_id) }}"><button class="btn">Edit</button></form>
          {% if L.status != 'revoked' %}
            <form style="display:inline" method="post" action="{{ url_for('admin_revoke', license_id=L.license_id) }}"><button class="btn" style="background:#ff6b6b">Revoke</button></form>
          {% else %}
            <form style="display:inline" method="post" action="{{ url_for('admin_unrevoke', license_id=L.license_id) }}"><button class="btn" style="background:#26a65b">Unrevoke</button></form>
          {% endif %}
          {% if L.status != 'suspended' %}
            <form style="display:inline" method="post" action="{{ url_for('admin_suspend', license_id=L.license_id) }}"><button class="btn" style="background:#ffb86b">Suspend</button></form>
          {% else %}
            <form style="display:inline" method="post" action="{{ url_for('admin_unsuspend', license_id=L.license_id) }}"><button class="btn" style="background:#66d9ff">Unsuspend</button></form>
          {% endif %}
        </td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
    <div class="small">No licenses found.</div>
  {% endif %}
</div>

<div class="card" style="margin-top:12px">
  <h3>Recent Activity</h3>
  <table class="table">
    <thead><tr><th>Time</th><th>Event</th><th>Details</th></tr></thead>
    <tbody>
      {% for a in activity %}
      <tr><td>{{ a.ts }}</td><td>{{ a.event }}</td><td><pre style="white-space:pre-wrap">{{ a.details }}</pre></td></tr>
      {% endfor %}
    </tbody>
  </table>
</div>

</body></html>
"""

_CREATE_HTML = """
<!doctype html><html><head><meta charset="utf-8"><title>Create License</title>
<style>
body{background:#071018;color:#e6f3ff;font-family:Inter,Arial;padding:12px}
.card{background:#08121a;padding:16px;border-radius:10px;max-width:820px;margin:20px auto}
.input{width:100%;padding:8px;margin:6px 0;border-radius:6px;background:#03121a;color:#dff;border:1px solid #123}
.btn{background:#17a2ff;color:#001;border:0;padding:8px 10px;border-radius:8px;cursor:pointer}
.small{color:#9fb2c8}
</style></head><body>
<div class="card">
  <h2>Create License</h2>
  <form method="post" action="{{ url_for('admin_create') }}">
    <label>HWID</label><input class="input" name="hwid" placeholder="hardware id">
    <label>Email</label><input class="input" name="email" placeholder="buyer email">
    <label>Expiry (YYYY-MM-DD or ISO)</label><input class="input" name="expiry" placeholder="2026-01-01T12:00:00">
    <label>Features (JSON) optional</label><input class="input" name="features" placeholder='{"pro":true}'>
    <div style="display:flex;gap:8px"><button class="btn" type="submit">Create</button> <a href="{{ url_for('admin') }}" class="small">Back</a></div>
  </form>
</div>
</body></html>
"""

_EDIT_HTML = """
<!doctype html><html><head><meta charset="utf-8"><title>Edit License {{ license.license_id }}</title>
<style>
body{background:#071018;color:#e6f3ff;font-family:Inter,Arial;padding:12px}
.card{background:#08121a;padding:16px;border-radius:10px;max-width:820px;margin:20px auto}
.input{width:100%;padding:8px;margin:6px 0;border-radius:6px;background:#03121a;color:#dff;border:1px solid #123}
.btn{background:#17a2ff;color:#001;border:0;padding:8px 10px;border-radius:8px;cursor:pointer}
.small{color:#9fb2c8}
</style></head><body>
<div class="card">
  <h2>Edit License {{ license.license_id }}</h2>
  <form method="post" action="{{ url_for('admin_edit', license_id=license.license_id) }}">
    <label>HWID</label><input class="input" name="hwid" value="{{ license.hwid or '' }}">
    <label>Email</label><input class="input" name="email" value="{{ license.email or '' }}">
    <label>Expiry</label><input class="input" name="expiry" value="{{ license.expiry or '' }}">
    <label>Features (JSON)</label><input class="input" name="features" value='{{ license.features or "" }}'>
    <div style="display:flex;gap:8px"><button class="btn" type="submit">Save</button> <a href="{{ url_for('admin') }}" class="small">Back</a></div>
  </form>
</div>
</body></html>
"""

# ---------------- Admin routes ----------------
@app.route("/admin/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        if u == ADMIN_USER and check_password_hash(_ADMIN_PASS_HASH, p) or (u == ADMIN_USER and p == ADMIN_PASS):
            session["admin_authenticated"] = True
            session["admin_user"] = u
            return redirect(url_for("admin"))
        flash("Invalid credentials")
    return render_template_string(_LOGIN_HTML)

@app.route("/admin/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/admin", methods=["GET"])
@login_required
def admin():
    # search and list licenses
    q = request.args.get("q", "").strip()
    status = request.args.get("status", "").strip()
    params = []
    sql = "SELECT license_id, hwid, email, expiry, status FROM licenses"
    conds = []
    if q:
        conds.append("(license_id LIKE ? OR email LIKE ? OR hwid LIKE ?)")
        params.extend([f"%{q}%"] * 3)
    if status:
        conds.append("status = ?"); params.append(status)
    if conds:
        sql += " WHERE " + " AND ".join(conds)
    sql += " ORDER BY created_at DESC LIMIT 200"
    with get_conn() as conn:
        rows = conn.execute(sql, params).fetchall()
        licenses = rows
        activity = conn.execute("SELECT ts, event, details FROM activity_logs ORDER BY ts DESC LIMIT 40").fetchall()
    return render_template_string(_DASH_HTML, licenses=licenses, activity=activity)

@app.route("/admin/create", methods=["GET", "POST"])
@login_required
def admin_create():
    if request.method == "GET":
        return render_template_string(_CREATE_HTML)
    # POST -> create license record
    hwid = request.form.get("hwid") or None
    email = request.form.get("email") or None
    expiry = request.form.get("expiry") or None
    features = request.form.get("features") or None
    if features:
        try:
            # normalize JSON
            json.loads(features)
        except Exception:
            flash("Features must be valid JSON"); return redirect(url_for("admin_create"))
    license_id = generate_readable_license_id()
    now = datetime.now(timezone.utc)
    with get_conn() as conn:
        conn.execute("""INSERT INTO licenses (license_id, hwid, email, created_at, expiry, features, status)
                        VALUES (?,?,?,?,?,?,?)""",
                     (license_id, hwid, email, now, expiry, features, "active"))
        conn.commit()
    log_activity("create_license", {"license_id": license_id, "email": email, "hwid": hwid})
    flash(f"Created license {license_id}")
    return redirect(url_for("admin"))

@app.route("/admin/edit/<license_id>", methods=["GET", "POST"])
@login_required
def admin_edit(license_id):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM licenses WHERE license_id = ?", (license_id,)).fetchone()
    if not row:
        flash("License not found"); return redirect(url_for("admin"))
    if request.method == "GET":
        # present edit form
        return render_template_string(_EDIT_HTML, license=row)
    # POST -> save edits
    hwid = request.form.get("hwid") or None
    email = request.form.get("email") or None
    expiry = request.form.get("expiry") or None
    features = request.form.get("features") or None
    with get_conn() as conn:
        conn.execute("UPDATE licenses SET hwid = ?, email = ?, expiry = ?, features = ? WHERE license_id = ?",
                     (hwid, email, expiry, features, license_id))
        conn.commit()
    log_activity("edit_license", {"license_id": license_id, "hwid": hwid, "email": email, "expiry": expiry})
    flash("Saved")
    return redirect(url_for("admin"))

@app.route("/admin/revoke/<license_id>", methods=["POST"])
@login_required
def admin_revoke(license_id):
    reason = request.form.get("reason") or "revoked via admin UI"
    now = datetime.now(timezone.utc)
    with get_conn() as conn:
        conn.execute("UPDATE licenses SET status='revoked', revoked_at=?, revoked_reason=?, revoked_by=? WHERE license_id=?",
                     (now, reason, session.get("admin_user"), license_id))
        # if license not exist insert as revoked
        conn.execute("""INSERT OR IGNORE INTO licenses
                        (license_id, created_at, status, revoked_at, revoked_reason, revoked_by)
                        VALUES (?, ?, ?, ?, ?, ?)""",
                     (license_id, now, "revoked", now, reason, session.get("admin_user")))
        conn.commit()
    log_activity("revoke", {"license_id": license_id, "reason": reason, "by": session.get("admin_user")})
    notify_webhooks({"event": "revoke", "license_id": license_id, "reason": reason, "revoked_at": now.isoformat()})
    flash(f"Revoked {license_id}")
    return redirect(url_for("admin"))

@app.route("/admin/unrevoke/<license_id>", methods=["POST"])
@login_required
def admin_unrevoke(license_id):
    with get_conn() as conn:
        conn.execute("UPDATE licenses SET status='active', revoked_at=NULL, revoked_reason=NULL, revoked_by=NULL WHERE license_id=?", (license_id,))
        conn.commit()
    log_activity("unrevoke", {"license_id": license_id, "by": session.get("admin_user")})
    notify_webhooks({"event": "unrevoke", "license_id": license_id})
    flash(f"Unrevoked {license_id}")
    return redirect(url_for("admin"))

@app.route("/admin/suspend/<license_id>", methods=["POST"])
@login_required
def admin_suspend(license_id):
    reason = request.form.get("reason") or "suspended via admin UI"
    with get_conn() as conn:
        conn.execute("UPDATE licenses SET status='suspended' WHERE license_id = ?", (license_id,))
        conn.commit()
    log_activity("suspend", {"license_id": license_id, "reason": reason, "by": session.get("admin_user")})
    flash(f"Suspended {license_id}")
    return redirect(url_for("admin"))

@app.route("/admin/unsuspend/<license_id>", methods=["POST"])
@login_required
def admin_unsuspend(license_id):
    with get_conn() as conn:
        conn.execute("UPDATE licenses SET status='active' WHERE license_id = ?", (license_id,))
        conn.commit()
    log_activity("unsuspend", {"license_id": license_id, "by": session.get("admin_user")})
    flash(f"Unsuspended {license_id}")
    return redirect(url_for("admin"))

# rotate API key (admin POST)
@app.route("/api/keys/rotate", methods=["POST"])
@login_required
def rotate_api_key_route():
    new_key = secrets.token_hex(32)
    key_id = new_key  # here we return key directly (key_id equal to the token); we store hash
    now = datetime.now(timezone.utc)
    with get_conn() as conn:
        conn.execute("INSERT INTO api_keys (key_id, key_hash, created_at, revoked) VALUES (?,?,?,0)",
                     (key_id, _hash_key(key_id), now))
        conn.commit()
    log_activity("api_key_rotated", {"key_id": key_id, "by": session.get("admin_user")})
    flash("Rotated API key (copy it now; it will not be shown again)")
    # Show the new key in a small page
    return jsonify({"key": key_id})

# alias for compatibility (legacy templates)
@app.route("/api/keys/rotate-alias", methods=["POST"])
@login_required
def rotate_api_key_alias():
    return rotate_api_key_route()

@app.route("/admin/export.csv")
@login_required
def export_csv():
    sio = io.StringIO()
    w = csv.writer(sio)
    w.writerow(["licenses"])
    w.writerow(["license_id","hwid","email","created_at","expiry","features","status","revoked_at","revoked_reason","revoked_by"])
    with get_conn() as conn:
        for r in conn.execute("SELECT license_id, hwid, email, created_at, expiry, features, status, revoked_at, revoked_reason, revoked_by FROM licenses ORDER BY created_at DESC"):
            w.writerow([r["license_id"], r["hwid"], r["email"], r["created_at"], r["expiry"], r["features"], r["status"], r["revoked_at"], r["revoked_reason"], r["revoked_by"]])
    w.writerow([])
    w.writerow(["activity_logs"])
    w.writerow(["ts","event","details"])
    with get_conn() as conn:
        for r in conn.execute("SELECT ts, event, details FROM activity_logs ORDER BY ts DESC"):
            w.writerow([r["ts"], r["event"], r["details"]])
    sio.seek(0)
    return send_file(io.BytesIO(sio.getvalue().encode("utf-8")), mimetype="text/csv", download_name="licenses_activity.csv", as_attachment=True)

# ---------------- Run ----------------
if __name__ == "__main__":
    # init db then run
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
