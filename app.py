## app.py
"""
License Management Server
- Admin login (session) + legacy API key support
- List issued licenses and revoked licenses (UI + API)
- Issue new license (UI + API) — server-side signing and save option
- Revoke license (UI + API)
- Signed license download, CSV export, API key rotation, activity logs
"""

from flask import (
    Flask, request, jsonify, render_template_string, redirect, url_for, flash,
    send_file, session, make_response, abort
)
from functools import wraps
import os, sqlite3, hmac, hashlib, json, csv, io, secrets, base64
from datetime import datetime, timezone
from pathlib import Path
import requests
from werkzeug.security import generate_password_hash, check_password_hash

# cryptography for signing
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    _HAS_CRYPTO = True
except Exception:
    _HAS_CRYPTO = False

# ---------------- Config ----------------
DB_PATH = os.environ.get("DB_PATH", "revocations.db")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "change_me")
FLASK_SECRET = os.environ.get("FLASK_SECRET", secrets.token_hex(32))
API_KEY_HEADER = "X-API-KEY"
ADMIN_KEY = os.environ.get("ADMIN_KEY", "")  # legacy header key
WEBHOOK_URLS = [u.strip() for u in (os.environ.get("WEBHOOK_URLS") or "").split(",") if u.strip()]

PRIVATE_KEY_PATH = os.environ.get("PRIVATE_KEY_PATH", "server_private.pem")
PUBLIC_KEY_PATH = os.environ.get("PUBLIC_KEY_PATH", "server_public.pem")
SIGNED_DIR = os.environ.get("SIGNED_DIR", "signed_licenses")

app = Flask(__name__)
app.secret_key = FLASK_SECRET

# ensure directories
_db_parent = Path(DB_PATH).parent
if str(_db_parent) not in (".", "") and not _db_parent.exists():
    _db_parent.mkdir(parents=True, exist_ok=True)
Path(SIGNED_DIR).mkdir(parents=True, exist_ok=True)

# ---------------- DB helpers ----------------
def get_conn():
    c = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
    c.row_factory = sqlite3.Row
    return c

def init_db():
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
            status TEXT NOT NULL DEFAULT 'active', -- active / suspended / revoked
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
    try:
        with get_conn() as conn:
            conn.execute("INSERT INTO activity_logs (ts, event, details) VALUES (?,?,?)",
                         (datetime.now(timezone.utc), event, json.dumps(details) if details is not None else None))
            conn.commit()
    except sqlite3.OperationalError as e:
        if "no such table" in str(e).lower():
            init_db()
            with get_conn() as conn:
                conn.execute("INSERT INTO activity_logs (ts, event, details) VALUES (?,?,?)",
                             (datetime.now(timezone.utc), event, json.dumps(details) if details is not None else None))
                conn.commit()
        else:
            raise

# init db
try:
    init_db()
except Exception:
    pass

# ---------------- Auth ----------------
_ADMIN_PASS_HASH = generate_password_hash(ADMIN_PASS)

def _hash_key(k: str) -> str:
    return hashlib.sha256(k.encode()).hexdigest()

def is_api_admin():
    header = request.headers.get(API_KEY_HEADER)
    if header:
        if ADMIN_KEY and hmac.compare_digest(header, ADMIN_KEY):
            return True
        try:
            with get_conn() as conn:
                row = conn.execute("SELECT key_hash, revoked FROM api_keys WHERE key_id = ?", (header,)).fetchone()
                if row and not row["revoked"]:
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

# ---------------- Utilities & Signing ----------------
def generate_readable_license_id(prefix="LIC"):
    now = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    rnd = secrets.token_hex(3).upper()
    return f"{prefix}-{now}-{rnd}"

_private_key_obj = None
_public_key_obj = None

def _ensure_private_key():
    global _private_key_obj, _public_key_obj
    if _private_key_obj is not None:
        return
    if not _HAS_CRYPTO:
        return
    priv_path = Path(PRIVATE_KEY_PATH)
    pub_path = Path(PUBLIC_KEY_PATH)
    if priv_path.exists():
        data = priv_path.read_bytes()
        _private_key_obj = serialization.load_pem_private_key(data, password=None)
        if pub_path.exists():
            try:
                _public_key_obj = serialization.load_pem_public_key(pub_path.read_bytes())
            except Exception:
                _public_key_obj = _private_key_obj.public_key()
        else:
            _public_key_obj = _private_key_obj.public_key()
        return
    # generate
    priv = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    pem_priv = priv.private_bytes(encoding=serialization.Encoding.PEM,
                                 format=serialization.PrivateFormat.PKCS8,
                                 encryption_algorithm=serialization.NoEncryption())
    pem_pub = priv.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                            format=serialization.PublicFormat.SubjectPublicKeyInfo)
    try:
        priv_path.write_bytes(pem_priv)
        pub_path.write_bytes(pem_pub)
        _private_key_obj = priv
        _public_key_obj = priv.public_key()
        log_activity("auto_generated_private_key", {"private_path": str(priv_path), "public_path": str(pub_path)})
    except Exception:
        pass

def sign_license_object(lic_obj: dict) -> str:
    if not _HAS_CRYPTO:
        raise RuntimeError("cryptography not available")
    _ensure_private_key()
    payload = json.dumps(lic_obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    sig = _private_key_obj.sign(
        payload,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return base64.b64encode(sig).decode("ascii")

def _signed_file_path(license_id: str) -> Path:
    safe = "".join(c for c in license_id if c.isalnum() or c in "-_.")
    return Path(SIGNED_DIR) / f"{safe}.json"

def notify_webhooks(payload: dict):
    for url in WEBHOOK_URLS:
        try:
            requests.post(url, json=payload, timeout=5)
        except Exception:
            try:
                log_activity("webhook_failed", {"url": url, "payload": payload})
            except Exception:
                pass

# ---------------- Public endpoints ----------------
@app.route("/health")
def health():
    return jsonify({"ok": True})

@app.route("/status/<license_id>")
def status(license_id):
    now = datetime.now(timezone.utc).isoformat()
    with get_conn() as conn:
        row = conn.execute("SELECT license_id, status, revoked_at, revoked_reason, expiry FROM licenses WHERE license_id = ?", (license_id,)).fetchone()
    if row:
        return jsonify({"revoked": row["status"] == "revoked", "suspended": row["status"] == "suspended",
                        "license_id": row["license_id"], "revoked_at": row["revoked_at"],
                        "reason": row["revoked_reason"], "expiry": row["expiry"], "server_time": now})
    return jsonify({"revoked": False, "suspended": False, "license_id": license_id, "server_time": now})

# ---------------- API: list / create / revoke licenses ----------------
@app.route("/api/licenses", methods=["GET", "POST"])
@login_required
def api_licenses_list_create():
    """
    GET: list licenses. Optional query param 'status' to filter: active/suspended/revoked
    POST: issue a new license. JSON body: {hwid, email, expiry, features, license_id(optional), save(optional bool)}
    Returns signed license JSON + signature (and also creates DB row).
    """
    if request.method == "GET":
        status_q = request.args.get("status", "").strip()
        params = []
        sql = "SELECT license_id, hwid, email, created_at, expiry, features, status, revoked_at, revoked_reason, revoked_by FROM licenses"
        if status_q:
            sql += " WHERE status = ?"
            params.append(status_q)
        sql += " ORDER BY created_at DESC LIMIT 1000"
        with get_conn() as conn:
            rows = conn.execute(sql, params).fetchall()
            out = []
            for r in rows:
                out.append({k: r[k] for k in r.keys()})
        return jsonify({"count": len(out), "licenses": out})
    # POST: create/issue license (server-side signing)
    data = request.get_json(force=True)
    hwid = data.get("hwid")
    email = data.get("email")
    expiry = data.get("expiry")
    features = data.get("features") or {"pro": True}
    lid = data.get("license_id") or generate_readable_license_id()
    save_file = data.get("save", False)
    now = datetime.now(timezone.utc).isoformat()
    lic = {"id": lid, "hwid": hwid, "email": email, "created_at": now, "expiry": expiry, "features": features}
    # sign
    sig = None
    if _HAS_CRYPTO:
        try:
            sig = sign_license_object(lic)
        except Exception as e:
            return jsonify({"error": f"sign failed: {e}"}), 500
    # store DB row
    try:
        with get_conn() as conn:
            conn.execute("INSERT OR REPLACE INTO licenses (license_id, hwid, email, created_at, expiry, features, status) VALUES (?,?,?,?,?,?,?)",
                         (lid, hwid, email, now, expiry, json.dumps(features) if not isinstance(features, str) else features, "active"))
            conn.commit()
    except Exception:
        pass
    log_activity("issue_license", {"license_id": lid, "email": email, "hwid": hwid, "by": session.get("admin_user") or "api"})
    if save_file and sig:
        out = {"license": lic, "signature": sig}
        try:
            _signed_file_path(lid).write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
        except Exception:
            pass
    notify_webhooks({"event": "issue", "license_id": lid, "by": session.get("admin_user") or "api"})
    return jsonify({"license": lic, "signature": sig})

@app.route("/api/licenses/<license_id>/revoke", methods=["POST"])
@login_required
def api_license_revoke(license_id):
    data = request.get_json(silent=True) or {}
    reason = data.get("reason") or request.form.get("reason") or "revoked via API"
    by = session.get("admin_user") or "api"
    now = datetime.now(timezone.utc)
    try:
        with get_conn() as conn:
            conn.execute("""
                INSERT INTO licenses (license_id, hwid, email, created_at, expiry, features, status, revoked_at, revoked_reason, revoked_by)
                VALUES (?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(license_id) DO UPDATE SET status='revoked', revoked_at=excluded.revoked_at, revoked_reason=excluded.revoked_reason, revoked_by=excluded.revoked_by
            """, (license_id, None, None, now, None, None, "revoked", now, reason, by))
            conn.commit()
    except Exception as e:
        log_activity("revoke_error", {"license_id": license_id, "error": str(e)})
        return jsonify({"error": str(e)}), 500
    log_activity("revoke", {"license_id": license_id, "reason": reason, "by": by})
    notify_webhooks({"event": "revoke", "license_id": license_id, "reason": reason, "revoked_at": now.isoformat()})
    return jsonify({"revoked": True, "license_id": license_id, "reason": reason})

# compatibility endpoints (old)
@app.route("/revoke", methods=["POST"])
def revoke_api_compat():
    if not (session.get("admin_authenticated") or is_api_admin()):
        return jsonify({"error": "unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    lid = data.get("license_id")
    reason = data.get("reason")
    if not lid:
        return jsonify({"error": "license_id required"}), 400
    return api_license_revoke(lid)

# ---------------- Signed download endpoint ----------------
@app.route("/signed/download/<license_id>", methods=["GET"])
@login_required
def signed_download(license_id):
    path = _signed_file_path(license_id)
    if path.exists():
        return send_file(str(path), mimetype="application/json", as_attachment=True, download_name=path.name)
    with get_conn() as conn:
        row = conn.execute("SELECT license_id, hwid, email, created_at, expiry, features FROM licenses WHERE license_id = ?", (license_id,)).fetchone()
    if not row:
        return abort(404, "license not found")
    features = row["features"]
    try:
        feats = json.loads(features) if features and isinstance(features, str) else features
    except Exception:
        feats = features
    lic = {
        "id": row["license_id"],
        "hwid": row["hwid"],
        "email": row["email"],
        "created_at": row["created_at"],
        "expiry": row["expiry"],
        "features": feats
    }
    if _HAS_CRYPTO:
        try:
            sig = sign_license_object(lic)
        except Exception as e:
            return abort(500, f"signing failed: {e}")
        out = {"license": lic, "signature": sig}
        data = json.dumps(out, indent=2, ensure_ascii=False)
    else:
        out = {"license": lic}
        data = json.dumps(out, indent=2, ensure_ascii=False)
    resp = make_response(data)
    resp.headers["Content-Type"] = "application/json"
    resp.headers["Content-Disposition"] = f"attachment; filename={license_id}.json"
    return resp

# ---------------- Admin UI templates ----------------
_LOGIN_HTML = """
<!doctype html><html><head><meta charset="utf-8"><title>Admin login</title>
<style>body{background:#0b0f12;color:#d6e6f0;font-family:Inter,Segoe UI,Roboto,Arial;margin:0}
.box{max-width:420px;margin:6% auto;padding:28px;background:#07111a;border-radius:10px}
input{width:100%;padding:10px;margin-top:6px;border-radius:6px;border:1px solid #1a2a35;background:#031016;color:#dff}
button{margin-top:16px;padding:10px 12px;border-radius:8px;border:0;background:#1f8cff;color:white;font-weight:600;cursor:pointer}
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
</div>
</body></html>
"""

_ADMIN_HTML = """
<!doctype html><html><head><meta charset="utf-8"><title>Admin Dashboard</title>
<style>
body{background:#071018;color:#e6f3ff;font-family:Inter,Arial;padding:12px} a{color:#9fd}
.header{display:flex;justify-content:space-between;align-items:center}
.controls{display:flex;gap:8px}
.btn{background:#17a2ff;color:#001;border:0;padding:8px 10px;border-radius:8px;cursor:pointer}
.card{background:#08121a;padding:12px;border-radius:10px;margin-top:12px}
.table{width:100%;border-collapse:collapse;margin-top:8px}
.table th,.table td{padding:8px;border-bottom:1px solid #0b394f;text-align:left}
.small{color:#9fb2c8}
.tabs{display:flex;gap:8px;margin-bottom:8px}
.tabbtn{padding:8px 10px;border-radius:8px;background:#0b2430;color:#bfe;cursor:pointer}
.form-inline{display:flex;gap:8px;align-items:center}
.input{padding:8px;border-radius:6px;border:1px solid #123;background:#03121a;color:#dff}
</style></head><body>
<div class="header">
  <div><strong>License Management — Admin</strong></div>
  <div class="controls">
    <a class="btn" href="{{ url_for('export_csv') }}">Export CSV</a>
    <form method="post" action="{{ url_for('rotate_api_key_route') }}" style="display:inline"><button class="btn">Rotate API Key</button></form>
    <a class="btn" href="{{ url_for('logout') }}" style="background:#ff6b6b">Logout</a>
  </div>
</div>

<div class="card">
  <div class="tabs">
    <a class="tabbtn" href="{{ url_for('admin') }}?view=issued">Issued Licenses</a>
    <a class="tabbtn" href="{{ url_for('admin') }}?view=revoked">Revoked Licenses</a>
    <a class="tabbtn" href="{{ url_for('admin') }}?view=issue">Issue New License</a>
  </div>

  {% if view == 'issue' %}
    <h3>Issue New License</h3>
    <form method="post" action="{{ url_for('admin_issue') }}">
      <div style="display:flex;gap:8px;align-items:center">
        <input name="hwid" class="input" placeholder="HWID" style="flex:2" required>
        <input name="email" class="input" placeholder="email / buyer" style="flex:2">
        <input name="expiry" class="input" placeholder="expiry (ISO) or empty for lifetime" style="flex:2">
        <select name="save" class="input"><option value="no">Don't save file</option><option value="yes">Save signed file</option></select>
        <button class="btn" type="submit">Issue</button>
      </div>
    </form>
  {% elif view == 'revoked' %}
    <h3>Revoked Licenses (recent)</h3>
    {% if licenses %}
      <table class="table"><thead><tr><th>ID</th><th>Email</th><th>Revoked At</th><th>Reason</th><th>By</th></tr></thead>
      <tbody>
      {% for L in licenses %}
        <tr><td><code>{{ L.license_id }}</code></td><td>{{ L.email or '-' }}</td><td>{{ L.revoked_at or '-' }}</td><td>{{ L.revoked_reason or '-' }}</td><td>{{ L.revoked_by or '-' }}</td></tr>
      {% endfor %}
      </tbody></table>
    {% else %}
      <div class="small">No revoked licenses found.</div>
    {% endif %}
  {% else %}
    <h3>Issued Licenses (recent)</h3>
    {% if licenses %}
      <table class="table"><thead><tr><th>ID</th><th>Email</th><th>HWID</th><th>Expiry</th><th>Status</th><th>Actions</th></tr></thead>
      <tbody>
      {% for L in licenses %}
        <tr>
          <td><code>{{ L.license_id }}</code></td>
          <td>{{ L.email or '-' }}</td>
          <td style="max-width:260px;overflow:hidden">{{ L.hwid or '-' }}</td>
          <td>{{ L.expiry or '-' }}</td>
          <td>{{ L.status }}</td>
          <td>
            <a class="btn" href="{{ url_for('signed_download', license_id=L.license_id) }}">Download</a>
            {% if L.status != 'revoked' %}
              <form style="display:inline" method="post" action="{{ url_for('admin_revoke') }}">
                <input type="hidden" name="license_id" value="{{ L.license_id }}">
                <input type="hidden" name="reason" value="revoked via admin UI">
                <button class="btn" style="background:#ff6b6b">Revoke</button>
              </form>
            {% endif %}
          </td>
        </tr>
      {% endfor %}
      </tbody></table>
    {% else %}
      <div class="small">No licenses found.</div>
    {% endif %}
  {% endif %}
</div>

<div class="card" style="margin-top:12px">
  <h3>Recent activity</h3>
  {% if activity %}
  <table class="table">
    <thead><tr><th>Time</th><th>Event</th><th>Details</th></tr></thead>
    <tbody>
      {% for a in activity %}
      <tr><td>{{ a.ts }}</td><td>{{ a.event }}</td><td><pre style="white-space:pre-wrap">{{ a.details }}</pre></td></tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
    <div class="small">No recent activity.</div>
  {% endif %}
</div>

</body></html>
"""

# ---------------- Admin routes ----------------
@app.route("/admin/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        if u == ADMIN_USER and (check_password_hash(_ADMIN_PASS_HASH, p) or p == ADMIN_PASS):
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
    view = request.args.get("view", "issued")
    # issued vs revoked: query DB accordingly
    licenses = []
    with get_conn() as conn:
        if view == "revoked":
            rows = conn.execute("SELECT license_id, email, hwid, expiry, status, revoked_at, revoked_reason, revoked_by FROM licenses WHERE status='revoked' ORDER BY revoked_at DESC LIMIT 200").fetchall()
        else:
            rows = conn.execute("SELECT license_id, email, hwid, expiry, status FROM licenses ORDER BY created_at DESC LIMIT 200").fetchall()
        for r in rows:
            licenses.append({k: r[k] for k in r.keys()})
        activity = conn.execute("SELECT ts, event, details FROM activity_logs ORDER BY ts DESC LIMIT 40").fetchall()
    return render_template_string(_ADMIN_HTML, licenses=licenses, activity=activity, view=view)

@app.route("/admin/issue", methods=["POST"])
@login_required
def admin_issue():
    hwid = request.form.get("hwid")
    email = request.form.get("email")
    expiry = request.form.get("expiry") or None
    save = request.form.get("save", "no") == "yes"
    # issue -> call internal API to reuse logic
    payload = {"hwid": hwid, "email": email, "expiry": expiry, "features": {"pro": True}, "save": save}
    # call app-internal function rather than HTTP
    with app.test_request_context():
        # reuse POST /api/licenses functionality by calling function directly
        with app.test_client() as c:
            headers = {}
            # if admin header configured, allow internal call
            if ADMIN_KEY:
                headers[API_KEY_HEADER] = ADMIN_KEY
            resp = c.post("/api/licenses", json=payload, headers=headers)
            try:
                j = resp.get_json()
            except Exception:
                j = {"error": "unexpected response"}
    if resp.status_code != 200:
        flash(f"Issue failed: {j.get('error','unknown')}")
    else:
        lic = j.get("license", {})
        log_activity("issued_via_ui", {"license_id": lic.get("id"), "email": email})
        flash(f"Issued license {lic.get('id')}")
    return redirect(url_for("admin", view="issued"))

@app.route("/admin/revoke", methods=["POST"])
@login_required
def admin_revoke():
    license_id = (request.form.get("license_id") or "").strip()
    reason = (request.form.get("reason") or "revoked via admin UI").strip()
    if not license_id:
        flash("License ID required", "error")
        return redirect(url_for("admin"))
    # call internal revoke API
    with app.test_request_context():
        with app.test_client() as c:
            headers = {}
            if ADMIN_KEY:
                headers[API_KEY_HEADER] = ADMIN_KEY
            resp = c.post(f"/api/licenses/{license_id}/revoke", json={"reason": reason}, headers=headers)
            try:
                j = resp.get_json()
            except Exception:
                j = {"error": "unexpected response"}
    if resp.status_code != 200:
        flash(f"Revoke failed: {j.get('error','unknown')}", "error")
    else:
        log_activity("revoked_via_ui", {"license_id": license_id, "reason": reason})
        flash(f"Revoked {license_id}")
    return redirect(url_for("admin", view="issued"))

# ---------------- CSV export & rotate ----------------
@app.route("/api/keys/rotate", methods=["POST"])
@login_required
def rotate_api_key_route():
    new_key = secrets.token_hex(32)
    key_id = new_key
    now = datetime.now(timezone.utc)
    with get_conn() as conn:
        conn.execute("INSERT INTO api_keys (key_id, key_hash, created_at, revoked) VALUES (?,?,?,0)",
                     (key_id, _hash_key(key_id), now))
        conn.commit()
    log_activity("api_key_rotated", {"key_id": key_id, "by": session.get("admin_user")})
    return jsonify({"key": key_id})

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

# ---------------- Compatibility & legacy endpoints ----------------
@app.route("/sign", methods=["POST"])
def sign_api_compat():
    # keep compatibility with older clients that called /sign
    return api_licenses_list_create()

# ---------------- Run ----------------
if __name__ == "__main__":
    if _HAS_CRYPTO:
        try:
            _ensure_private_key()
        except Exception as e:
            print("Warning: private key issue:", e)
    else:
        print("cryptography not installed; signing endpoints disabled.")
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
