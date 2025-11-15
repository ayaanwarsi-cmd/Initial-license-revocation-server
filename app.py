# app.py
"""
License Management server — admin login + signing + revoke + signed-license downloads + dashboard
- Admin UI: login, sign (auto-download), revoke quick form, signed-license list + download
- Programmatic APIs: /sign, /revoke, /unrevoke
- CSV export, API key rotation
- Server-side RSA signing (uses cryptography)
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

# -------- configuration (env overrideable) --------
DB_PATH = os.environ.get("DB_PATH", "revocations.db")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "change_me")
FLASK_SECRET = os.environ.get("FLASK_SECRET", secrets.token_hex(32))
API_KEY_HEADER = "X-API-KEY"
ADMIN_KEY = os.environ.get("ADMIN_KEY", "")  # legacy header admin key
WEBHOOK_URLS = [u.strip() for u in (os.environ.get("WEBHOOK_URLS") or "").split(",") if u.strip()]

PRIVATE_KEY_PATH = os.environ.get("PRIVATE_KEY_PATH", "server_private.pem")
PUBLIC_KEY_PATH = os.environ.get("PUBLIC_KEY_PATH", "server_public.pem")
SIGNED_DIR = os.environ.get("SIGNED_DIR", "signed_licenses")

app = Flask(__name__)
app.secret_key = FLASK_SECRET

# Ensure directories exist
_db_parent = Path(DB_PATH).parent
if str(_db_parent) not in (".", "") and not _db_parent.exists():
    _db_parent.mkdir(parents=True, exist_ok=True)
Path(SIGNED_DIR).mkdir(parents=True, exist_ok=True)

# -------- DB helpers --------
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
            status TEXT NOT NULL DEFAULT 'active',
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

# init DB at import-time
try:
    init_db()
except Exception:
    pass

# -------- auth helpers --------
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

# -------- utility --------
def generate_readable_license_id(prefix="LIC"):
    now = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    rnd = secrets.token_hex(3).upper()
    return f"{prefix}-{now}-{rnd}"

def notify_webhooks(payload: dict):
    for url in WEBHOOK_URLS:
        try:
            requests.post(url, json=payload, timeout=5)
        except Exception:
            try:
                log_activity("webhook_failed", {"url": url, "payload": payload})
            except Exception:
                pass

# -------- signing helpers --------
_private_key_obj = None
_public_key_obj = None

def _ensure_private_key():
    global _private_key_obj, _public_key_obj
    if _private_key_obj is not None:
        return
    if not _HAS_CRYPTO:
        raise RuntimeError("cryptography not available; install 'cryptography'")
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
    # Auto-generate
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
    except Exception as e:
        raise RuntimeError(f"Failed to write generated keys: {e}")

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

# -------- public endpoints --------
@app.route("/health")
def health():
    return jsonify({"ok": True})

@app.route("/status/<license_id>")
def status(license_id):
    now = datetime.now(timezone.utc).isoformat()
    with get_conn() as conn:
        row = conn.execute("SELECT license_id, status, revoked_at, revoked_reason FROM licenses WHERE license_id = ?", (license_id,)).fetchone()
    if row:
        return jsonify({"revoked": row["status"] == "revoked", "suspended": row["status"] == "suspended",
                        "license_id": row["license_id"], "revoked_at": row["revoked_at"],
                        "reason": row["revoked_reason"], "server_time": now})
    return jsonify({"revoked": False, "suspended": False, "license_id": license_id, "server_time": now})

# -------- programmatic admin APIs --------
@app.route("/revoke", methods=["POST"])
def revoke_api():
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

# -------- signing programmatic API --------
@app.route("/sign", methods=["POST"])
def sign_api():
    if not (session.get("admin_authenticated") or is_api_admin()):
        return jsonify({"error": "unauthorized"}), 401
    if not _HAS_CRYPTO:
        return jsonify({"error": "server missing cryptography support"}), 500
    data = request.get_json(force=True)
    hwid = data.get("hwid")
    email = data.get("email")
    expiry = data.get("expiry")
    features = data.get("features") or {"pro": True}
    lid = data.get("license_id") or generate_readable_license_id()
    now = datetime.now(timezone.utc).isoformat()
    lic = {"id": lid, "hwid": hwid, "email": email, "created_at": now, "expiry": expiry, "features": features}
    try:
        sig = sign_license_object(lic)
    except Exception as e:
        return jsonify({"error": f"signing failed: {e}"}), 500
    # save license row
    try:
        with get_conn() as conn:
            conn.execute("INSERT OR REPLACE INTO licenses (license_id, hwid, email, created_at, expiry, features, status) VALUES (?,?,?,?,?,?,?)",
                         (lid, hwid, email, now, expiry, json.dumps(features) if not isinstance(features, str) else features, "active"))
            conn.commit()
    except Exception:
        pass
    log_activity("sign", {"license_id": lid, "by": session.get("admin_user") or "api"})
    # support optional "save" flag in JSON to write file to SIGNED_DIR
    if data.get("save") in (True, "true", "1", 1):
        out_path = _signed_file_path(lid)
        out_obj = {"license": lic, "signature": sig}
        out_path.write_text(json.dumps(out_obj, indent=2, ensure_ascii=False), encoding="utf-8")
    return jsonify({"license": lic, "signature": sig})

# -------- signed file download (UI + API) --------
@app.route("/signed/download/<license_id>", methods=["GET"])
@login_required
def signed_download(license_id):
    """
    If a file exists in SIGNED_DIR, serve it.
    Otherwise regenerate signed JSON from DB and stream it (no persistent file).
    """
    path = _signed_file_path(license_id)
    if path.exists():
        return send_file(str(path), mimetype="application/json", as_attachment=True, download_name=path.name)
    # Regenerate from DB
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
    if not _HAS_CRYPTO:
        # return unsigned if no crypto available
        return jsonify({"license": lic})
    try:
        sig = sign_license_object(lic)
    except Exception as e:
        return abort(500, f"signing failed: {e}")
    out = {"license": lic, "signature": sig}
    data = json.dumps(out, indent=2, ensure_ascii=False)
    resp = make_response(data)
    resp.headers["Content-Type"] = "application/json"
    resp.headers["Content-Disposition"] = f"attachment; filename={license_id}.json"
    return resp

# -------- admin UI templates (login, dashboard with signed table, sign form) --------
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
.quick{background:#08121a;padding:12px;border-radius:8px;margin:12px 0}
.input{padding:8px;border-radius:6px;border:1px solid #123;background:#03121a;color:#dff;width:100%}
.card{background:#08121a;padding:12px;border-radius:10px;margin-top:12px}
.table{width:100%;border-collapse:collapse;margin-top:8px}
.table th,.table td{padding:8px;border-bottom:1px solid #0b394f;text-align:left}
.small{color:#9fb2c8}
</style></head><body>
<div class="header">
  <div><strong>License Management — Admin</strong></div>
  <div class="controls">
    <a class="btn" href="{{ url_for('export_csv') }}">Export CSV</a>
    <form method="post" action="{{ url_for('rotate_api_key_route') }}" style="display:inline"><button class="btn">Rotate API Key</button></form>
    <a class="btn" href="{{ url_for('logout') }}" style="background:#ff6b6b">Logout</a>
  </div>
</div>

<div class="quick">
  <form method="post" action="{{ url_for('admin_revoke') }}">
    <div style="display:flex;gap:8px;align-items:center">
      <div style="flex:1">
        <label class="small">Revoke license (enter exact ID)</label>
        <input name="license_id" class="input" placeholder="LIC-20251115-152911-ZS9CFZ" required>
      </div>
      <div style="width:280px">
        <label class="small">Reason (optional)</label>
        <input name="reason" class="input" placeholder="e.g. fraud detected">
      </div>
      <div style="width:120px"><label class="small">&nbsp;</label><button class="btn" type="submit" style="background:#ff6b6b">Revoke</button></div>
    </div>
  </form>
</div>

<div class="card">
  <h3>Signed licenses</h3>
  <div class="small">List of licenses (from database). Click Download to get the signed license JSON (served from server or generated on-the-fly).</div>
  {% if licenses %}
  <table class="table">
    <thead><tr><th>License ID</th><th>Email</th><th>HWID</th><th>Expiry</th><th>Status</th><th>Signed file</th></tr></thead>
    <tbody>
      {% for L in licenses %}
      <tr>
        <td><code>{{ L.license_id }}</code></td>
        <td>{{ L.email or '-' }}</td>
        <td>{{ L.hwid or '-' }}</td>
        <td>{{ L.expiry or '-' }}</td>
        <td>{{ L.status }}</td>
        <td>
          <a class="btn" href="{{ url_for('signed_download', license_id=L.license_id) }}">Download</a>
          {% if L.file_exists %}
            <span class="small">saved</span>
          {% else %}
            <span class="small">generated</span>
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

_SIGN_HTML = """
<!doctype html><html><head><meta charset="utf-8"><title>Sign License</title>
<style>
body{background:#071018;color:#e6f3ff;font-family:Inter,Arial;padding:12px}
.card{background:#08121a;padding:16px;border-radius:10px;max-width:820px;margin:20px auto}
.input{width:100%;padding:8px;margin:6px 0;border-radius:6px;background:#03121a;color:#dff;border:1px solid #123}
.btn{background:#17a2ff;color:#001;border:0;padding:8px 10px;border-radius:8px;cursor:pointer}
.small{color:#9fb2c8}
</style></head><body>
<div class="card">
  <h2>Server-side Sign License</h2>
  <form method="post" action="{{ url_for('admin_sign') }}">
    <label>License ID (optional)</label><input class="input" name="license_id" placeholder="Leave empty to auto-generate">
    <label>HWID</label><input class="input" name="hwid" placeholder="hardware id">
    <label>Email</label><input class="input" name="email" placeholder="buyer email">
    <label>Expiry (YYYY-MM-DD or ISO)</label><input class="input" name="expiry" placeholder="2026-01-01T12:00:00">
    <label>Features (JSON)</label><input class="input" name="features" placeholder='{"pro":true}'>
    <label>Save file on server?</label>
    <select name="save" class="input"><option value="no">No</option><option value="yes">Yes</option></select>
    <div style="display:flex;gap:8px;margin-top:8px"><button class="btn" type="submit">Sign</button> <a class="small" href="{{ url_for('admin') }}">Back</a></div>
  </form>
</div>
</body></html>
"""

# -------- admin routes --------
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
    q = request.args.get("q", "").strip()
    status_filter = request.args.get("status", "").strip()
    params = []
    sql = "SELECT license_id, hwid, email, expiry, status FROM licenses"
    conds = []
    if q:
        conds.append("(license_id LIKE ? OR email LIKE ? OR hwid LIKE ?)")
        params.extend([f"%{q}%"]*3)
    if status_filter:
        conds.append("status = ?"); params.append(status_filter)
    if conds:
        sql += " WHERE " + " AND ".join(conds)
    sql += " ORDER BY created_at DESC LIMIT 200"
    licenses = []
    with get_conn() as conn:
        rows = conn.execute(sql, params).fetchall()
        for r in rows:
            path = _signed_file_path(r["license_id"])
            licenses.append({
                "license_id": r["license_id"],
                "hwid": r["hwid"],
                "email": r["email"],
                "expiry": r["expiry"],
                "status": r["status"],
                "file_exists": path.exists()
            })
        activity = conn.execute("SELECT ts, event, details FROM activity_logs ORDER BY ts DESC LIMIT 40").fetchall()
    return render_template_string(_ADMIN_HTML, licenses=licenses, activity=activity)

@app.route("/admin/sign", methods=["GET", "POST"])
@login_required
def admin_sign():
    if request.method == "GET":
        return render_template_string(_SIGN_HTML)
    lid = request.form.get("license_id") or generate_readable_license_id()
    hwid = request.form.get("hwid") or None
    email = request.form.get("email") or None
    expiry = request.form.get("expiry") or None
    feats = request.form.get("features") or None
    if feats:
        try:
            feats_parsed = json.loads(feats)
        except Exception:
            flash("Features must be valid JSON"); return redirect(url_for("admin_sign"))
    else:
        feats_parsed = {"pro": True}
    now = datetime.now(timezone.utc).isoformat()
    lic = {"id": lid, "hwid": hwid, "email": email, "created_at": now, "expiry": expiry, "features": feats_parsed}
    if not _HAS_CRYPTO:
        flash("Server missing cryptography; cannot sign."); return redirect(url_for("admin"))
    try:
        sig = sign_license_object(lic)
    except Exception as e:
        flash(f"Signing failed: {e}"); return redirect(url_for("admin"))
    # save row
    try:
        with get_conn() as conn:
            conn.execute("INSERT OR REPLACE INTO licenses (license_id, hwid, email, created_at, expiry, features, status) VALUES (?,?,?,?,?,?,?)",
                         (lid, hwid, email, now, expiry, json.dumps(feats_parsed), "active"))
            conn.commit()
    except Exception:
        pass
    log_activity("sign", {"license_id": lid, "by": session.get("admin_user")})
    # Save file if requested
    if request.form.get("save") == "yes":
        out_path = _signed_file_path(lid)
        out_obj = {"license": lic, "signature": sig}
        out_path.write_text(json.dumps(out_obj, indent=2, ensure_ascii=False), encoding="utf-8")
        # Immediately serve the file as a download (auto-download)
        return redirect(url_for("signed_download", license_id=lid))
    # Otherwise return JSON in browser
    return jsonify({"license": lic, "signature": sig})

# quick revoke route
@app.route("/admin/revoke", methods=["POST"])
@login_required
def admin_revoke():
    license_id = (request.form.get("license_id") or "").strip()
    reason = (request.form.get("reason") or "revoked via admin UI").strip()
    if not license_id:
        flash("License ID required", "error")
        return redirect(url_for("admin"))
    now = datetime.now(timezone.utc)
    try:
        with get_conn() as conn:
            conn.execute("""
                INSERT INTO licenses (license_id, hwid, email, created_at, expiry, features, status, revoked_at, revoked_reason, revoked_by)
                VALUES (?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(license_id) DO UPDATE SET status='revoked', revoked_at=excluded.revoked_at, revoked_reason=excluded.revoked_reason, revoked_by=excluded.revoked_by
            """, (license_id, None, None, now, None, None, "revoked", now, reason, session.get("admin_user")))
            conn.commit()
    except Exception as e:
        log_activity("revoke_error", {"license_id": license_id, "error": str(e)})
        flash(f"Failed to revoke: {e}", "error")
        return redirect(url_for("admin"))
    try:
        log_activity("revoke", {"license_id": license_id, "reason": reason, "by": session.get("admin_user")})
    except Exception:
        pass
    try:
        notify_webhooks({"event": "revoke", "license_id": license_id, "reason": reason, "revoked_at": now.isoformat()})
    except Exception:
        pass
    flash(f"Revoked {license_id}", "ok")
    return redirect(url_for("admin"))

# rotate API key + export CSV
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

# -------- run server --------
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
