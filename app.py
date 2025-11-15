# app.py
"""
License Revocation & Management Server with Admin Login Dashboard and Server-side Signing
- Admin UI (login) + API endpoints
- Licenses table (create/edit/suspend/revoke/unrevoke)
- Server-side signing endpoint (/admin/sign and /sign)
- CSV export, activity logs, API key rotation
"""

from flask import (
    Flask, request, jsonify, render_template_string, redirect, url_for, flash,
    send_file, session, abort, make_response
)
from functools import wraps
import os, sqlite3, hmac, hashlib, json, csv, io, secrets, base64, time
from datetime import datetime, timezone
from pathlib import Path
import requests
from werkzeug.security import generate_password_hash, check_password_hash

# cryptography for signing
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.hazmat.primitives import serialization as crypto_serialization
    _HAS_CRYPTO = True
except Exception:
    _HAS_CRYPTO = False

# ---------------- Config ----------------
DB_PATH = os.environ.get("DB_PATH", "revocations.db")
ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("ADMIN_PASS", "change_me")  # plain; hashed at startup
FLASK_SECRET = os.environ.get("FLASK_SECRET", secrets.token_hex(32))
API_KEY_HEADER = "X-API-KEY"
ADMIN_KEY = os.environ.get("ADMIN_KEY", "")  # legacy/key for API header
WEBHOOK_URLS = [u.strip() for u in (os.environ.get("WEBHOOK_URLS") or "").split(",") if u.strip()]

# signing key config
PRIVATE_KEY_PATH = os.environ.get("PRIVATE_KEY_PATH", "server_private.pem")
PUBLIC_KEY_PATH = os.environ.get("PUBLIC_KEY_PATH", "server_public.pem")
SIGNED_DIR = os.environ.get("SIGNED_DIR", "signed_licenses")

app = Flask(__name__)
app.secret_key = FLASK_SECRET

# Ensure DB parent exists (if DB_PATH contains directories)
_db_parent = Path(DB_PATH).parent
if str(_db_parent) not in (".", "") and not _db_parent.exists():
    try:
        _db_parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

# Ensure signed dir exists
try:
    Path(SIGNED_DIR).mkdir(parents=True, exist_ok=True)
except Exception:
    pass

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

# Initialize DB (import-time)
try:
    init_db()
except Exception:
    pass

# ---------------- Auth helpers ----------------
_ADMIN_PASS_HASH = generate_password_hash(ADMIN_PASS)

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

# ---------------- Utilities ----------------
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

# ---------------- Signing helpers ----------------
_private_key_obj = None
_public_key_obj = None

def _ensure_private_key():
    """
    Load private key object into _private_key_obj and public into _public_key_obj.
    Auto-generate a keypair if none found and cryptography is available.
    """
    global _private_key_obj, _public_key_obj
    if _private_key_obj is not None:
        return
    if not _HAS_CRYPTO:
        raise RuntimeError("cryptography library not available; install 'cryptography' to enable signing")
    priv_path = Path(PRIVATE_KEY_PATH)
    pub_path = Path(PUBLIC_KEY_PATH)
    if priv_path.exists():
        data = priv_path.read_bytes()
        _private_key_obj = serialization.load_pem_private_key(data, password=None)
        # load public if available
        if pub_path.exists():
            try:
                _public_key_obj = serialization.load_pem_public_key(pub_path.read_bytes())
            except Exception:
                _public_key_obj = _private_key_obj.public_key()
        else:
            _public_key_obj = _private_key_obj.public_key()
        return
    # auto-generate (only if key doesn't exist) — warn in logs
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
        raise RuntimeError(f"Failed to write generated key files: {e}")

def sign_license_object(lic_obj: dict) -> str:
    """
    Sign canonical JSON of license object and return base64 signature.
    """
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

def export_public_key_pem() -> bytes:
    _ensure_private_key()
    return _public_key_obj.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

# ---------------- Public API endpoints ----------------
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

# ---------------- Programmatic admin API ----------------
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

# ---------------- Signing API ----------------
@app.route("/sign", methods=["POST"])
def sign_api():
    """
    Programmatic signing endpoint.
    JSON body: { "hwid": "...", "email": "...", "expiry": "2026-01-01T12:00:00", "features": {...}, "license_id": optional }
    Returns: { "license": {...}, "signature": "..." }
    Protected: session admin OR API key header.
    """
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
    # optionally save to licenses table as active
    try:
        with get_conn() as conn:
            conn.execute("INSERT OR REPLACE INTO licenses (license_id, hwid, email, created_at, expiry, features, status) VALUES (?,?,?,?,?,?,?)",
                         (lid, hwid, email, now, expiry, json.dumps(features) if not isinstance(features, str) else features, "active"))
            conn.commit()
    except Exception:
        pass
    log_activity("sign", {"license_id": lid, "by": session.get("admin_user") or "api"})
    # return signed license object
    return jsonify({"license": lic, "signature": sig})

# ---------------- Admin web UI templates (unchanged parts omitted for brevity) ----------------
# For full admin UI templates, reuse previous templates; below we add the sign form template.

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

# We'll use the same admin login/dashboard templates from previous iteration.
# To avoid duplicating the long styling templates here, import them from a small helper if present,
# otherwise provide simple placeholders for admin and login pages. For completeness we include minimal login/admin
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

# Minimal admin dashboard (we'll include links to Sign and Export)
_ADMIN_SIMPLE = """
<!doctype html><html><head><meta charset="utf-8"><title>Admin Dashboard</title>
<style>body{background:#071018;color:#e6f3ff;font-family:Inter,Arial;padding:12px} a{color:#9fd}</style></head>
<body>
<h2>Admin</h2>
<div><a href="{{ url_for('admin_sign') }}">Sign license</a> | <a href="{{ url_for('export_csv') }}">Export CSV</a> | <a href="{{ url_for('logout') }}">Logout</a></div>
<hr>
<h3>Recent activity</h3>
<ul>
{% for a in activity %}
  <li>{{ a.ts }} — {{ a.event }} — {{ a.details }}</li>
{% endfor %}
</ul>
</body></html>
"""

# ---------------- Admin routes (login, dashboard, sign) ----------------
@app.route("/admin/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        # allow either check_hash or raw fallback (compat)
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
    with get_conn() as conn:
        activity = conn.execute("SELECT ts, event, details FROM activity_logs ORDER BY ts DESC LIMIT 40").fetchall()
    return render_template_string(_ADMIN_SIMPLE, activity=activity)

@app.route("/admin/sign", methods=["GET", "POST"])
@login_required
def admin_sign():
    if request.method == "GET":
        return render_template_string(_SIGN_HTML)
    # POST: gather fields and sign
    lid = request.form.get("license_id") or generate_readable_license_id()
    hwid = request.form.get("hwid") or None
    email = request.form.get("email") or None
    expiry = request.form.get("expiry") or None
    feats = request.form.get("features") or None
    if feats:
        try:
            feats_parsed = json.loads(feats)
        except Exception:
            flash("Features must be valid JSON")
            return redirect(url_for("admin_sign"))
    else:
        feats_parsed = {"pro": True}
    now = datetime.now(timezone.utc).isoformat()
    lic = {"id": lid, "hwid": hwid, "email": email, "created_at": now, "expiry": expiry, "features": feats_parsed}
    if not _HAS_CRYPTO:
        flash("Server missing cryptography library; cannot sign.")
        return redirect(url_for("admin"))
    try:
        sig = sign_license_object(lic)
    except Exception as e:
        flash(f"Signing failed: {e}")
        return redirect(url_for("admin"))
    # save to DB
    try:
        with get_conn() as conn:
            conn.execute("INSERT OR REPLACE INTO licenses (license_id, hwid, email, created_at, expiry, features, status) VALUES (?,?,?,?,?,?,?)",
                         (lid, hwid, email, now, expiry, json.dumps(feats_parsed), "active"))
            conn.commit()
    except Exception:
        pass
    log_activity("sign", {"license_id": lid, "by": session.get("admin_user")})
    # optional save file
    if request.form.get("save") == "yes":
        out_path = Path(SIGNED_DIR) / f"{lid}.json"
        out_obj = {"license": lic, "signature": sig}
        out_path.write_text(json.dumps(out_obj, indent=2, ensure_ascii=False), encoding="utf-8")
        flash(f"Signed and saved to {out_path}")
        # return the file for download
        resp = make_response(json.dumps(out_obj, indent=2, ensure_ascii=False))
        resp.headers["Content-Type"] = "application/json"
        resp.headers["Content-Disposition"] = f"attachment; filename={lid}.json"
        return resp
    # otherwise show JSON in browser
    return jsonify({"license": lic, "signature": sig})

# ---------------- Export / rotate endpoints (unchanged) ----------------
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

# ---------------- Run ----------------
if __name__ == "__main__":
    # Ensure private key exists (or auto-generate when possible)
    if _HAS_CRYPTO:
        try:
            _ensure_private_key()
        except Exception as e:
            print("Warning: private key could not be loaded/generated:", e)
    else:
        print("cryptography not installed; signing endpoints disabled.")
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
