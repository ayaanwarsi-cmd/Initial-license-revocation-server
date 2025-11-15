# app.py
from flask import Flask, request, jsonify, render_template_string, redirect, url_for, flash, send_file
from functools import wraps
import os, sqlite3, hmac, hashlib, json, csv, io, secrets, base64, time
from datetime import datetime, timezone
import requests
from pathlib import Path

DB_PATH = os.environ.get('DB_PATH', 'revocations.db')
ADMIN_KEY = os.environ.get('ADMIN_KEY', None) or 'CHANGE_ME'  # rotate via UI
API_KEY_HEADER = 'X-API-KEY'
WEBHOOK_URLS = [u.strip() for u in (os.environ.get('WEBHOOK_URLS') or '').split(',') if u.strip()]

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET', secrets.token_hex(16))

# Ensure DB directory exists (if DB_PATH contains folders)
_db_parent = Path(DB_PATH).parent
if str(_db_parent) not in ('.', '') and not _db_parent.exists():
    try:
        _db_parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

# ---------- DB ----------
def get_conn():
    # Each call returns a fresh sqlite3 connection (safe per-thread)
    c = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES|sqlite3.PARSE_COLNAMES)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    """
    Create required tables if they don't exist.
    Safe to call multiple times.
    """
    with get_conn() as conn:
        conn.executescript('''
        CREATE TABLE IF NOT EXISTS revocations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            license_id TEXT NOT NULL UNIQUE,
            revoked_at TIMESTAMP NOT NULL,
            reason TEXT,
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
        ''')
        conn.commit()

def log_activity(event: str, details: dict | str = None):
    """
    Write an activity log. If the table is missing (OperationalError),
    attempt to init_db() and retry once rather than crashing the request.
    """
    try:
        with get_conn() as conn:
            conn.execute('INSERT INTO activity_logs (ts, event, details) VALUES (?,?,?)',
                         (datetime.now(timezone.utc), event, json.dumps(details) if details is not None else None))
            conn.commit()
    except sqlite3.OperationalError as e:
        # If missing table or DB not initialized, try to create schema and retry once
        if 'no such table' in str(e).lower():
            try:
                init_db()
                with get_conn() as conn:
                    conn.execute('INSERT INTO activity_logs (ts, event, details) VALUES (?,?,?)',
                                 (datetime.now(timezone.utc), event, json.dumps(details) if details is not None else None))
                    conn.commit()
                return
            except Exception:
                # fall through to raising the original error below
                pass
        raise

# Initialize DB at import time to avoid "no such table" on first requests
try:
    init_db()
except Exception:
    # if init fails, we still let app start and try again at runtime
    pass

# ---------- admin auth ----------
def _get_admin_key_from_request():
    key = request.headers.get(API_KEY_HEADER)
    if key:
        return key
    key = request.args.get('admin_key')
    if key:
        return key
    try:
        j = request.get_json(silent=True) or {}
        if isinstance(j, dict) and j.get('admin_key'):
            return j.get('admin_key')
    except Exception:
        pass
    if 'admin_key' in request.form:
        return request.form.get('admin_key')
    return None

def require_admin(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        key = _get_admin_key_from_request()
        if not key or not hmac.compare_digest(key, ADMIN_KEY):
            if request.is_json or request.path.startswith('/api') or request.path.startswith('/revoke') or request.path.startswith('/unrevoke'):
                return jsonify({'error': 'unauthorized'}), 401
            flash('Unauthorized: invalid admin key', 'error')
            return redirect(url_for('admin'))
        return fn(*args, **kwargs)
    return wrapper

# ---------- webhooks ----------
def notify_webhooks(payload: dict):
    for url in WEBHOOK_URLS:
        try:
            requests.post(url, json=payload, timeout=5)
        except Exception:
            # swallow — log in DB
            try:
                log_activity('webhook_failed', {'url': url, 'payload': payload})
            except Exception:
                pass

# ---------- API ----------
@app.route('/health')
def health():
    return jsonify({'ok': True})

@app.route('/time')
def server_time():
    now = datetime.now(timezone.utc)
    return jsonify({'server_time': now.isoformat()})

@app.route('/revoke', methods=['POST'])
@require_admin
def revoke():
    data = request.get_json(silent=True) or request.form or {}
    lid = data.get('license_id')
    reason = data.get('reason')
    by = data.get('by', 'admin')
    if not lid:
        return jsonify({'error': 'license_id required'}), 400
    now = datetime.now(timezone.utc)
    with get_conn() as conn:
        conn.execute('INSERT OR REPLACE INTO revocations (license_id, revoked_at, reason, revoked_by) VALUES (?,?,?,?)',
                     (lid, now, reason, by))
        conn.commit()
    # log and webhook (resilient)
    try:
        log_activity('revoke', {'license_id': lid, 'reason': reason, 'by': by})
    except Exception:
        pass
    try:
        notify_webhooks({'event': 'revoke', 'license_id': lid, 'reason': reason, 'revoked_at': now.isoformat()})
    except Exception:
        pass
    return jsonify({'revoked': True, 'license_id': lid, 'revoked_at': now.isoformat(), 'reason': reason})

@app.route('/unrevoke', methods=['POST'])
@require_admin
def unrevoke():
    data = request.get_json(silent=True) or request.form or {}
    lid = data.get('license_id')
    by = data.get('by', 'admin')
    if not lid:
        return jsonify({'error': 'license_id required'}), 400
    with get_conn() as conn:
        conn.execute('DELETE FROM revocations WHERE license_id = ?', (lid,))
        conn.commit()
    try:
        log_activity('unrevoke', {'license_id': lid, 'by': by})
    except Exception:
        pass
    try:
        notify_webhooks({'event': 'unrevoke', 'license_id': lid, 'by': by, 'time': datetime.now(timezone.utc).isoformat()})
    except Exception:
        pass
    return jsonify({'revoked': False, 'license_id': lid})

@app.route('/status/<license_id>')
def status(license_id):
    now = datetime.now(timezone.utc)
    with get_conn() as conn:
        r = conn.execute('SELECT license_id, revoked_at, reason, revoked_by FROM revocations WHERE license_id = ?', (license_id,)).fetchone()
    if r:
        return jsonify({'revoked': True, 'license_id': r['license_id'], 'revoked_at': r['revoked_at'], 'reason': r['reason'], 'server_time': now.isoformat()})
    return jsonify({'revoked': False, 'license_id': license_id, 'server_time': now.isoformat()})

# ---------- API key management ----------
def _hash_key(k: str) -> str:
    return hashlib.sha256(k.encode('utf-8')).hexdigest()

@app.route('/api/keys/rotate', methods=['POST'])
@require_admin
def rotate_api_key_route():
    # generate new key and store hash; return plaintext once
    new_key = secrets.token_hex(32)
    key_id = secrets.token_hex(8)
    now = datetime.now(timezone.utc)
    with get_conn() as conn:
        conn.execute('INSERT INTO api_keys (key_id, key_hash, created_at, revoked) VALUES (?,?,?,0)', (key_id, _hash_key(new_key), now))
        conn.commit()
    try:
        log_activity('api_key_rotated', {'key_id': key_id})
    except Exception:
        pass
    return jsonify({'key_id': key_id, 'key': new_key})

@app.route('/admin/export.csv')
@require_admin
def export_csv():
    sio = io.StringIO()
    w = csv.writer(sio)
    w.writerow(['revocations'])
    w.writerow(['license_id','revoked_at','reason','revoked_by'])
    with get_conn() as conn:
        for r in conn.execute('SELECT license_id, revoked_at, reason, revoked_by FROM revocations ORDER BY revoked_at DESC'):
            w.writerow([r['license_id'], r['revoked_at'], r['reason'], r['revoked_by']])
    w.writerow([])
    w.writerow(['activity_logs'])
    w.writerow(['ts','event','details'])
    with get_conn() as conn:
        for r in conn.execute('SELECT ts, event, details FROM activity_logs ORDER BY ts DESC'):
            w.writerow([r['ts'], r['event'], r['details']])
    sio.seek(0)
    return send_file(io.BytesIO(sio.getvalue().encode('utf-8')), mimetype='text/csv', download_name='revocations_activity.csv', as_attachment=True)

# ---------- Admin UI ----------
ADMIN_HTML = """<!doctype html><html><head><meta charset="utf-8"><title>Admin</title>
<style>body{font-family:Arial;background:#071018;color:#dfe;} .card{max-width:980px;margin:24px auto;padding:18px;background:#08121a;border-radius:8px} input,textarea,select{width:100%;padding:8px;margin:6px 0;border-radius:6px;background:#02121a;color:#dfe;border:1px solid #233} table{width:100%;border-collapse:collapse;margin-top:12px}th,td{padding:8px;border-bottom:1px solid #123;text-align:left}</style>
</head><body><div class="card">
<h2>Revocation Admin</h2>
{% with messages = get_flashed_messages(with_categories=true) %}
  {% if messages %}{% for cat,msg in messages %}<div style="padding:8px;background:#222;margin-bottom:8px;border-radius:6px">{{msg}}</div>{% endfor %}{% endif %}
{% endwith %}
<form method="post" action="{{ url_for('admin_action') }}">
<label>ADMIN KEY (paste)</label><input name="admin_key" required>
<label>License ID</label><input name="license_id" placeholder="e.g. LIC-...">
<label>Reason</label><textarea name="reason"></textarea>
<div style="display:flex;gap:8px"><button name="action" value="revoke">Revoke</button><button name="action" value="unrevoke">Unrevoke</button><button name="action" value="list">List</button></div>
</form>

<h3>Search revocations</h3>
<form method="get" action="{{ url_for('admin') }}">
<label>license_id contains</label><input name="q" value="{{ request.args.get('q','') }}">
<label>since (YYYY-MM-DD)</label><input name="since" value="{{ request.args.get('since','') }}">
<button formaction="{{ url_for('admin') }}" formmethod="get">Search</button>
<a href="{{ url_for('export_csv') }}">Download CSV</a> |
<form method="post" action="{{ url_for('rotate_api_key') }}" style="display:inline;"><input type="hidden" name="admin_key" value="{{ request.args.get('admin_key','') }}"><button type="submit">Rotate API Key</button></form>
<hr>
{% if revocations %}
  <table><thead><tr><th>License ID</th><th>Reason</th><th>Revoked At</th><th>By</th></tr></thead><tbody>
  {% for r in revocations %}
    <tr><td>{{ r['license_id'] }}</td><td>{{ r['reason'] }}</td><td>{{ r['revoked_at'] }}</td><td>{{ r['revoked_by'] }}</td></tr>
  {% endfor %}</tbody></table>
{% endif %}
</div></body></html>
"""

@app.route('/admin', methods=['GET'])
def admin():
    q = request.args.get('q','').strip()
    since = request.args.get('since','').strip()
    revs = []
    sql = 'SELECT license_id, reason, revoked_at, revoked_by FROM revocations'
    params = []
    conds = []
    if q:
        conds.append("license_id LIKE ?")
        params.append(f"%{q}%")
    if since:
        conds.append("date(revoked_at) >= date(?)")
        params.append(since)
    if conds:
        sql += ' WHERE ' + ' AND '.join(conds)
    sql += ' ORDER BY revoked_at DESC LIMIT 200'
    with get_conn() as conn:
        for r in conn.execute(sql, params):
            revs.append(dict(r))
    return render_template_string(ADMIN_HTML, revocations=revs)

@app.route('/admin/action', methods=['POST'])
def admin_action():
    action = request.form.get('action')
    key = _get_admin_key_from_request()
    if not key or not hmac.compare_digest(key, ADMIN_KEY):
        flash('Unauthorized', 'error'); return redirect(url_for('admin'))
    license_id = request.form.get('license_id') or ''
    reason = request.form.get('reason') or ''
    if action == 'revoke':
        now = datetime.now(timezone.utc)
        with get_conn() as conn:
            conn.execute('INSERT OR REPLACE INTO revocations (license_id, revoked_at, reason, revoked_by) VALUES (?,?,?,?)', (license_id, now, reason, 'web-admin'))
            conn.commit()
        try:
            log_activity('revoke', {'license_id': license_id, 'reason': reason})
        except Exception:
            pass
        try:
            notify_webhooks({'event':'revoke','license_id':license_id,'reason':reason,'revoked_at':now.isoformat()})
        except Exception:
            pass
        flash(f"Revoked {license_id}", 'ok'); return redirect(url_for('admin', admin_key=key))
    if action == 'unrevoke':
        with get_conn() as conn:
            conn.execute('DELETE FROM revocations WHERE license_id = ?', (license_id,))
            conn.commit()
        try:
            log_activity('unrevoke', {'license_id': license_id})
        except Exception:
            pass
        try:
            notify_webhooks({'event':'unrevoke','license_id':license_id})
        except Exception:
            pass
        flash(f"Unrevoked {license_id}", 'ok'); return redirect(url_for('admin', admin_key=key))
    flash('Unknown action', 'error'); return redirect(url_for('admin'))

if __name__ == '__main__':
    # When run directly, ensure DB exists and start Flask for local debugging.
    init_db()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
