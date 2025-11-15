from flask import Flask, request, jsonify, render_template_string, redirect, url_for, flash
from functools import wraps
import os
import sqlite3
from datetime import datetime, timezone
import hmac

DB_PATH = os.environ.get('DB_PATH', 'revocations.db')
ADMIN_KEY = os.environ.get('ADMIN_KEY', 'CHANGE_ME')  # replace in Render env
API_KEY_HEADER = 'X-API-KEY'

app = Flask(__name__)
# secret key used by Flask to flash messages in admin UI; not security-critical here
app.secret_key = os.environ.get('FLASK_SECRET', 'dev-secret-for-flash')

# ------------- DB helpers -------------
def get_conn():
    c = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES)
    c.row_factory = sqlite3.Row
    return c

def init_db():
    with get_conn() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS revocations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                license_id TEXT NOT NULL UNIQUE,
                revoked_at TIMESTAMP NOT NULL,
                reason TEXT,
                revoked_by TEXT
            )
        ''')
        conn.commit()

# ------------- admin check (accept header, query, json body, or form) -------------
def _get_admin_key_from_request():
    # priority: header -> query param -> json body -> form field
    key = request.headers.get(API_KEY_HEADER)
    if key:
        return key
    key = request.args.get('admin_key')
    if key:
        return key
    # json body (if any)
    try:
        j = request.get_json(silent=True) or {}
        if isinstance(j, dict) and j.get('admin_key'):
            return j.get('admin_key')
    except Exception:
        pass
    # form (from admin panel)
    if 'admin_key' in request.form:
        return request.form.get('admin_key')
    return None

def require_admin(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        key = _get_admin_key_from_request()
        if not key or not hmac.compare_digest(key, ADMIN_KEY):
            # if JSON/REST call, return JSON 401
            if request.is_json or request.path.startswith('/api') or request.path.startswith('/revoke') or request.path.startswith('/unrevoke'):
                return jsonify({'error': 'unauthorized'}), 401
            # otherwise, for admin UI, redirect to admin page with flash
            flash('Unauthorized: invalid admin key', 'error')
            return redirect(url_for('admin'))
        return fn(*args, **kwargs)
    return wrapper

# ------------- Routes -------------
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
    """Admin API: revoke license with reason (JSON or form)."""
    data = request.get_json(silent=True) or request.form or {}
    lid = data.get('license_id')
    reason = data.get('reason')
    by = data.get('by', 'admin')
    if not lid:
        return jsonify({'error': 'license_id required'}), 400
    now = datetime.now(timezone.utc)
    with get_conn() as conn:
        conn.execute('INSERT OR REPLACE INTO revocations (license_id, revoked_at, reason, revoked_by) VALUES (?,?,?,?)', (lid, now, reason, by))
        conn.commit()
    return jsonify({'revoked': True, 'license_id': lid, 'revoked_at': now.isoformat(), 'reason': reason})

@app.route('/unrevoke', methods=['POST'])
@require_admin
def unrevoke():
    data = request.get_json(silent=True) or request.form or {}
    lid = data.get('license_id')
    if not lid:
        return jsonify({'error': 'license_id required'}), 400
    with get_conn() as conn:
        conn.execute('DELETE FROM revocations WHERE license_id = ?', (lid,))
        conn.commit()
    return jsonify({'revoked': False, 'license_id': lid})

@app.route('/status/<license_id>')
def status(license_id):
    now = datetime.now(timezone.utc)
    with get_conn() as conn:
        r = conn.execute('SELECT license_id, revoked_at, reason, revoked_by FROM revocations WHERE license_id = ?', (license_id,)).fetchone()
    if r:
        return jsonify({'revoked': True, 'license_id': r['license_id'], 'revoked_at': r['revoked_at'], 'reason': r['reason'], 'server_time': now.isoformat()})
    return jsonify({'revoked': False, 'license_id': license_id, 'server_time': now.isoformat()})

# ---------------- Admin panel UI ----------------
ADMIN_HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>License Revocation — Admin</title>
  <style>
    body { font-family: Arial, Helvetica, sans-serif; margin: 28px; background:#0b0f10; color:#dfe; }
    .card { background:#08121a; padding:20px; border-radius:8px; max-width:720px; margin:0 auto; box-shadow:0 2px 10px rgba(0,0,0,0.6); }
    input[type=text], textarea { width:100%; padding:8px; margin:6px 0 12px 0; border-radius:4px; border:1px solid #234; background:#021; color:#dfe; }
    label { font-weight:bold; display:block; margin-top:8px; }
    .row { display:flex; gap:10px; }
    .row > * { flex:1; }
    button { padding:10px 14px; border-radius:6px; border:0; cursor:pointer; background:#06a; color:#001; font-weight:bold; }
    .small { font-size:0.9rem; color:#9cffb2; }
    .flash { padding:8px; margin-bottom:10px; border-radius:6px; }
    .flash.error { background:#3b0c0c; color:#ffb2b2; }
    .flash.ok { background:#083b10; color:#bff0c8; }
    table { width:100%; border-collapse:collapse; margin-top:16px; }
    th, td { padding:8px; border-bottom:1px solid #123; text-align:left; }
  </style>
</head>
<body>
  <div class="card">
    <h2>License Revocation — Admin Panel</h2>
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
        {% for cat, msg in messages %}
          <div class="flash {{cat}}">{{msg}}</div>
        {% endfor %}
      {% endif %}
    {% endwith %}

    <form method="post" action="{{ url_for('admin_action') }}">
      <label>ADMIN KEY (paste here)</label>
      <input type="text" name="admin_key" placeholder="paste ADMIN_KEY" required>

      <label>License ID</label>
      <input type="text" name="license_id" placeholder="e.g. LIC-1234" required>

      <label>Reason (for revocation)</label>
      <textarea name="reason" rows="3" placeholder="Reason for revocation (optional)"></textarea>

      <div class="row">
        <button type="submit" name="action" value="revoke">Revoke</button>
        <button type="submit" name="action" value="unrevoke">Unrevoke</button>
        <button type="submit" name="action" value="list">List Revocations</button>
      </div>
    </form>

    {% if revocations is defined and revocations %}
      <h3 style="margin-top:20px;">Recent revocations</h3>
      <table>
        <thead><tr><th>License ID</th><th>Reason</th><th>Revoked At (UTC)</th><th>By</th></tr></thead>
        <tbody>
        {% for r in revocations %}
          <tr>
            <td>{{ r['license_id'] }}</td>
            <td>{{ r['reason'] or '' }}</td>
            <td>{{ r['revoked_at'] }}</td>
            <td>{{ r['revoked_by'] or '' }}</td>
          </tr>
        {% endfor %}
        </tbody>
      </table>
    {% endif %}
    <p class="small">This admin page uses your ADMIN_KEY. Keep it secret. Calls made here are server-side and protected.</p>
  </div>
</body>
</html>
"""

@app.route('/admin', methods=['GET'])
def admin():
    # render empty admin page (no revocations shown)
    return render_template_string(ADMIN_HTML)

@app.route('/admin/action', methods=['POST'])
def admin_action():
    # this endpoint uses require_admin() to perform actions, but we need to extract admin_key first
    # the require_admin decorator expects the key available via header/query/json/form, so form works
    action = request.form.get('action')
    # validate admin key via decorator wrapper call manually for nicer flash behavior
    key = _get_admin_key_from_request()
    if not key or not hmac.compare_digest(key, ADMIN_KEY):
        flash('Unauthorized: invalid ADMIN_KEY', 'error')
        return redirect(url_for('admin'))

    license_id = request.form.get('license_id')
    reason = request.form.get('reason') or ''

    if action == 'revoke':
        now = datetime.now(timezone.utc)
        with get_conn() as conn:
            conn.execute('INSERT OR REPLACE INTO revocations (license_id, revoked_at, reason, revoked_by) VALUES (?,?,?,?)', (license_id, now, reason, 'web-admin'))
            conn.commit()
        flash(f"Revoked {license_id}", 'ok')
        return redirect(url_for('admin'))

    if action == 'unrevoke':
        with get_conn() as conn:
            conn.execute('DELETE FROM revocations WHERE license_id = ?', (license_id,))
            conn.commit()
        flash(f"Unrevoked {license_id}", 'ok')
        return redirect(url_for('admin'))

    if action == 'list':
        with get_conn() as conn:
            rows = conn.execute('SELECT license_id, revoked_at, reason, revoked_by FROM revocations ORDER BY revoked_at DESC LIMIT 200').fetchall()
        # convert rows to list of dicts for template
        revs = [dict(r) for r in rows]
        return render_template_string(ADMIN_HTML, revocations=revs)

    flash('Unknown action', 'error')
    return redirect(url_for('admin'))

# ------------- Startup -------------
if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
