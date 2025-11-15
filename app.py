from flask import Flask, request, jsonify
from functools import wraps
import os
import sqlite3
from datetime import datetime, timezone
import hmac

DB_PATH = os.environ.get('DB_PATH', 'revocations.db')
ADMIN_KEY = os.environ.get('ADMIN_KEY', 'CHANGE_ME')  # Replace in Render
API_KEY_HEADER = 'X-API-KEY'

app = Flask(__name__)

# -------------------------------------------------
# DATABASE HELPERS
# -------------------------------------------------

def get_conn():
    c = sqlite3.connect(
        DB_PATH,
        detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES
    )
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


# -------------------------------------------------
# AUTH DECORATOR
# -------------------------------------------------

def require_admin(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        key = request.headers.get(API_KEY_HEADER) or request.args.get('admin_key')
        if not key or not hmac.compare_digest(key, ADMIN_KEY):
            return jsonify({'error': 'unauthorized'}), 401
        return fn(*args, **kwargs)
    return wrapper


# -------------------------------------------------
# ROUTES
# -------------------------------------------------

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
    """Admin: revoke license with reason."""
    data = request.get_json(force=True)
    lid = data.get('license_id')
    reason = data.get('reason')
    by = data.get('by', 'admin')

    if not lid:
        return jsonify({'error': 'license_id required'}), 400

    now = datetime.now(timezone.utc)

    with get_conn() as conn:
        conn.execute(
            'INSERT OR REPLACE INTO revocations (license_id, revoked_at, reason, revoked_by) VALUES (?,?,?,?)',
            (lid, now, reason, by)
        )
        conn.commit()

    return jsonify({
        'revoked': True,
        'license_id': lid,
        'revoked_at': now.isoformat(),
        'reason': reason
    })


@app.route('/unrevoke', methods=['POST'])
@require_admin
def unrevoke():
    """Admin: remove revocation."""
    data = request.get_json(force=True)
    lid = data.get('license_id')

    if not lid:
        return jsonify({'error': 'license_id required'}), 400

    with get_conn() as conn:
        conn.execute('DELETE FROM revocations WHERE license_id = ?', (lid,))
        conn.commit()

    return jsonify({'revoked': False, 'license_id': lid})


@app.route('/status/<license_id>')
def status(license_id):
    """Public: check if a license is revoked + get server UTC time."""
    now = datetime.now(timezone.utc)

    with get_conn() as conn:
        row = conn.execute(
            'SELECT license_id, revoked_at, reason, revoked_by FROM revocations WHERE license_id = ?',
            (license_id,)
        ).fetchone()

    if row:
        return jsonify({
            'revoked': True,
            'license_id': row['license_id'],
            'revoked_at': row['revoked_at'],
            'reason': row['reason'],
            'server_time': now.isoformat()
        })

    return jsonify({
        'revoked': False,
        'license_id': license_id,
        'server_time': now.isoformat()
    })


# -------------------------------------------------
# MAIN ENTRY
# -------------------------------------------------

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
