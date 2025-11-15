from flask import Flask, request, jsonify, abort
import os
import sqlite3
from datetime import datetime, timezone
import hmac

# ---------- CONFIG ----------
DB_PATH = os.environ.get("DB_PATH", "revocations.db")
ADMIN_KEY = os.environ.get("ADMIN_KEY", "")  # MUST set this in your environment before running
API_KEY_HEADER = "X-API-KEY"

app = Flask(__name__)

# ---------- DB helpers ----------
def get_conn():
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES|sqlite3.PARSE_COLNAMES)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_conn() as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS revocations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                license_id TEXT NOT NULL UNIQUE,
                revoked_at TEXT NOT NULL,
                reason TEXT,
                revoked_by TEXT
            )
        """)
        c.commit()

# initialize DB on import/run
try:
    init_db()
except Exception as e:
    print("DB init error:", e)

# ---------- auth ----------
def require_api_key(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        header = request.headers.get(API_KEY_HEADER, "")
        if not ADMIN_KEY:
            return jsonify({"error":"server not configured with ADMIN_KEY"}), 500
        # use constant-time compare
        if not hmac.compare_digest(header, ADMIN_KEY):
            return jsonify({"error":"unauthorized"}), 401
        return fn(*args, **kwargs)
    return wrapper

# ---------- endpoints ----------
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True})

@app.route("/revoke", methods=["POST"])
@require_api_key
def revoke():
    """
    Revoke a license.
    Body JSON: {"license_id": "...", "reason": "...", "by":"..."}
    """
    if not request.is_json:
        return jsonify({"error":"expected JSON body"}), 400
    data = request.get_json()
    lid = (data.get("license_id") or "").strip()
    if not lid:
        return jsonify({"error":"license_id required"}), 400
    reason = data.get("reason")
    by = data.get("by") or "admin"
    now = datetime.now(timezone.utc).isoformat()
    try:
        with get_conn() as conn:
            # insert or replace (keeps unique license_id)
            conn.execute("""
                INSERT INTO revocations (license_id, revoked_at, reason, revoked_by)
                VALUES (?,?,?,?)
                ON CONFLICT(license_id) DO UPDATE SET
                  revoked_at=excluded.revoked_at,
                  reason=excluded.reason,
                  revoked_by=excluded.revoked_by
            """, (lid, now, reason, by))
            conn.commit()
    except Exception as e:
        return jsonify({"error": f"db error: {e}"}), 500
    return jsonify({"revoked": True, "license_id": lid, "revoked_at": now, "reason": reason})

@app.route("/status/<license_id>", methods=["GET"])
def status(license_id):
    lid = license_id.strip()
    with get_conn() as conn:
        row = conn.execute("SELECT license_id, revoked_at, reason, revoked_by FROM revocations WHERE license_id = ?", (lid,)).fetchone()
    if not row:
        return jsonify({"license_id": lid, "revoked": False})
    return jsonify({
        "license_id": row["license_id"],
        "revoked": True,
        "revoked_at": row["revoked_at"],
        "reason": row["reason"],
        "revoked_by": row["revoked_by"]
    })

# ---------- run ----------
if __name__ == "__main__":
    if not ADMIN_KEY:
        print("Warning: ADMIN_KEY is not set. Set ADMIN_KEY env var to protect the revoke endpoint.")
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
