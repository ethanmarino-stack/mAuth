from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
import sqlite3
import bcrypt
import uuid
import time
import re
from functools import wraps
import logging

app = Flask(__name__)
CORS(app)

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# -------------------------
# Localhost protection decorator
# -------------------------
def require_localhost(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.remote_addr != '127.0.0.1':
            return "Access Denied", 403
        return f(*args, **kwargs)
    return decorated_function

# -------------------------
# DB Helper
# -------------------------
def get_db():
    conn = sqlite3.connect("database.db")
    conn.row_factory = sqlite3.Row
    return conn

# -------------------------
# HWID NORMALIZER
# -------------------------
def normalize_hwid(hwid):
    if hwid is None:
        return ""
    normalized = re.sub(r'\s+', '', str(hwid)).strip().upper()
    normalized = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', normalized)
    return normalized

def normalize_string(s):
    if s is None:
        return ""
    return str(s).strip()

# -------------------------
# VERSION ENDPOINT
# -------------------------
@app.route("/get_version", methods=["GET"])
def get_version():
    conn = get_db()
    cur = conn.cursor()
    
    cur.execute("CREATE TABLE IF NOT EXISTS version (id INTEGER PRIMARY KEY, version TEXT, download_url TEXT, changelog TEXT, force_update BOOLEAN, updated_at INTEGER)")
    cur.execute("SELECT * FROM version WHERE id = 1")
    version_info = cur.fetchone()
    
    if not version_info:
        cur.execute("INSERT INTO version (id, version, download_url, changelog, force_update, updated_at) VALUES (1, '1.0.0', '', 'Initial release', 0, ?)", (int(time.time()),))
        conn.commit()
        version_info = cur.execute("SELECT * FROM version WHERE id = 1").fetchone()
    
    conn.close()
    
    return jsonify({
        "status": "ok",
        "version": version_info["version"],
        "download_url": version_info["download_url"] or "",
        "changelog": version_info["changelog"] or "",
        "force_update": bool(version_info["force_update"])
    })

# -------------------------
# LOGIN
# -------------------------
@app.route("/login", methods=["POST"])
def login():
    data = request.json or {}
    username = normalize_string(data.get("username"))
    password = normalize_string(data.get("password"))
    client_hwid = normalize_hwid(data.get("hwid"))
    
    if not username or not password:
        return jsonify({"status": "fail", "message": "Username and password required"})
    
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id, password_hash, hwid FROM users WHERE username=?", (username,))
    row = cur.fetchone()
    
    if not row:
        conn.close()
        return jsonify({"status": "fail", "message": "Invalid credentials"})
    
    stored_hash = row["password_hash"]
    if not bcrypt.checkpw(password.encode(), stored_hash):
        conn.close()
        return jsonify({"status": "fail", "message": "Invalid credentials"})
    
    stored_hwid = normalize_hwid(row["hwid"]) if row["hwid"] else ""
    user_id = row["id"]
    
    if not stored_hwid:
        cur.execute("UPDATE users SET hwid=? WHERE id=?", (client_hwid, user_id))
        conn.commit()
        stored_hwid = client_hwid
    
    if stored_hwid != client_hwid:
        conn.close()
        return jsonify({"status": "hwid_mismatch", "message": "Hardware ID mismatch"})
    
    cur.execute("DELETE FROM sessions WHERE username=?", (username,))
    token = str(uuid.uuid4())
    now = int(time.time())
    expires = now + 3600
    
    cur.execute("INSERT INTO sessions (token, username, user_id, hwid, expires, last_seen, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)", 
                (token, username, user_id, client_hwid, expires, now, now))
    conn.commit()
    conn.close()
    
    return jsonify({"status": "ok", "token": token, "username": username, "expires": expires, "uid": str(user_id)})

# -------------------------
# REGISTER
# -------------------------
@app.route("/register", methods=["POST"])
def register():
    data = request.json or {}
    username = normalize_string(data.get("username"))
    password = normalize_string(data.get("password"))
    license_key = normalize_string(data.get("license_key"))
    client_hwid = normalize_hwid(data.get("hwid"))
    
    if not username or not password or not license_key:
        return jsonify({"status": "fail", "message": "Username, password, and license key required"})
    
    if len(username) < 3 or len(username) > 20:
        return jsonify({"status": "fail", "message": "Username must be 3-20 characters"})
    
    if len(password) < 4:
        return jsonify({"status": "fail", "message": "Password must be at least 4 characters"})
    
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE username=?", (username,))
    if cur.fetchone():
        conn.close()
        return jsonify({"status": "fail", "message": "Username already exists"})
    
    cur.execute("SELECT id, used FROM licenses WHERE license_key=? AND used=0", (license_key,))
    license_row = cur.fetchone()
    if not license_row:
        conn.close()
        return jsonify({"status": "fail", "message": "Invalid or already used license key"})
    
    cur.execute("UPDATE licenses SET used=1, used_by=?, used_at=? WHERE license_key=?", (username, int(time.time()), license_key))
    
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    cur.execute("INSERT INTO users (username, password_hash, hwid, created_at, license_key) VALUES (?, ?, ?, ?, ?)", 
                (username, password_hash, client_hwid, int(time.time()), license_key))
    
    token = str(uuid.uuid4())
    now = int(time.time())
    expires = now + 3600
    user_id = cur.lastrowid
    
    cur.execute("INSERT INTO sessions (token, username, user_id, hwid, expires, last_seen, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)", 
                (token, username, user_id, client_hwid, expires, now, now))
    conn.commit()
    conn.close()
    
    return jsonify({"status": "ok", "token": token, "username": username, "expires": expires, "uid": str(user_id)})

# -------------------------
# HEARTBEAT
# -------------------------
@app.route("/heartbeat", methods=["POST"])
def heartbeat():
    data = request.json or {}
    token = normalize_string(data.get("token"))
    client_hwid = normalize_hwid(data.get("hwid"))
    
    if not token:
        return jsonify({"status": "invalid"})
    
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT username, hwid, expires FROM sessions WHERE token=?", (token,))
    row = cur.fetchone()
    
    if not row:
        conn.close()
        return jsonify({"status": "invalid"})
    
    stored_hwid = normalize_hwid(row["hwid"])
    expires = row["expires"]
    now = int(time.time())
    
    if now > expires:
        cur.execute("DELETE FROM sessions WHERE token=?", (token,))
        conn.commit()
        conn.close()
        return jsonify({"status": "expired"})
    
    if stored_hwid != client_hwid:
        conn.close()
        return jsonify({"status": "hwid_mismatch"})
    
    cur.execute("UPDATE sessions SET last_seen=?, expires=? WHERE token=?", (now, now + 3600, token))
    conn.commit()
    conn.close()
    
    return jsonify({"status": "ok"})

# -------------------------
# VALIDATE SESSION
# -------------------------
@app.route("/validate", methods=["POST"])
def validate_session():
    data = request.json or {}
    token = normalize_string(data.get("token"))
    client_hwid = normalize_hwid(data.get("hwid"))
    
    if not token:
        return jsonify({"status": "invalid"})
    
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT username, hwid, expires, last_seen FROM sessions WHERE token=?", (token,))
    row = cur.fetchone()
    
    if not row:
        conn.close()
        return jsonify({"status": "invalid"})
    
    stored_hwid = normalize_hwid(row["hwid"])
    expires = row["expires"]
    last_seen = row["last_seen"]
    now = int(time.time())
    
    if now > expires:
        cur.execute("DELETE FROM sessions WHERE token=?", (token,))
        conn.commit()
        conn.close()
        return jsonify({"status": "expired"})
    
    if stored_hwid != client_hwid:
        conn.close()
        return jsonify({"status": "hwid_mismatch"})
    
    if now - last_seen > 300:
        conn.close()
        return jsonify({"status": "timeout"})
    
    conn.close()
    return jsonify({"status": "ok"})

# -------------------------
# LOGOUT
# -------------------------
@app.route("/logout", methods=["POST"])
def logout():
    data = request.json or {}
    token = normalize_string(data.get("token"))
    if token:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("DELETE FROM sessions WHERE token=?", (token,))
        conn.commit()
        conn.close()
    return jsonify({"status": "ok"})





# -------------------------
# ADMIN API ROUTES
# -------------------------
@app.route("/admin/create_license", methods=["POST"])
@require_localhost
def create_license():
    data = request.json or {}
    count = data.get("count", 1)
    
    conn = get_db()
    cur = conn.cursor()
    licenses = []
    for _ in range(count):
        license_key = str(uuid.uuid4()).upper()
        cur.execute("INSERT INTO licenses (license_key, created_at) VALUES (?, ?)", (license_key, int(time.time())))
        licenses.append(license_key)
    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "licenses": licenses})




@app.route("/admin/sessions", methods=["GET"])
@require_localhost
def admin_sessions():
    conn = get_db()
    cur = conn.cursor()
    now = int(time.time())
    cur.execute("SELECT token, username, user_id, hwid, expires, last_seen, created_at FROM sessions WHERE expires > ? ORDER BY last_seen DESC", (now,))
    sessions = []
    for row in cur.fetchall():
        session = dict(row)
        session['expires_in'] = session['expires'] - now
        session['last_seen_ago'] = now - session['last_seen']
        session['token_short'] = session['token'][:8] + '...'
        sessions.append(session)
    conn.close()
    return jsonify({"status": "ok", "sessions": sessions})

@app.route("/admin/close_session", methods=["POST"])
@require_localhost
def admin_close_session():
    data = request.json or {}
    token = data.get('token')
    if not token:
        return jsonify({"status": "error", "message": "Token required"})
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT username FROM sessions WHERE token = ?", (token,))
    row = cur.fetchone()
    if not row:
        conn.close()
        return jsonify({"status": "error", "message": "Session not found"})
    username = row['username']
    cur.execute("DELETE FROM sessions WHERE token = ?", (token,))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "message": f"Session closed for {username}"})

@app.route("/admin/close_user_sessions", methods=["POST"])
@require_localhost
def admin_close_user_sessions():
    data = request.json or {}
    username = data.get('username')
    if not username:
        return jsonify({"status": "error", "message": "Username required"})
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) as count FROM sessions WHERE username = ?", (username,))
    count = cur.fetchone()['count']
    cur.execute("DELETE FROM sessions WHERE username = ?", (username,))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "message": f"Closed {count} session(s) for {username}"})

@app.route("/admin/reset_hwid", methods=["POST"])
@require_localhost
def admin_reset_hwid():
    data = request.json or {}
    username = data.get('username')
    if not username:
        return jsonify({"status": "error", "message": "Username required"})
    conn = get_db()
    cur = conn.cursor()
    cur.execute("UPDATE users SET hwid = '' WHERE username = ?", (username,))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})

@app.route("/admin/delete_user", methods=["POST"])
@require_localhost
def admin_delete_user():
    data = request.json or {}
    username = data.get('username')
    if not username:
        return jsonify({"status": "error", "message": "Username required"})
    conn = get_db()
    cur = conn.cursor()
    cur.execute("DELETE FROM sessions WHERE username = ?", (username,))
    cur.execute("DELETE FROM users WHERE username = ?", (username,))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})

@app.route("/admin/update_version", methods=["POST"])
@require_localhost
def admin_update_version():
    data = request.json or {}
    version = data.get('version')
    download_url = data.get('download_url', '')
    changelog = data.get('changelog', '')
    force_update = data.get('force_update', False)
    if not version:
        return jsonify({"status": "error", "message": "Version required"})
    conn = get_db()
    cur = conn.cursor()
    cur.execute("INSERT OR REPLACE INTO version (id, version, download_url, changelog, force_update, updated_at) VALUES (1, ?, ?, ?, ?, ?)", 
                (version, download_url, changelog, force_update, int(time.time())))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "message": f"Version updated to {version}"})

# -------------------------
# ADMIN PANEL
# -------------------------
@app.route("/admin")
@require_localhost
def admin_panel():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) as count FROM users")
    users_count = cur.fetchone()['count']
    cur.execute("SELECT COUNT(*) as count FROM sessions WHERE expires > ?", (int(time.time()),))
    active_sessions = cur.fetchone()['count']
    cur.execute("SELECT COUNT(*) as count FROM licenses")
    total_licenses = cur.fetchone()['count']
    cur.execute("SELECT COUNT(*) as count FROM licenses WHERE used = 1")
    used_licenses = cur.fetchone()['count']
    unused_licenses = total_licenses - used_licenses
    cur.execute("SELECT license_key FROM licenses WHERE used = 0 ORDER BY id DESC")
    unused_licenses_list = [dict(row) for row in cur.fetchall()]
    cur.execute("SELECT license_key, used_by FROM licenses WHERE used = 1 ORDER BY used_at DESC")
    used_licenses_list = [dict(row) for row in cur.fetchall()]
    cur.execute("SELECT id, username, hwid, license_key, created_at FROM users ORDER BY id DESC")
    users = []
    for row in cur.fetchall():
        user = dict(row)
        user['created_at_str'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(user['created_at'])) if user['created_at'] else 'N/A'
        users.append(user)
    conn.close()
    stats = {'users': users_count, 'active_sessions': active_sessions, 'total_licenses': total_licenses, 'used_licenses': used_licenses, 'unused_licenses': unused_licenses}
    return render_template_string(ADMIN_TEMPLATE, users=users, stats=stats, unused_licenses=unused_licenses_list, used_licenses_list=used_licenses_list)

ADMIN_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>mAuth - Ethan Admin</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background: #1a1a1a; color: #e0e0e0; font-family: 'Segoe UI', sans-serif; padding: 20px; }
        .container { max-width: 1600px; margin: 0 auto; }
        .header { background: #252525; padding: 20px; border-radius: 10px; margin-bottom: 25px; border-left: 4px solid #3a6ea5; }
        .header h1 { color: #3a6ea5; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: #252525; border-radius: 10px; padding: 20px; text-align: center; border: 1px solid #333; }
        .stat-card h3 { color: #3a6ea5; font-size: 32px; }
        .two-columns { display: grid; grid-template-columns: repeat(auto-fit, minmax(450px, 1fr)); gap: 25px; margin-bottom: 30px; }
        .card { background: #252525; border-radius: 10px; border: 1px solid #333; overflow: hidden; margin-bottom: 25px; }
        .card-header { background: #2a2a2a; padding: 15px 20px; border-bottom: 2px solid #3a6ea5; }
        .card-header h2 { color: #3a6ea5; font-size: 18px; }
        .card-body { padding: 20px; }
        .form-group { margin-bottom: 15px; }
        .form-group label { display: block; margin-bottom: 8px; color: #aaa; font-size: 13px; }
        input, select, textarea { width: 100%; padding: 10px; background: #1a1a1a; border: 1px solid #3a3a3a; color: #e0e0e0; border-radius: 6px; }
        input:focus, select:focus, textarea:focus { outline: none; border-color: #3a6ea5; }
        .btn { padding: 10px 20px; border: none; border-radius: 6px; cursor: pointer; font-size: 14px; font-weight: 500; transition: all 0.2s; }
        .btn-primary { background: #3a6ea5; color: white; }
        .btn-primary:hover { background: #2d5a8c; transform: translateY(-1px); }
        .btn-danger { background: #8b3a3a; color: white; }
        .btn-danger:hover { background: #a54444; transform: translateY(-1px); }
        .btn-warning { background: #8b6b3a; color: white; }
        .btn-warning:hover { background: #a58044; transform: translateY(-1px); }
        .btn-success { background: #2a5a3a; color: white; }
        .btn-success:hover { background: #3a7a4a; transform: translateY(-1px); }
        .btn-sm { padding: 5px 12px; font-size: 12px; }
        .table-wrapper { overflow-x: auto; max-height: 500px; overflow-y: auto; }
        table { width: 100%; border-collapse: collapse; }
        th { background: #2a2a2a; padding: 12px; text-align: left; color: #3a6ea5; position: sticky; top: 0; }
        td { padding: 10px 12px; border-bottom: 1px solid #333; }
        tr:hover { background: #2a2a2a; }
        code { background: #1a1a1a; padding: 2px 6px; border-radius: 4px; color: #3a6ea5; font-family: monospace; }
        .badge { display: inline-block; padding: 2px 8px; border-radius: 20px; font-size: 11px; font-weight: 600; }
        .badge-used { background: #8b3a3a; color: #ffaaaa; }
        .badge-unused { background: #2a5a3a; color: #aaffaa; }
        .license-list { max-height: 300px; overflow-y: auto; }
        .license-item { background: #1a1a1a; padding: 8px 12px; margin-bottom: 8px; border-radius: 6px; display: flex; justify-content: space-between; align-items: center; }
        .result-message { margin-top: 12px; padding: 10px; border-radius: 6px; }
        .result-success { background: #1a3a2a; color: #5aad5a; border-left: 3px solid #5aad5a; }
        .result-error { background: #3a1a1a; color: #ad5a5a; border-left: 3px solid #ad5a5a; }
        hr { border-color: #333; margin: 15px 0; }
        .session-count { margin-left: 15px; padding: 5px 12px; background: #1a1a1a; border-radius: 20px; }
        .readonly-input { background: #1a3a3a; color: #3a6ea5; cursor: not-allowed; }
    </style>
</head>
<body>
<div class="container">
    <div class="header"><h1>mAuth Admin</h1><p>Manage users, licenses, and sessions</p></div>
    
    <!-- Stats -->
    <div class="stats-grid">
        <div class="stat-card"><h3 id="stat_users">{{ stats.users }}</h3><p>Total Users</p></div>
        <div class="stat-card"><h3 id="stat_sessions">{{ stats.active_sessions }}</h3><p>Active Sessions</p></div>
        <div class="stat-card"><h3 id="stat_total_licenses">{{ stats.total_licenses }}</h3><p>Total Licenses</p></div>
        <div class="stat-card"><h3 id="stat_used_licenses">{{ stats.used_licenses }}</h3><p>Used Licenses</p></div>
        <div class="stat-card"><h3 id="stat_unused_licenses">{{ stats.unused_licenses }}</h3><p>Unused Licenses</p></div>
    </div>
    
    <!-- Two Column Layout -->
    <div class="two-columns">
        <!-- License Management -->
        <div class="card">
            <div class="card-header"><h2>🔑 License Management</h2></div>
            <div class="card-body">
                <div class="form-group"><label>Generate New Keys</label><div style="display:flex;gap:10px;"><input type="number" id="license_count" value="5" min="1" max="50" style="width:100px;"><button onclick="createLicenses()" class="btn btn-primary">Generate</button></div></div>
                <div id="license_result"></div><hr>
                <label>Unused License Keys (<span id="unused_count">{{ stats.unused_licenses }}</span>)</label>
                <div class="license-list" id="unused_licenses_list">{% for lic in unused_licenses %}<div class="license-item"><span class="license-key">{{ lic.license_key }}</span><span class="badge badge-unused">unused</span></div>{% endfor %}</div><hr>
                <label>Used License Keys (<span id="used_count">{{ stats.used_licenses }}</span>)</label>
                <div class="license-list" id="used_licenses_list">{% for lic in used_licenses_list %}<div class="license-item"><span class="license-key">{{ lic.license_key }}</span><span class="badge badge-used">used by {{ lic.used_by }}</span></div>{% endfor %}</div>
            </div>
        </div>
        
        <!-- User Management -->
        <div class="card">
            <div class="card-header"><h2>👤 User Management</h2></div>
            <div class="card-body">
                <div class="form-group"><label>Reset User HWID</label><div style="display:flex;gap:10px;"><input type="text" id="reset_username" placeholder="Username"><button onclick="resetHwid()" class="btn btn-warning">Reset HWID</button></div></div>
                <div class="form-group"><label>Delete User</label><div style="display:flex;gap:10px;"><input type="text" id="delete_username" placeholder="Username"><button onclick="deleteUser()" class="btn btn-danger">Delete User</button></div></div>
                <div id="user_result"></div>
            </div>
        </div>
    </div>
    
    <!-- Version Control -->
    <div class="card">
        <div class="card-header"><h2>📦 Version Control</h2></div>
        <div class="card-body">
            <div class="form-group"><label>Current Version</label><input type="text" id="version_current" class="readonly-input" readonly value="Loading..."></div>
            <div class="form-group"><label>New Version</label><input type="text" id="version_new" placeholder="e.g., 1.0.1"></div>
            <div class="form-group"><label>Download URL</label><input type="text" id="version_url" placeholder="https://yourdownload.com/program.zip"></div>
            <div class="form-group"><label>Changelog</label><textarea id="version_changelog" rows="3" placeholder="What's new in this version?"></textarea></div>
            <div class="form-group"><label><input type="checkbox" id="version_force"> Force update (users must update to use)</label></div>
            <button onclick="updateVersion()" class="btn btn-primary">Update Version</button>
            <div id="version_result"></div>
        </div>
    </div>
    
    
    

    
    <!-- Active Sessions -->
    <div class="card">
        <div class="card-header"><h2>🟢 Active Sessions</h2></div>
        <div class="card-body">
            <div style="margin-bottom:15px; display:flex; gap:10px; align-items:center; flex-wrap:wrap;">
                <button onclick="refreshSessions()" class="btn btn-primary">🔄 Refresh Sessions</button>
                <button onclick="closeAllSessions()" class="btn btn-danger">⚠️ Close All Sessions</button>
                <span id="session_count" class="session-count"></span>
            </div>
            <div class="table-wrapper">
                <table id="sessions_table">
                    <thead><tr><th>User</th><th>Session ID</th><th>Last Seen</th><th>Expires In</th><th>Status</th><th>Actions</th></tr></thead>
                    <tbody id="sessions_tbody"><tr><td colspan="6" style="text-align:center;">Loading sessions...</td></tr></tbody>
                </table>
            </div>
        </div>
    </div>
    
    <!-- All Users Table -->
    <div class="card">
        <div class="card-header"><h2>📋 All Users</h2></div>
        <div class="card-body">
            <div class="form-group"><input type="text" id="search_input" placeholder="🔍 Search by username or HWID..." onkeyup="searchUsers()"></div>
            <div class="table-wrapper">
                <table id="users_table">
                    <thead><tr><th>ID</th><th>Username</th><th>HWID</th><th>License Key</th><th>Created</th><th>Actions</th></tr></thead>
                    <tbody id="users_tbody">
                        {% for user in users %}
                        <tr>
                            <td>{{ user.id }}</td>
                            <td><strong>{{ user.username }}</strong></td>
                            <td><code>{{ user.hwid[:30] + '...' if user.hwid and user.hwid|length > 30 else user.hwid or 'Not bound' }}</code></td>
                            <td><code>{{ user.license_key[:20] + '...' if user.license_key and user.license_key|length > 20 else user.license_key or '-' }}</code></td>
                            <td>{{ user.created_at_str }}</td>
                            <td>
                                <button onclick="resetHwidFor('{{ user.username }}')" class="btn btn-warning btn-sm">Reset HWID</button>
                                <button onclick="deleteUserFor('{{ user.username }}')" class="btn btn-danger btn-sm">Delete</button>
                                <button onclick="closeUserSessions('{{ user.username }}')" class="btn btn-primary btn-sm">Kill Sessions</button>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
</div>

<script>
// Get admin token from localStorage
function getAdminToken() {
    return localStorage.getItem('admin_token');
}

// License Management
function createLicenses() {
    let count = document.getElementById('license_count').value;
    fetch('/admin/create_license', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ count: parseInt(count) })
    })
    .then(res => res.json())
    .then(data => {
        if (data.licenses) {
            document.getElementById('license_result').innerHTML = '<div class="result-message result-success">✅ Generated ' + data.licenses.length + ' keys: ' + data.licenses.join(', ') + '</div>';
            setTimeout(() => location.reload(), 2000);
        } else {
            document.getElementById('license_result').innerHTML = '<div class="result-message result-error">❌ Error: ' + (data.message || 'Unknown error') + '</div>';
        }
    })
    .catch(err => {
        document.getElementById('license_result').innerHTML = '<div class="result-message result-error">❌ Error: ' + err + '</div>';
    });
}

// HWID Reset
function resetHwid() {
    let username = document.getElementById('reset_username').value;
    if (!username) { alert('Enter username'); return; }
    resetHwidFor(username);
}

function resetHwidFor(username) {
    fetch('/admin/reset_hwid', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username })
    })
    .then(res => res.json())
    .then(data => {
        let msg = data.status === 'ok' ? 
            '<div class="result-message result-success">✅ HWID reset for ' + username + '</div>' : 
            '<div class="result-message result-error">❌ Error: ' + (data.message || 'Unknown') + '</div>';
        document.getElementById('user_result').innerHTML = msg;
        setTimeout(() => location.reload(), 1000);
    });
}

// Delete User
function deleteUser() {
    let username = document.getElementById('delete_username').value;
    if (!username) { alert('Enter username'); return; }
    deleteUserFor(username);
}

function deleteUserFor(username) {
    if (!confirm('Delete user ' + username + '? This cannot be undone!')) return;
    fetch('/admin/delete_user', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username })
    })
    .then(res => res.json())
    .then(data => {
        let msg = data.status === 'ok' ? 
            '<div class="result-message result-success">✅ User ' + username + ' deleted</div>' : 
            '<div class="result-message result-error">❌ Error: ' + (data.message || 'Unknown') + '</div>';
        document.getElementById('user_result').innerHTML = msg;
        setTimeout(() => location.reload(), 1000);
    });
}

// Version Control
function loadCurrentVersion() {
    fetch('/get_version')
        .then(res => res.json())
        .then(data => {
            if (data.status === 'ok') {
                document.getElementById('version_current').value = data.version;
                document.getElementById('version_force').checked = data.force_update;
            }
        })
        .catch(err => {
            document.getElementById('version_current').value = 'Error loading';
        });
}

function updateVersion() {
    let version = document.getElementById('version_new').value;
    if (!version) {
        alert('Enter a version number');
        return;
    }
    fetch('/admin/update_version', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            version: version,
            download_url: document.getElementById('version_url').value,
            changelog: document.getElementById('version_changelog').value,
            force_update: document.getElementById('version_force').checked
        })
    })
    .then(res => res.json())
    .then(data => {
        let resultDiv = document.getElementById('version_result');
        if (data.status === 'ok') {
            resultDiv.innerHTML = '<div class="result-message result-success">✅ ' + data.message + '</div>';
            loadCurrentVersion();
            document.getElementById('version_new').value = '';
            document.getElementById('version_url').value = '';
            document.getElementById('version_changelog').value = '';
            setTimeout(() => resultDiv.innerHTML = '', 3000);
        } else {
            resultDiv.innerHTML = '<div class="result-message result-error">❌ ' + data.message + '</div>';
        }
    });
}





// Session Management
function refreshSessions() {
    fetch('/admin/sessions')
        .then(res => res.json())
        .then(data => {
            if (data.status === 'ok') {
                updateSessionsTable(data.sessions);
                document.getElementById('session_count').innerHTML = `📊 ${data.sessions.length} active session(s)`;
            }
        })
        .catch(err => {
            document.getElementById('sessions_tbody').innerHTML = '<tr><td colspan="6" style="text-align:center; color:#ad5a5a;">❌ Failed to load sessions</td></tr>';
        });
}

function updateSessionsTable(sessions) {
    const tbody = document.getElementById('sessions_tbody');
    if (!sessions || sessions.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;">No active sessions</td></tr>';
        return;
    }
    tbody.innerHTML = sessions.map(ss => {
        let lastSeenMins = Math.floor(ss.last_seen_ago / 60);
        let lastSeenText = lastSeenMins < 1 ? 'Just now' : lastSeenMins < 60 ? `${lastSeenMins} min ago` : `${Math.floor(lastSeenMins / 60)} hours ago`;
        let expiresMins = Math.floor(ss.expires_in / 60);
        let expiresText = expiresMins < 60 ? `${expiresMins} min` : `${Math.floor(expiresMins / 60)} hours`;
        let status = ss.expires_in < 300 ? '⚠️ Expiring soon' : '🟢 Active';
        let statusColor = ss.expires_in < 300 ? '#ad5a5a' : '#5aad5a';
        return `<tr>
            <td><strong>${escapeHtml(ss.username)}</strong></td>
            <td><code>${escapeHtml(ss.token_short)}</code></td>
            <td>${lastSeenText}</td>
            <td>${expiresText}</td>
            <td style="color:${statusColor}">${status}</td>
            <td><button onclick="closeSession('${escapeHtml(ss.token)}')" class="btn btn-danger btn-sm">Kill</button> <button onclick="closeUserSessions('${escapeHtml(ss.username)}')" class="btn btn-warning btn-sm">Kill All</button></td>
        </tr>`;
    }).join('');
}

function closeSession(token) {
    if (!confirm('Kill this session? The user will be forced to re-login.')) return;
    fetch('/admin/close_session', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: token })
    })
    .then(res => res.json())
    .then(data => {
        if (data.status === 'ok') refreshSessions();
    });
}

function closeUserSessions(username) {
    if (!confirm(`Kill ALL sessions for ${username}? They will be forced to re-login.`)) return;
    fetch('/admin/close_user_sessions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username })
    })
    .then(res => res.json())
    .then(data => {
        if (data.status === 'ok') {
            refreshSessions();
            setTimeout(() => location.reload(), 1000);
        }
    });
}

function closeAllSessions() {
    if (!confirm('⚠️ DANGER: Close ALL active sessions? Every user will be logged out!')) return;
    fetch('/admin/sessions')
        .then(res => res.json())
        .then(data => {
            if (data.sessions) {
                const promises = data.sessions.map(s => 
                    fetch('/admin/close_session', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ token: s.token })
                    })
                );
                Promise.all(promises).then(() => {
                    refreshSessions();
                    setTimeout(() => location.reload(), 1000);
                });
            }
        });
}

// Search Users
function searchUsers() {
    let query = document.getElementById('search_input').value.toLowerCase();
    let rows = document.querySelectorAll('#users_tbody tr');
    rows.forEach(row => {
        let text = row.innerText.toLowerCase();
        row.style.display = text.includes(query) ? '' : 'none';
    });
}

// Helper Functions
function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/[&<>]/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[m]));
}



// Auto-refresh sessions every 10 seconds
let refreshInterval;
document.addEventListener('DOMContentLoaded', function() {
    refreshSessions();
    loadCurrentVersion();
    refreshInterval = setInterval(refreshSessions, 10000);
});

window.addEventListener('beforeunload', function() {
    if (refreshInterval) clearInterval(refreshInterval);
});
</script>
</body>
</html>
'''

# -------------------------
# RUN
# -------------------------
if __name__ == "__main__":
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password_hash BLOB, hwid TEXT, license_key TEXT, created_at INTEGER)")
        cur.execute("CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, username TEXT, user_id INTEGER, hwid TEXT, expires INTEGER, last_seen INTEGER, created_at INTEGER)")
        cur.execute("CREATE TABLE IF NOT EXISTS licenses (id INTEGER PRIMARY KEY AUTOINCREMENT, license_key TEXT UNIQUE, used INTEGER DEFAULT 0, used_by TEXT, used_at INTEGER, created_at INTEGER)")
        cur.execute("CREATE TABLE IF NOT EXISTS version (id INTEGER PRIMARY KEY, version TEXT, download_url TEXT, changelog TEXT, force_update BOOLEAN, updated_at INTEGER)")
        conn.commit()
    
    app.run(host="0.0.0.0", port=5000, debug=True)