"""
DeupGaming Free Panel — app.py
Shared-IP VPS hosting: each container gets a dedicated SSH port + 5 extra
ports via iptables DNAT. sshx still runs as the browser terminal.
Users can self-register and create one VPS. No port forwarding UI needed —
ports are assigned automatically and shown on the dashboard.
"""

import os, sqlite3, time, secrets, threading, base64, datetime
from datetime import timedelta
from flask import (Flask, request, render_template, redirect, url_for,
                   jsonify, session, Response, stream_with_context, flash, abort)
from flask_login import (LoginManager, UserMixin, login_user, logout_user,
                         login_required, current_user)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

from vps import (
    create_vps_container, destroy_vps, suspend_vps, unsuspend_vps,
    regen_sshx, get_container_stats, build_logs_stream,
    can_create_vps, can_allocate_disk, MAX_VPS_PER_NODE,
    get_host_capacity, start_vps, stop_vps, reinstall_vps,
    sync_status, list_files, read_file_b64, write_file_b64,
    delete_file, create_directory, exec_command,
    get_free_vps_cpu, get_free_vps_ram, get_free_vps_disk,
    kvm_available, set_kvm_enabled,
)
from monitor import start_monitor
import queue_manager as queue
import node_mesh
import ip_intel
import nat

DB = "panel.db"

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

SECRET_KEY_FILE = "secret.key"
if os.environ.get("FLASK_SECRET_KEY"):
    app.secret_key = os.environ["FLASK_SECRET_KEY"]
elif os.path.exists(SECRET_KEY_FILE):
    app.secret_key = open(SECRET_KEY_FILE).read().strip()
else:
    _key = secrets.token_hex(32)
    open(SECRET_KEY_FILE, "w").write(_key)
    app.secret_key = _key

app.config["REMEMBER_COOKIE_DURATION"] = timedelta(days=30)
login_manager = LoginManager(app)
login_manager.login_view = "login"

ADMIN_MAX_RAM_GB    = 160
ADMIN_MAX_CPU_CORES = 32
ADMIN_MAX_DISK_GB   = 2000
_last_create_click: dict  = {}
_last_power_action: dict  = {}
CREATE_DEBOUNCE_SECONDS   = 10
POWER_DEBOUNCE_SECONDS    = 10
REINSTALL_DEBOUNCE_SECONDS = 60


# ── DB ────────────────────────────────────────────────────────────────────────

def get_db():
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    db = get_db()
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        signup_ip TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0,
        created_at INTEGER NOT NULL,
        recovery_code_hash TEXT,
        recovery_code_shown INTEGER DEFAULT 0,
        youtube_verified INTEGER DEFAULT 0,
        is_vpn_signup INTEGER DEFAULT 0,
        vpn_provider TEXT
    );
    CREATE TABLE IF NOT EXISTS vps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        container_id TEXT NOT NULL,
        ssh_command TEXT,
        status TEXT DEFAULT 'creating',
        creator_ip TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        last_regen INTEGER DEFAULT 0,
        kvm_enabled INTEGER DEFAULT 0,
        node_id INTEGER DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS feedback (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        stars INTEGER NOT NULL,
        comment TEXT,
        created_at INTEGER NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS broadcast (
        id INTEGER PRIMARY KEY CHECK (id=1),
        message TEXT, active INTEGER DEFAULT 0, updated_at INTEGER
    );
    CREATE TABLE IF NOT EXISTS panel_config (
        key TEXT PRIMARY KEY, value TEXT NOT NULL
    );
    """)
    db.execute("INSERT OR IGNORE INTO broadcast(id,message,active,updated_at) VALUES(1,'',0,0)")
    for stmt in [
        "ALTER TABLE users ADD COLUMN is_vpn_signup INTEGER DEFAULT 0",
        "ALTER TABLE users ADD COLUMN vpn_provider TEXT",
        "ALTER TABLE users ADD COLUMN youtube_verified INTEGER DEFAULT 0",
        "ALTER TABLE vps ADD COLUMN node_id INTEGER DEFAULT 0",
        "ALTER TABLE vps ADD COLUMN kvm_enabled INTEGER DEFAULT 0",
    ]:
        try: db.execute(stmt)
        except: pass
    db.commit()
    node_mesh.init_mesh_tables(db)
    nat.init_nat_tables(db)
    db.close()


# ── Auth ──────────────────────────────────────────────────────────────────────

class User(UserMixin):
    def __init__(self, row):
        self.id               = row["id"]
        self.username         = row["username"]
        self.is_admin         = bool(row["is_admin"])
        self.youtube_verified = bool(row["youtube_verified"] or 0)

@login_manager.user_loader
def load_user(uid):
    row = get_db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    return User(row) if row else None

def generate_recovery_code():
    return "".join(secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(6))


# ── Template helpers ──────────────────────────────────────────────────────────

@app.template_filter("strftime")
def strftime_filter(ts):
    try: return datetime.datetime.fromtimestamp(int(ts)).strftime("%Y-%m-%d %H:%M")
    except: return str(ts)

@app.template_filter("parse_ssh_command")
def parse_ssh_command_filter(ssh_command):
    """Jinja2 filter: returns (ssh_str, sshx_url) tuple from stored ssh_command."""
    if not ssh_command or ssh_command == "__terminal_only__":
        return (None, None)
    if "|||" in ssh_command:
        parts = ssh_command.split("|||", 1)
        return (parts[0].strip(), parts[1].strip())
    if ssh_command.startswith("ssh "):
        return (ssh_command, None)
    return (None, ssh_command)

@app.before_request
def detect_node_url():
    node_mesh.set_detected_url(f"{request.scheme}://{request.host}")

@app.context_processor
def inject_globals():
    db  = get_db()
    row = db.execute("SELECT message,active FROM broadcast WHERE id=1").fetchone()
    db.close()
    return dict(
        broadcast_message=(row["message"] if row and row["active"] and row["message"] else None),
        node_url=node_mesh.get_node_url(),
        node_code=node_mesh.NODE_CODE,
        kvm_available=kvm_available(),
        public_ip=nat.get_public_ip(),
    )


# ── Public routes ─────────────────────────────────────────────────────────────

@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("admin" if current_user.is_admin else "dashboard"))
    return render_template("landing.html")

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        u  = request.form.get("username","").strip()
        p  = request.form.get("password","")
        ip = request.remote_addr
        if not u or not p:
            return render_template("register.html", error="Fill both fields.")
        if len(p) < 6:
            return render_template("register.html", error="Password must be ≥6 characters.")
        db = get_db()
        if db.execute("SELECT 1 FROM users WHERE username=?", (u,)).fetchone():
            return render_template("register.html", error="Username already taken.")
        is_vpn, vpn_label = ip_intel.is_vpn_or_proxy(ip)
        db.execute(
            "INSERT INTO users(username,password,signup_ip,created_at,is_vpn_signup,vpn_provider)"
            " VALUES(?,?,?,?,?,?)",
            (u, generate_password_hash(p), ip, int(time.time()), int(is_vpn), vpn_label)
        )
        db.commit()
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        u   = request.form.get("username","").strip()
        p   = request.form.get("password","")
        db  = get_db()
        row = db.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
        if row and check_password_hash(row["password"], p):
            login_user(User(row), remember=True)
            if not row["recovery_code_shown"]:
                code = generate_recovery_code()
                db.execute(
                    "UPDATE users SET recovery_code_hash=?, recovery_code_shown=1 WHERE id=?",
                    (generate_password_hash(code), row["id"])
                )
                db.commit()
                session["show_recovery_code"] = code
                return redirect(url_for("recovery_code_display"))
            return redirect(url_for("admin" if row["is_admin"] else "dashboard"))
        return render_template("login.html", error="Incorrect credentials.")
    return render_template("login.html")

@app.route("/recovery-code")
@login_required
def recovery_code_display():
    code = session.pop("show_recovery_code", None)
    if not code: return redirect(url_for("dashboard"))
    return render_template("recovery_code.html", code=code)

@app.route("/forgot-password", methods=["GET","POST"])
def forgot_password():
    if request.method == "POST":
        u    = request.form.get("username","").strip()
        code = request.form.get("code","").strip().upper()
        db   = get_db()
        row  = db.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
        if not row or not row["recovery_code_hash"] or \
                not check_password_hash(row["recovery_code_hash"], code):
            return render_template("forgot_password.html", error="No match.")
        session["reset_user_id"] = row["id"]
        return redirect(url_for("reset_password"))
    return render_template("forgot_password.html")

@app.route("/reset-password", methods=["GET","POST"])
def reset_password():
    uid = session.get("reset_user_id")
    if not uid: return redirect(url_for("forgot_password"))
    if request.method == "POST":
        pw = request.form.get("password","")
        if len(pw) < 6:
            return render_template("reset_password.html", error="Min 6 characters.")
        db = get_db()
        db.execute("UPDATE users SET password=? WHERE id=?", (generate_password_hash(pw), uid))
        db.commit(); session.pop("reset_user_id", None)
        return redirect(url_for("login"))
    return render_template("reset_password.html")

@app.route("/logout", methods=["GET","POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route("/account/delete", methods=["GET","POST"])
@login_required
def delete_account():
    if request.method == "POST":
        code = request.form.get("code","").strip().upper()
        db   = get_db()
        row  = db.execute("SELECT * FROM users WHERE id=?", (current_user.id,)).fetchone()
        if not row or not row["recovery_code_hash"] or \
                not check_password_hash(row["recovery_code_hash"], code):
            return render_template("delete_account.html", error="Incorrect recovery code.")
        for v in db.execute("SELECT * FROM vps WHERE user_id=?", (current_user.id,)).fetchall():
            try:
                nat.deprovision_nat(db, v["id"])
                destroy_vps(v["container_id"])
            except Exception as e:
                print(f"[DELETE ACCOUNT] {e}")
        db.execute("DELETE FROM vps WHERE user_id=?",      (current_user.id,))
        db.execute("DELETE FROM feedback WHERE user_id=?",  (current_user.id,))
        db.execute("DELETE FROM users WHERE id=?",          (current_user.id,))
        db.commit()
        logout_user()
        return redirect(url_for("login"))
    return render_template("delete_account.html")


# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.route("/dashboard")
@login_required
def dashboard():
    db      = get_db()
    all_vps = db.execute(
        "SELECT * FROM vps WHERE user_id=? ORDER BY created_at ASC", (current_user.id,)
    ).fetchall()
    selected_id = request.args.get("vps_id", type=int)
    vps = None
    if selected_id:
        vps = next((v for v in all_vps if v["id"] == selected_id), None)
    if not vps and all_vps:
        vps = all_vps[0]

    if vps and vps["status"] in ("running","stopped"):
        real = sync_status(vps["container_id"], vps["status"])
        if real != vps["status"]:
            db.execute("UPDATE vps SET status=? WHERE id=?", (real, vps["id"]))
            db.commit()
            vps = db.execute("SELECT * FROM vps WHERE id=?", (vps["id"],)).fetchone()

    nat_info = nat.get_nat_rule(db, vps["id"]) if vps else None
    queue_pos = queue.get_position(vps["id"]) if vps and vps["status"] in ("queued","creating") else 0

    feedback_rows = db.execute(
        "SELECT feedback.*,users.username FROM feedback "
        "JOIN users ON users.id=feedback.user_id "
        "ORDER BY feedback.created_at DESC LIMIT 20"
    ).fetchall()

    limits = {
        "cpu":  get_free_vps_cpu(),
        "ram":  get_free_vps_ram() // 1024,
        "disk": get_free_vps_disk(),
    }
    can_feedback = bool(vps and vps["status"] == "running" and vps["ssh_command"])

    return render_template("dashboard.html",
        vps=vps, all_vps=all_vps,
        nat_info=nat_info,
        feedback_rows=feedback_rows,
        queue_pos=queue_pos, slot_seconds=queue.SLOT_SECONDS,
        can_feedback=can_feedback, limits=limits,
        public_ip=nat.get_public_ip(),
    )


# ── VPS creation ──────────────────────────────────────────────────────────────

@app.route("/vps/create", methods=["POST"])
@login_required
def vps_create():
    db = get_db()
    ip = request.remote_addr

    if db.execute("SELECT 1 FROM vps WHERE user_id=?", (current_user.id,)).fetchone():
        return "You already have a VPS", 403
    if db.execute("SELECT 1 FROM vps WHERE creator_ip=?", (ip,)).fetchone():
        return "This IP already has a VPS", 403
    user_row = db.execute("SELECT signup_ip FROM users WHERE id=?", (current_user.id,)).fetchone()
    if db.execute("SELECT 1 FROM vps WHERE creator_ip=?", (user_row["signup_ip"],)).fetchone():
        return "Your signup IP already has a VPS", 403

    is_vpn, vpn_label = ip_intel.is_vpn_or_proxy(ip)
    if is_vpn:
        return f"VPN/proxy detected ({vpn_label}) — disable it and try again.", 403

    found_elsewhere, other_url = node_mesh.check_ip_across_mesh(db, ip)
    if found_elsewhere:
        return f"This IP already has a VPS on another node ({other_url})", 403

    allowed, current_count = can_create_vps()
    if not allowed:
        peer_url, peer_secret = node_mesh.get_peer_for_overflow(db)
        if peer_url and peer_secret:
            now = int(time.time())
            cur = db.execute(
                "INSERT INTO vps(user_id,container_id,creator_ip,created_at,status,node_id)"
                " VALUES(?,?,?,?,'creating',1)",
                (current_user.id, "pending-overflow", ip, now)
            )
            db.commit()
            vps_id = cur.lastrowid
            threading.Thread(target=_overflow_build_worker,
                             args=(vps_id, current_user.id, ip, peer_url, peer_secret),
                             daemon=True).start()
            flash(f"Node full — VPS being created on {peer_url}.")
            return redirect(url_for("vps_view", vps_id=vps_id))
        return "Node full and no peer nodes available. Try again later.", 503

    disk_ok, disk_alloc, disk_budget, disk_msg = can_allocate_disk(get_free_vps_disk())
    if not disk_ok:
        return disk_msg or f"Disk budget reached ({disk_alloc}/{disk_budget}GB).", 503

    now        = int(time.time())
    last_click = _last_create_click.get(ip, 0)
    if now - last_click < CREATE_DEBOUNCE_SECONDS:
        return "Please wait a few seconds before retrying.", 429
    _last_create_click[ip] = now

    cur    = db.execute(
        "INSERT INTO vps(user_id,container_id,creator_ip,created_at,status) VALUES(?,?,?,?,?)",
        (current_user.id, "pending", ip, now, "queued")
    )
    db.commit()
    vps_id = cur.lastrowid
    queue.enqueue(current_user.id, vps_id)
    return redirect(url_for("vps_view", vps_id=vps_id))


def _overflow_build_worker(vps_id, user_id, ip, peer_url, peer_secret):
    result = node_mesh.create_vps_on_peer(
        peer_url=peer_url, shared_secret=peer_secret,
        my_url=node_mesh.get_node_url(),
        username=f"vps-{user_id}",
        cpu=get_free_vps_cpu(), ram_mb=get_free_vps_ram(), disk_gb=get_free_vps_disk(),
    )
    db = get_db()
    if "error" in result:
        db.execute("UPDATE vps SET status='failed',ssh_command=?,container_id='overflow-failed' WHERE id=?",
                   (result["error"], vps_id))
    else:
        db.execute("UPDATE vps SET status='running',container_id=?,ssh_command=? WHERE id=?",
                   (result.get("container_id","overflow"), result.get("ssh_url",""), vps_id))
    db.commit(); db.close()


def _build_vps(vps_id: int, user_id: int):
    """Queue worker — builds container then provisions NAT."""
    db = get_db()
    db.execute("UPDATE vps SET status='creating' WHERE id=?", (vps_id,))
    db.commit(); db.close()
    try:
        cid, ssh = create_vps_container(f"vps-{user_id}")
        # Provision NAT
        db = get_db()
        try:
            nat_info = nat.provision_nat(db, vps_id, cid)
            public_ip = nat_info["public_ip"]
            ssh_port  = nat_info["ssh_port"]
            extra     = nat_info["extra_ports"]
            # Build the SSH connection string shown to users
            ssh_str   = f"ssh root@{public_ip} -p {ssh_port}"
            # Append sshx URL if we got one
            if ssh and ssh != "__terminal_only__":
                ssh_str = f"{ssh_str}|||{ssh}"
        except Exception as e:
            print(f"[BUILD] NAT provision failed: {e} — VPS still created, using sshx only")
            ssh_str = ssh or "__terminal_only__"
            db = get_db()

        db.execute(
            "UPDATE vps SET container_id=?,ssh_command=?,status='running' WHERE id=?",
            (cid, ssh_str, vps_id)
        )
        db.commit(); db.close()
    except Exception as e:
        db = get_db()
        db.execute("UPDATE vps SET status='failed',ssh_command=? WHERE id=?", (str(e), vps_id))
        db.commit(); db.close()


def _build_vps_custom(vps_id, user_id, cpu, ram_mb, disk_gb, kvm=False):
    db = get_db()
    db.execute("UPDATE vps SET status='creating' WHERE id=?", (vps_id,))
    db.commit(); db.close()
    try:
        cid, ssh = create_vps_container(
            f"vps-{user_id}", cpu_limit=cpu, ram_limit_mb=ram_mb,
            disk_limit_gb=disk_gb, kvm_enabled=kvm
        )
        db = get_db()
        try:
            nat_info = nat.provision_nat(db, vps_id, cid)
            ssh_port = nat_info["ssh_port"]
            public_ip = nat_info["public_ip"]
            ssh_str = f"ssh root@{public_ip} -p {ssh_port}"
            if ssh and ssh != "__terminal_only__":
                ssh_str = f"{ssh_str}|||{ssh}"
        except Exception as e:
            print(f"[BUILD_CUSTOM] NAT failed: {e}")
            ssh_str = ssh or "__terminal_only__"
            db = get_db()
        db.execute(
            "UPDATE vps SET container_id=?,ssh_command=?,status='running',kvm_enabled=? WHERE id=?",
            (cid, ssh_str, int(kvm), vps_id)
        )
        db.commit(); db.close()
    except Exception as e:
        db = get_db()
        db.execute("UPDATE vps SET status='failed',ssh_command=? WHERE id=?", (str(e), vps_id))
        db.commit(); db.close()


# ── VPS helpers ───────────────────────────────────────────────────────────────

def _parse_ssh_command(ssh_command: str) -> tuple:
    """Returns (ssh_str, sshx_url) from the stored ssh_command field."""
    if not ssh_command or ssh_command == "__terminal_only__":
        return None, None
    if "|||" in ssh_command:
        parts = ssh_command.split("|||", 1)
        return parts[0].strip(), parts[1].strip()
    if ssh_command.startswith("ssh "):
        return ssh_command, None
    return None, ssh_command


@app.route("/vps/<int:vps_id>")
@login_required
def vps_view(vps_id):
    db  = get_db()
    vps = db.execute("SELECT * FROM vps WHERE id=?", (vps_id,)).fetchone()
    if not vps or (vps["user_id"] != current_user.id and not current_user.is_admin):
        return "Not found", 404
    queue_pos = queue.get_position(vps_id) if vps["status"] in ("queued","creating") else 0
    return render_template("vps_view.html", vps=vps, queue_pos=queue_pos,
                           slot_seconds=queue.SLOT_SECONDS)

@app.route("/vps/<int:vps_id>/queue_status")
@login_required
def vps_queue_status(vps_id):
    db  = get_db()
    vps = db.execute("SELECT * FROM vps WHERE id=?", (vps_id,)).fetchone()
    if not vps or (vps["user_id"] != current_user.id and not current_user.is_admin):
        return jsonify({"error":"no"}), 404
    return jsonify({"status":vps["status"],"position":queue.get_position(vps_id),
                    "ssh_command":vps["ssh_command"]})

@app.route("/vps/<int:vps_id>/logs")
@login_required
def vps_logs(vps_id):
    db  = get_db()
    vps = db.execute("SELECT * FROM vps WHERE id=?", (vps_id,)).fetchone()
    if not vps or (vps["user_id"] != current_user.id and not current_user.is_admin):
        return "not found", 404
    @stream_with_context
    def gen():
        cid, waited = vps["container_id"], 0
        while cid in ("pending","pending-overflow") and waited < 600:
            time.sleep(2); waited += 2
            row = get_db().execute("SELECT container_id,status FROM vps WHERE id=?", (vps_id,)).fetchone()
            if not row: yield "data: gone\n\n"; yield "data: [DONE]\n\n"; return
            cid = row["container_id"]
            if row["status"] == "failed": yield f"data: {cid}\n\n"; yield "data: [DONE]\n\n"; return
        for line in build_logs_stream(cid): yield f"data: {line}\n\n"
        yield "data: [DONE]\n\n"
    return Response(gen(), mimetype="text/event-stream")

@app.route("/vps/<int:vps_id>/stats")
@login_required
def vps_stats(vps_id):
    db  = get_db()
    vps = db.execute("SELECT * FROM vps WHERE id=?", (vps_id,)).fetchone()
    if not vps or (vps["user_id"] != current_user.id and not current_user.is_admin):
        return jsonify({"error":"no"}), 404
    if vps["status"] != "running":
        return jsonify({"error":"not running","status":vps["status"]})
    try: return jsonify(get_container_stats(vps["container_id"], vps["created_at"]))
    except Exception as e: return jsonify({"error":str(e)})

@app.route("/vps/<int:vps_id>/dismiss", methods=["POST"])
@login_required
def vps_dismiss(vps_id):
    db  = get_db()
    vps = db.execute("SELECT * FROM vps WHERE id=?", (vps_id,)).fetchone()
    if not vps or vps["user_id"] != current_user.id: return "not found", 404
    if vps["status"] != "failed": return "not failed", 400
    db.execute("DELETE FROM vps WHERE id=?", (vps_id,)); db.commit()
    return redirect(url_for("dashboard"))

@app.route("/vps/<int:vps_id>/regen_ssh", methods=["POST"])
@login_required
def regen_ssh(vps_id):
    db  = get_db()
    vps = db.execute("SELECT * FROM vps WHERE id=?", (vps_id,)).fetchone()
    if not vps or (vps["user_id"] != current_user.id and not current_user.is_admin):
        flash("Not found"); return redirect(url_for("dashboard"))
    if vps["status"] != "running":
        flash("VPS must be running"); return redirect(url_for("dashboard", vps_id=vps_id))
    if time.time() - vps["last_regen"] < 30:
        flash("Wait 30s between regens"); return redirect(url_for("dashboard", vps_id=vps_id))
    try:
        new_sshx = regen_sshx(vps["container_id"])
        # Preserve the SSH port string, update just the sshx part
        ssh_str, _ = _parse_ssh_command(vps["ssh_command"])
        if ssh_str and new_sshx:
            new_cmd = f"{ssh_str}|||{new_sshx}"
        elif new_sshx:
            new_cmd = new_sshx
        else:
            new_cmd = ssh_str or "__terminal_only__"
        db.execute("UPDATE vps SET ssh_command=?,last_regen=? WHERE id=?",
                   (new_cmd, int(time.time()), vps_id))
        db.commit()
        flash("Terminal link regenerated")
    except Exception as e:
        flash(f"Failed: {e}")
    return redirect(url_for("dashboard", vps_id=vps_id))

@app.route("/vps/<int:vps_id>/power/<action>", methods=["POST"])
@login_required
def vps_power(vps_id, action):
    if action not in ("start","stop","reinstall"): return "bad action", 400
    db  = get_db()
    vps = db.execute("SELECT * FROM vps WHERE id=?", (vps_id,)).fetchone()
    if not vps or (vps["user_id"] != current_user.id and not current_user.is_admin):
        flash("Not found"); return redirect(url_for("dashboard"))
    debounce = REINSTALL_DEBOUNCE_SECONDS if action == "reinstall" else POWER_DEBOUNCE_SECONDS
    if time.time() - _last_power_action.get(vps_id, 0) < debounce:
        flash("Please wait before retrying."); return redirect(url_for("dashboard", vps_id=vps_id))
    _last_power_action[vps_id] = time.time()
    if action == "start":
        start_vps(vps["container_id"])
        db.execute("UPDATE vps SET status='running' WHERE id=?", (vps_id,)); db.commit()
        # Reapply NAT rules (container IP may have changed)
        nat_row = nat.get_nat_rule(db, vps_id)
        if nat_row:
            extra = [int(p) for p in nat_row["extra_ports"].split(",") if p.strip().isdigit()]
            nat.add_nat_rules(vps["container_id"], nat_row["container_ip"],
                              nat_row["ssh_port"], extra)
        flash("VPS started")
    elif action == "stop":
        stop_vps(vps["container_id"])
        db.execute("UPDATE vps SET status='stopped' WHERE id=?", (vps_id,)); db.commit()
        flash("VPS stopped")
    elif action == "reinstall":
        db.execute("UPDATE vps SET status='creating',ssh_command=NULL WHERE id=?", (vps_id,)); db.commit()
        kvm = bool(vps["kvm_enabled"]) if "kvm_enabled" in vps.keys() else False
        threading.Thread(target=_reinstall_worker,
                         args=(vps_id, vps["container_id"], f"vps-{vps['user_id']}", kvm),
                         daemon=True).start()
        flash("Reinstalling…")
    return redirect(url_for("dashboard", vps_id=vps_id))

def _reinstall_worker(vps_id, old_cid, username, kvm=False):
    db = get_db()
    try:
        # Remove old NAT rules first
        nat.deprovision_nat(db, vps_id)
    except Exception as e:
        print(f"[REINSTALL] NAT deprovision: {e}")
    db.close()
    try:
        from vps import reinstall_vps
        new_cid, new_ssh = reinstall_vps(old_cid, username, kvm_enabled=kvm)
        db = get_db()
        try:
            nat_info = nat.provision_nat(db, vps_id, new_cid)
            ssh_str  = f"ssh root@{nat_info['public_ip']} -p {nat_info['ssh_port']}"
            if new_ssh and new_ssh != "__terminal_only__":
                ssh_str = f"{ssh_str}|||{new_ssh}"
        except Exception as e:
            print(f"[REINSTALL] NAT provision: {e}")
            ssh_str = new_ssh or "__terminal_only__"
            db = get_db()
        db.execute(
            "UPDATE vps SET container_id=?,ssh_command=?,status='running',kvm_enabled=? WHERE id=?",
            (new_cid, ssh_str, int(kvm), vps_id)
        )
        db.commit(); db.close()
    except Exception as e:
        db = get_db()
        db.execute("UPDATE vps SET status='failed',ssh_command=? WHERE id=?", (str(e), vps_id))
        db.commit(); db.close()


# ── Terminal ──────────────────────────────────────────────────────────────────

@app.route("/vps/<int:vps_id>/terminal/exec", methods=["POST"])
@login_required
def terminal_exec(vps_id):
    db  = get_db()
    vps = db.execute("SELECT * FROM vps WHERE id=?", (vps_id,)).fetchone()
    if not vps or (vps["user_id"] != current_user.id and not current_user.is_admin):
        return jsonify({"error":"not found"}), 404
    if vps["status"] != "running":
        return jsonify({"error":"VPS not running"}), 400
    data = request.get_json(silent=True) or {}
    cmd  = data.get("cmd","").strip()
    if not cmd: return jsonify({"error":"no command"}), 400
    blocked = ["rm -rf /","mkfs","> /dev/sda","dd if="]
    if any(b in cmd for b in blocked):
        return jsonify({"output":"Blocked.","exit_code":1})
    try: return jsonify(exec_command(vps["container_id"], cmd))
    except Exception as e: return jsonify({"error":str(e)}), 500


# ── File manager ──────────────────────────────────────────────────────────────

def _owned_vps(vps_id):
    db  = get_db()
    vps = db.execute("SELECT * FROM vps WHERE id=?", (vps_id,)).fetchone()
    if not vps or (vps["user_id"] != current_user.id and not current_user.is_admin): return None
    return vps

@app.route("/vps/<int:vps_id>/files")
@login_required
def file_manager(vps_id):
    vps = _owned_vps(vps_id)
    if not vps: abort(404)
    if vps["status"] != "running": flash("VPS must be running"); return redirect(url_for("dashboard"))
    path = request.args.get("path","/root")
    try: entries = list_files(vps["container_id"], path)
    except Exception as e: entries=[]; flash(str(e))
    return render_template("file_manager.html", vps=vps, path=path, entries=entries)

@app.route("/vps/<int:vps_id>/files/download")
@login_required
def file_download(vps_id):
    vps = _owned_vps(vps_id)
    if not vps: abort(404)
    path = request.args.get("path","")
    if not path: return "No path", 400
    try:
        raw = base64.b64decode(read_file_b64(vps["container_id"], path))
        fn  = path.split("/")[-1] or "file"
        return Response(raw, mimetype="application/octet-stream",
                        headers={"Content-Disposition":f'attachment; filename="{fn}"'})
    except Exception as e: return str(e), 500

@app.route("/vps/<int:vps_id>/files/upload", methods=["POST"])
@login_required
def file_upload(vps_id):
    vps  = _owned_vps(vps_id)
    if not vps: abort(404)
    dest = request.form.get("path","/root")
    f    = request.files.get("file")
    if not f or not f.filename: flash("No file"); return redirect(url_for("file_manager",vps_id=vps_id,path=dest))
    fn   = f.filename.replace(" ","_")
    b64  = base64.b64encode(f.read()).decode()
    try: write_file_b64(vps["container_id"], dest.rstrip("/")+"/"+fn, b64); flash(f"Uploaded {fn}")
    except Exception as e: flash(f"Failed: {e}")
    return redirect(url_for("file_manager",vps_id=vps_id,path=dest))

@app.route("/vps/<int:vps_id>/files/delete", methods=["POST"])
@login_required
def file_delete(vps_id):
    vps  = _owned_vps(vps_id)
    if not vps: abort(404)
    path = request.form.get("path",""); back = request.form.get("back","/root")
    try: delete_file(vps["container_id"], path); flash(f"Deleted")
    except Exception as e: flash(f"Failed: {e}")
    return redirect(url_for("file_manager",vps_id=vps_id,path=back))

@app.route("/vps/<int:vps_id>/files/mkdir", methods=["POST"])
@login_required
def file_mkdir(vps_id):
    vps  = _owned_vps(vps_id)
    if not vps: abort(404)
    base = request.form.get("base","/root"); name = request.form.get("name","").strip()
    if not name: flash("Name required"); return redirect(url_for("file_manager",vps_id=vps_id,path=base))
    try: create_directory(vps["container_id"], base.rstrip("/")+"/"+name); flash("Created")
    except Exception as e: flash(f"Failed: {e}")
    return redirect(url_for("file_manager",vps_id=vps_id,path=base))


# ── Feedback ──────────────────────────────────────────────────────────────────

@app.route("/feedback", methods=["POST"])
@login_required
def submit_feedback():
    db  = get_db()
    vps = db.execute(
        "SELECT 1 FROM vps WHERE user_id=? AND status='running'", (current_user.id,)
    ).fetchone()
    if not vps: return "Need a running VPS", 403
    try: stars = int(request.form.get("stars",0))
    except: stars = 0
    if not (1 <= stars <= 5): return "Stars must be 1–5", 400
    comment = request.form.get("comment","").strip()[:500]
    db.execute("INSERT INTO feedback(user_id,stars,comment,created_at) VALUES(?,?,?,?)",
               (current_user.id, stars, comment, int(time.time())))
    db.commit()
    return redirect(url_for("dashboard"))


# ── Admin ─────────────────────────────────────────────────────────────────────

@app.route("/admin")
@login_required
def admin():
    if not current_user.is_admin: return "Forbidden", 403
    db    = get_db()
    vpses = db.execute(
        "SELECT vps.*,users.username FROM vps JOIN users ON users.id=vps.user_id"
    ).fetchall()
    users = db.execute(
        "SELECT id,username,signup_ip,is_admin,created_at,is_vpn_signup,vpn_provider FROM users"
    ).fetchall()
    bc    = db.execute("SELECT message,active FROM broadcast WHERE id=1").fetchone()
    host  = get_host_capacity()
    cfg   = {r["key"]:r["value"] for r in db.execute("SELECT key,value FROM panel_config").fetchall()}
    nat_rules = db.execute("SELECT * FROM nat_rules ORDER BY ssh_port").fetchall()
    return render_template("admin.html",
        vpses=vpses, users=users, broadcast=bc, host=host,
        config=cfg, nat_rules=nat_rules,
        max_vps=MAX_VPS_PER_NODE,
        queue_length=queue.queue_length(),
        host_kvm=kvm_available(),
        node_code=node_mesh.NODE_CODE,
        node_url=node_mesh.get_node_url(),
        public_ip=nat.get_public_ip(),
    )

@app.route("/admin/config", methods=["POST"])
@login_required
def admin_update_config():
    if not current_user.is_admin: return "Forbidden", 403
    db = get_db()
    for key in ("vps_cpu_cores","vps_ram_gb","vps_disk_gb"):
        val = request.form.get(key,"").strip()
        if val.isdigit() and int(val) > 0:
            db.execute("INSERT INTO panel_config(key,value) VALUES(?,?) "
                       "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, val))
    db.commit(); flash("Limits updated")
    return redirect(url_for("admin"))

@app.route("/admin/broadcast", methods=["POST"])
@login_required
def admin_broadcast_set():
    if not current_user.is_admin: return "Forbidden", 403
    msg = request.form.get("message","").strip()[:500]
    if not msg: flash("Empty"); return redirect(url_for("admin"))
    db = get_db()
    db.execute("UPDATE broadcast SET message=?,active=1,updated_at=? WHERE id=1",
               (msg, int(time.time()))); db.commit()
    flash("Broadcast posted"); return redirect(url_for("admin"))

@app.route("/admin/broadcast/clear", methods=["POST"])
@login_required
def admin_broadcast_clear():
    if not current_user.is_admin: return "Forbidden", 403
    get_db().execute("UPDATE broadcast SET active=0 WHERE id=1"); get_db().commit()
    flash("Cleared"); return redirect(url_for("admin"))

@app.route("/admin/grant-vps", methods=["POST"])
@login_required
def admin_grant_vps():
    if not current_user.is_admin: return "Forbidden", 403
    db       = get_db()
    username = request.form.get("username","").strip()
    try:
        cpu     = int(request.form.get("cpu_cores", 4))
        ram_gb  = int(request.form.get("ram_gb",    4))
        disk_gb = int(request.form.get("disk_gb",  80))
    except ValueError: flash("Invalid numbers"); return redirect(url_for("admin"))
    want_kvm = bool(request.form.get("kvm_enabled")) and kvm_available()
    if not username: flash("Username required"); return redirect(url_for("admin"))
    target = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not target: flash("User not found"); return redirect(url_for("admin"))
    cur = db.execute(
        "INSERT INTO vps(user_id,container_id,creator_ip,created_at,status,kvm_enabled)"
        " VALUES(?,?,?,?,'creating',?)",
        (target["id"],"pending","admin-grant",int(time.time()),int(want_kvm))
    )
    db.commit()
    vps_id = cur.lastrowid
    threading.Thread(target=_build_vps_custom,
                     args=(vps_id, target["id"], cpu, ram_gb*1024, disk_gb, want_kvm),
                     daemon=True).start()
    flash(f"VPS provisioning started for {username}")
    return redirect(url_for("admin"))

@app.route("/admin/vps/<int:vps_id>/<action>", methods=["POST"])
@login_required
def admin_vps_action(vps_id, action):
    if not current_user.is_admin: return "Forbidden", 403
    db  = get_db()
    vps = db.execute("SELECT * FROM vps WHERE id=?", (vps_id,)).fetchone()
    if not vps: flash("Not found"); return redirect(url_for("admin"))
    if action == "suspend":
        suspend_vps(vps["container_id"])
        db.execute("UPDATE vps SET status='suspended' WHERE id=?", (vps_id,))
    elif action == "unsuspend":
        unsuspend_vps(vps["container_id"])
        db.execute("UPDATE vps SET status='running' WHERE id=?", (vps_id,))
        # Reapply NAT
        nat_row = nat.get_nat_rule(db, vps_id)
        if nat_row:
            extra = [int(p) for p in nat_row["extra_ports"].split(",") if p.strip().isdigit()]
            nat.add_nat_rules(vps["container_id"], nat_row["container_ip"],
                              nat_row["ssh_port"], extra)
    elif action == "delete":
        try: nat.deprovision_nat(db, vps_id)
        except: pass
        try: destroy_vps(vps["container_id"])
        except: pass
        db.execute("DELETE FROM vps WHERE id=?", (vps_id,))
    elif action in ("enable_kvm","disable_kvm"):
        if not kvm_available(): flash("KVM not available"); return redirect(url_for("admin"))
        enable = action == "enable_kvm"
        if set_kvm_enabled(vps["container_id"], enable):
            db.execute("UPDATE vps SET kvm_enabled=? WHERE id=?", (int(enable), vps_id))
            flash(f"KVM {'enabled' if enable else 'disabled'}")
        else: flash("KVM toggle failed")
    db.commit()
    return redirect(url_for("admin"))


# ── Nodes ─────────────────────────────────────────────────────────────────────

@app.route("/admin/nodes", methods=["GET","POST"])
@login_required
def admin_nodes():
    if not current_user.is_admin: return "Forbidden", 403
    db = get_db(); result = None
    if request.method == "POST":
        remote_url  = request.form.get("remote_url","").strip()
        remote_code = request.form.get("remote_code","").strip()
        result = node_mesh.pair_with_node(db, remote_url, remote_code) \
                 if remote_url and remote_code else (False, "Enter both fields.")
    nodes = node_mesh.list_nodes(db)
    return render_template("admin_nodes.html", nodes=nodes, result=result,
                           my_code=node_mesh.NODE_CODE, my_url=node_mesh.get_node_url(),
                           max_vps=MAX_VPS_PER_NODE, now=int(time.time()))

@app.route("/admin/nodes/<int:node_id>/remove", methods=["POST"])
@login_required
def admin_node_remove(node_id):
    if not current_user.is_admin: return "Forbidden", 403
    db = get_db(); db.execute("DELETE FROM nodes WHERE id=?", (node_id,)); db.commit()
    flash("Node removed"); return redirect(url_for("admin_nodes"))


# ── Mesh API ──────────────────────────────────────────────────────────────────

@app.route("/api/node/pair", methods=["POST"])
def api_node_pair():
    code = request.headers.get("Authorization","")
    data = request.get_json(silent=True) or {}
    db   = get_db()
    ok, result = node_mesh.accept_pairing(db, code, data.get("my_url",""))
    if not ok: return jsonify({"error":result}), 403
    return jsonify({"shared_secret":result})

@app.route("/api/node/check_ip", methods=["POST"])
def api_node_check_ip():
    db = get_db()
    if not node_mesh.verify_peer_secret(db, request.headers.get("X-Node-Url",""),
                                         request.headers.get("Authorization","")):
        return jsonify({"error":"unauthorized"}), 403
    ip = (request.get_json(silent=True) or {}).get("ip","")
    has = bool(db.execute("SELECT 1 FROM vps WHERE creator_ip=?", (ip,)).fetchone())
    return jsonify({"has_vps":has})

@app.route("/api/node/stats", methods=["POST"])
def api_node_stats():
    db = get_db()
    peer_url = request.headers.get("X-Node-Url","")
    if not node_mesh.verify_peer_secret(db, peer_url, request.headers.get("Authorization","")):
        return jsonify({"error":"unauthorized"}), 403
    data = request.get_json(silent=True) or {}
    node_mesh.update_peer_stats(db, peer_url, data.get("vps_count",0),
                                 data.get("cpu_cores",0), data.get("ram_mb",0),
                                 data.get("disk_gb",0))
    return jsonify({"ok":True})

@app.route("/api/node/create_vps", methods=["POST"])
def api_node_create_vps():
    db = get_db()
    if not node_mesh.verify_peer_secret(db, request.headers.get("X-Node-Url",""),
                                         request.headers.get("Authorization","")):
        return jsonify({"error":"unauthorized"}), 403
    data = request.get_json(silent=True) or {}
    allowed, _ = can_create_vps()
    if not allowed: return jsonify({"error":"Node full"}), 503
    try:
        cid, ssh = create_vps_container(
            data.get("username","overflow"),
            cpu_limit=int(data.get("cpu",4)),
            ram_limit_mb=int(data.get("ram_mb",4096)),
            disk_limit_gb=int(data.get("disk_gb",80))
        )
        return jsonify({"container_id":cid,"ssh_url":ssh})
    except Exception as e:
        return jsonify({"error":str(e)}), 500

@app.route("/api/node/bootstrap_status")
@login_required
def api_bootstrap_status():
    if not current_user.is_admin: return jsonify({"error":"forbidden"}), 403
    logs = node_mesh.get_bootstrap_logs(request.args.get("url","").strip())
    return jsonify({"logs":logs,"done":any("complete" in l.lower() or "error" in l.lower() for l in logs[-3:])})

@app.route("/vps/stats_summary")
@login_required
def vps_stats_summary():
    if not current_user.is_admin: return jsonify({"error":"forbidden"}), 403
    db  = get_db()
    cnt = db.execute("SELECT COUNT(*) FROM vps WHERE status NOT IN ('failed','deleted')").fetchone()[0]
    return jsonify({"vps_count":cnt,"max":MAX_VPS_PER_NODE})

@app.route("/vps/<int:vps_id>")
@login_required
def vps_view(vps_id):
    return redirect(url_for("dashboard", vps_id=vps_id))


# ── Boot ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    db = get_db()
    nat.reapply_all_rules(db)
    db.close()
    print("="*55)
    print(f"  DeupGaming Free Panel")
    print(f"  Public IP : {nat.get_public_ip()}")
    print(f"  SSH ports : {nat.SSH_PORT_START}–{nat.SSH_PORT_END}")
    print(f"  Extra ports: {nat.EXTRA_PORT_START}–{nat.EXTRA_PORT_END}")
    print(f"  Node code : {node_mesh.NODE_CODE}")
    print("="*55)
    start_monitor()
    queue.start_queue_worker(_build_vps)
    app.run(host="0.0.0.0", port=5000, threaded=True)
