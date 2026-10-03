"""
DeupGaming Free Panel — first-run setup.
Sets admin account + per-VPS resource limits.
"""
import sqlite3, getpass, time
from werkzeug.security import generate_password_hash

DB = "panel.db"

def init():
    con = sqlite3.connect(DB)
    c   = con.cursor()
    c.executescript("""
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
    CREATE TABLE IF NOT EXISTS nat_rules (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        vps_id       INTEGER NOT NULL UNIQUE,
        container_id TEXT NOT NULL,
        container_ip TEXT NOT NULL,
        ssh_port     INTEGER NOT NULL UNIQUE,
        extra_ports  TEXT NOT NULL DEFAULT '',
        created_at   INTEGER NOT NULL
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
    con.execute("INSERT OR IGNORE INTO broadcast(id,message,active,updated_at) VALUES(1,'',0,0)")
    con.commit()

    c.execute("SELECT COUNT(*) FROM users WHERE is_admin=1")
    if c.fetchone()[0] == 0:
        print("\n╔══════════════════════════════════════╗")
        print("║   DeupGaming Free Panel — First Run  ║")
        print("╚══════════════════════════════════════╝\n")
        username = input("  Admin username: ").strip()
        while not username:
            username = input("  Cannot be empty: ").strip()
        password = getpass.getpass("  Admin password: ")
        while len(password) < 6:
            password = getpass.getpass("  Min 6 chars: ")
        con.execute(
            "INSERT INTO users(username,password,signup_ip,is_admin,created_at,recovery_code_shown)"
            " VALUES(?,?,?,1,?,1)",
            (username, generate_password_hash(password), "127.0.0.1", int(time.time()))
        )
        con.commit()
        print(f"\n  ✓ Admin '{username}' created.")
    else:
        print("\n  Admin already exists — skipping.")

    # Per-VPS resource limits
    existing = {r[0]:r[1] for r in con.execute("SELECT key,value FROM panel_config").fetchall()}
    keys = ["vps_cpu_cores","vps_ram_gb","vps_disk_gb"]
    if any(k not in existing for k in keys):
        print("\n[ Per-VPS Resource Limits ]")
        def ask_int(prompt, default, lo, hi):
            while True:
                raw = input(f"  {prompt} [{default}]: ").strip()
                if not raw: return default
                try:
                    v = int(raw)
                    if lo <= v <= hi: return v
                    print(f"    Must be {lo}–{hi}")
                except ValueError:
                    print("    Enter a number")
        cpu  = ask_int("CPU cores (1–32)",  4,  1, 32)
        ram  = ask_int("RAM GB (1–256)",     4,  1, 256)
        disk = ask_int("Disk GB (5–2000)",  80,  5, 2000)
        for k,v in [("vps_cpu_cores",str(cpu)),("vps_ram_gb",str(ram)),("vps_disk_gb",str(disk))]:
            con.execute("INSERT INTO panel_config(key,value) VALUES(?,?) "
                        "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (k,v))
        con.commit()
        print(f"\n  ✓ Each VPS: {cpu} vCPU / {ram}GB RAM / {disk}GB disk")
    else:
        print(f"\n  Limits already set: "
              f"{existing['vps_cpu_cores']} vCPU / {existing['vps_ram_gb']}GB RAM / {existing['vps_disk_gb']}GB disk")

    con.close()
    print("\n  Setup complete. Run: python3 -u app.py\n")

if __name__ == "__main__":
    init()
