"""
NAT / iptables manager for shared-IP VPS hosting.

Each container gets:
  - 1 SSH port  (range 10000–10999) → forwards to container:22
  - 5 extra ports (range 11000–19999) → forwarded to container:same_port
    so users can expose web servers, bots, game servers, etc.

The host's public IP is auto-detected. All rules use iptables PREROUTING
DNAT + FORWARD ACCEPT. Rules are stored in the DB and re-applied on
panel startup so reboots don't wipe them.

Requirements on the host:
  apt install iptables
  echo 1 > /proc/sys/net/ipv4/ip_forward        # temporary
  echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf  # permanent
"""

import subprocess
import sqlite3
import os
import time
import urllib.request

SSH_PORT_START   = 10000
SSH_PORT_END     = 10999
EXTRA_PORT_START = 11000
EXTRA_PORT_END   = 19999
EXTRA_PORTS_PER_VPS = 5

DB = "panel.db"

# ── Public IP detection ──────────────────────────────────────────────────────

_cached_public_ip: str = ""

def get_public_ip() -> str:
    global _cached_public_ip
    if _cached_public_ip:
        return _cached_public_ip
    providers = [
        "https://api.ipify.org",
        "https://ipv4.icanhazip.com",
        "https://checkip.amazonaws.com",
    ]
    for url in providers:
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                ip = r.read().decode().strip()
                if ip:
                    _cached_public_ip = ip
                    return ip
        except Exception:
            continue
    # Fallback: first non-loopback IP
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        _cached_public_ip = ip
        return ip
    except Exception:
        return ""


# ── DB helpers ───────────────────────────────────────────────────────────────

def init_nat_tables(db):
    db.executescript("""
    CREATE TABLE IF NOT EXISTS nat_rules (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        vps_id       INTEGER NOT NULL UNIQUE,
        container_id TEXT NOT NULL,
        container_ip TEXT NOT NULL,
        ssh_port     INTEGER NOT NULL UNIQUE,
        extra_ports  TEXT NOT NULL DEFAULT '',
        created_at   INTEGER NOT NULL
    );
    """)
    try:
        db.execute("ALTER TABLE nat_rules ADD COLUMN extra_ports TEXT NOT NULL DEFAULT ''")
    except Exception:
        pass
    db.commit()


def get_nat_rule(db, vps_id: int) -> dict | None:
    row = db.execute("SELECT * FROM nat_rules WHERE vps_id=?", (vps_id,)).fetchone()
    if not row:
        return None
    return dict(row)


def _next_ssh_port(db) -> int:
    used = {r[0] for r in db.execute("SELECT ssh_port FROM nat_rules").fetchall()}
    for port in range(SSH_PORT_START, SSH_PORT_END + 1):
        if port not in used:
            return port
    raise RuntimeError("SSH port range exhausted (10000–10999)")


def _next_extra_ports(db, count: int = EXTRA_PORTS_PER_VPS) -> list[int]:
    used = set()
    for row in db.execute("SELECT extra_ports FROM nat_rules").fetchall():
        for p in (row[0] or "").split(","):
            if p.strip().isdigit():
                used.add(int(p.strip()))
    ports = []
    for port in range(EXTRA_PORT_START, EXTRA_PORT_END + 1):
        if port not in used:
            ports.append(port)
            if len(ports) == count:
                break
    if len(ports) < count:
        raise RuntimeError("Extra port range exhausted")
    return ports


# ── iptables helpers ─────────────────────────────────────────────────────────

def _ipt(*args, check=False) -> bool:
    cmd = ["iptables"] + list(args)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if check and result.returncode != 0:
            print(f"[NAT] iptables error: {result.stderr.strip()}")
        return result.returncode == 0
    except Exception as e:
        print(f"[NAT] iptables exception: {e}")
        return False


def _rule_exists(chain: str, *rule_args) -> bool:
    return _ipt("-t", "nat", "-C", chain, *rule_args)


def _ensure_ip_forward():
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1\n")
    except Exception as e:
        print(f"[NAT] Could not enable ip_forward: {e}")


def _get_container_ip(container_id: str) -> str:
    """Gets the LXC container's IP address."""
    try:
        result = subprocess.run(
            ["lxc", "list", container_id, "--format=csv", "--columns=4"],
            capture_output=True, text=True, timeout=10
        )
        output = result.stdout.strip()
        # output looks like: "10.x.x.x (eth0)"
        for part in output.split():
            if part.count(".") == 3 and not part.startswith("("):
                return part
    except Exception as e:
        print(f"[NAT] Could not get IP for {container_id}: {e}")
    return ""


def add_nat_rules(container_id: str, container_ip: str,
                  ssh_port: int, extra_ports: list[int]):
    """
    Adds iptables DNAT rules for SSH and extra ports.
    Idempotent — checks before adding.
    """
    _ensure_ip_forward()
    public_ip = get_public_ip()

    # SSH DNAT: host:ssh_port → container:22
    rule_ssh = [
        "PREROUTING", "-p", "tcp",
        "--dport", str(ssh_port),
        "-j", "DNAT",
        "--to-destination", f"{container_ip}:22"
    ]
    if not _rule_exists("nat", *rule_ssh[1:]):
        _ipt("-t", "nat", "-A", *rule_ssh, check=True)

    # FORWARD rule for SSH
    fwd_ssh = [
        "FORWARD", "-p", "tcp",
        "-d", container_ip,
        "--dport", "22",
        "-j", "ACCEPT"
    ]
    if not _ipt("-C", *fwd_ssh):
        _ipt("-A", *fwd_ssh, check=True)

    # Extra port DNAT
    for port in extra_ports:
        rule = [
            "PREROUTING", "-p", "tcp",
            "--dport", str(port),
            "-j", "DNAT",
            "--to-destination", f"{container_ip}:{port}"
        ]
        if not _rule_exists("nat", *rule[1:]):
            _ipt("-t", "nat", "-A", *rule, check=True)

        fwd = [
            "FORWARD", "-p", "tcp",
            "-d", container_ip,
            "--dport", str(port),
            "-j", "ACCEPT"
        ]
        if not _ipt("-C", *fwd):
            _ipt("-A", *fwd, check=True)

    # MASQUERADE so return traffic gets NAT'd back
    masq = [
        "POSTROUTING", "-s", f"{container_ip}/32",
        "-j", "MASQUERADE"
    ]
    if not _rule_exists("nat", *masq[1:]):
        _ipt("-t", "nat", "-A", *masq, check=True)

    print(f"[NAT] Rules added for {container_id} "
          f"(IP={container_ip}, SSH={ssh_port}, extra={extra_ports})")


def remove_nat_rules(container_ip: str, ssh_port: int, extra_ports: list[int]):
    """Removes all iptables rules for a container."""
    # SSH DNAT
    _ipt("-t", "nat", "-D", "PREROUTING", "-p", "tcp",
         "--dport", str(ssh_port), "-j", "DNAT",
         "--to-destination", f"{container_ip}:22")
    _ipt("-D", "FORWARD", "-p", "tcp",
         "-d", container_ip, "--dport", "22", "-j", "ACCEPT")

    for port in extra_ports:
        _ipt("-t", "nat", "-D", "PREROUTING", "-p", "tcp",
             "--dport", str(port), "-j", "DNAT",
             "--to-destination", f"{container_ip}:{port}")
        _ipt("-D", "FORWARD", "-p", "tcp",
             "-d", container_ip, "--dport", str(port), "-j", "ACCEPT")

    _ipt("-t", "nat", "-D", "POSTROUTING", "-s", f"{container_ip}/32",
         "-j", "MASQUERADE")

    print(f"[NAT] Rules removed for {container_ip}")


# ── High-level: provision NAT for a new VPS ──────────────────────────────────

def provision_nat(db, vps_id: int, container_id: str) -> dict:
    """
    Called after a container is created. Assigns ports, gets container IP,
    writes DB row, installs iptables rules.
    Returns {"ssh_port": N, "extra_ports": [...], "container_ip": "...", "public_ip": "..."}
    """
    # Wait up to 30s for the container to get an IP
    container_ip = ""
    for _ in range(15):
        container_ip = _get_container_ip(container_id)
        if container_ip:
            break
        time.sleep(2)

    if not container_ip:
        raise RuntimeError(
            f"Container {container_id} has no IP after 30s — "
            "is it running? Check: lxc list"
        )

    ssh_port   = _next_ssh_port(db)
    extra_ports = _next_extra_ports(db)

    add_nat_rules(container_id, container_ip, ssh_port, extra_ports)

    db.execute(
        "INSERT INTO nat_rules(vps_id, container_id, container_ip, ssh_port, "
        "extra_ports, created_at) VALUES(?,?,?,?,?,?)",
        (vps_id, container_id, container_ip, ssh_port,
         ",".join(str(p) for p in extra_ports), int(time.time()))
    )
    db.commit()

    return {
        "ssh_port":    ssh_port,
        "extra_ports": extra_ports,
        "container_ip": container_ip,
        "public_ip":   get_public_ip(),
    }


def deprovision_nat(db, vps_id: int):
    """Removes iptables rules and DB row for a VPS."""
    row = get_nat_rule(db, vps_id)
    if not row:
        return
    extra_ports = [int(p) for p in row["extra_ports"].split(",") if p.strip().isdigit()]
    remove_nat_rules(row["container_ip"], row["ssh_port"], extra_ports)
    db.execute("DELETE FROM nat_rules WHERE vps_id=?", (vps_id,))
    db.commit()


def reapply_all_rules(db):
    """
    Called on panel startup to restore all iptables rules after a reboot.
    iptables rules don't survive reboots by default.
    """
    _ensure_ip_forward()
    rows = db.execute("SELECT * FROM nat_rules").fetchall()
    if not rows:
        return
    print(f"[NAT] Reapplying {len(rows)} NAT rule sets after restart...")
    for row in rows:
        extra_ports = [int(p) for p in row["extra_ports"].split(",") if p.strip().isdigit()]
        add_nat_rules(row["container_id"], row["container_ip"],
                      row["ssh_port"], extra_ports)
    print("[NAT] All rules restored.")
