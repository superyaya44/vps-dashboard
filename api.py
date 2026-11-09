"""
VPS Infrastructure Dashboard - Status API
Flask API that checks all services on the VPS and returns JSON status.
Runs on port 8788.
"""

import os
import re
import json
import time
import socket
import sqlite3
import subprocess
import threading
import platform
from urllib.request import urlopen, Request
from urllib.error import URLError
from concurrent.futures import ThreadPoolExecutor, as_completed

from flask import Flask, jsonify, send_from_directory, request
import psutil
import re
import shlex
import hmac

app = Flask(__name__)

# Sécurité : CORS fermé (UI servie same-origin) + validation Origin/Host
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response

# Hosts autorisés — comparaison EXACTE uniquement. Ajoutez les vôtres via
# DASH_ALLOWED_HOSTS="host1,host2" (ex: hostname Tailscale).
_ALLOWED_HOSTS = {"localhost", "127.0.0.1", "::1"} | {
    h.strip().lower() for h in os.environ.get("DASH_ALLOWED_HOSTS", "").split(",") if h.strip()
}

def _host_ok(h):
    return (h or "").strip().lower() in _ALLOWED_HOSTS

# Actions (POST/PUT/PATCH/DELETE) : désactivées par défaut.
# Activer avec DASH_ENABLE_ACTIONS=1 ET fournir DASH_TOKEN (header X-Dash-Token).
DASH_TOKEN = os.environ.get("DASH_TOKEN", "")
DASH_ENABLE_ACTIONS = os.environ.get("DASH_ENABLE_ACTIONS", "") == "1"

@app.before_request
def _guard_host_origin():
    host = (request.host or "").split(":")[0]
    if not _host_ok(host):
        return jsonify({"error": "host not allowed"}), 403
    origin = request.headers.get("Origin")
    if origin is not None:
        if origin == "null":
            return jsonify({"error": "origin not allowed"}), 403
        if "//" in origin and not _host_ok(origin.split("//", 1)[1].split("/")[0].split(":")[0]):
            return jsonify({"error": "origin not allowed"}), 403
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        if not DASH_ENABLE_ACTIONS:
            return jsonify({"error": "actions disabled: set DASH_ENABLE_ACTIONS=1 and DASH_TOKEN"}), 503
        if not DASH_TOKEN:
            return jsonify({"error": "actions disabled: DASH_TOKEN not configured"}), 503
        tok = request.headers.get("X-Dash-Token", "")
        if not hmac.compare_digest(tok, DASH_TOKEN):
            return jsonify({"error": "invalid or missing token"}), 401
    # Sécurité : les logs peuvent contenir des secrets →
    # token requis aussi sur les routes GET qui exposent des logs
    elif DASH_TOKEN and request.path.endswith(("/logs", "/detail")):
        tok = request.headers.get("X-Dash-Token", "")
        if not hmac.compare_digest(tok, DASH_TOKEN):
            return jsonify({"error": "invalid or missing token"}), 401
    return None

HOST = "127.0.0.1"
TIMEOUT = 3
DASHBOARD_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(DASHBOARD_DIR, "data", "dashboard.db")
SERVICES_FILE = os.path.join(DASHBOARD_DIR, "services.json")

# ── Dynamic Services Loading ────────────────────────────────────────────────────

_services_cache = None
_services_file_mtime = None

def load_services(force_reload=False):
    """Load services from services.json file with caching."""
    global _services_cache, _services_file_mtime
    
    try:
        current_mtime = os.path.getmtime(SERVICES_FILE)
        if not force_reload and _services_cache is not None and _services_file_mtime == current_mtime:
            return _services_cache
        
        with open(SERVICES_FILE, 'r', encoding='utf-8') as f:
            services = json.load(f)
        
        _services_cache = services
        _services_file_mtime = current_mtime
        return services
    except FileNotFoundError:
        # If file doesn't exist, return empty list
        if _services_cache is None:
            _services_cache = []
        return _services_cache
    except json.JSONDecodeError as e:
        print(f"Error parsing services.json: {e}")
        if _services_cache is None:
            _services_cache = []
        return _services_cache

def get_services():
    """Get current services list."""
    return load_services()

def save_services(services):
    """Save services to services.json file."""
    global _services_cache, _services_file_mtime
    
    try:
        with open(SERVICES_FILE, 'w', encoding='utf-8') as f:
            json.dump(services, f, indent=2, ensure_ascii=False)
        
        _services_cache = services
        _services_file_mtime = os.path.getmtime(SERVICES_FILE)
        return True
    except Exception as e:
        print(f"Error saving services.json: {e}")
        return False

# ── Auto-Discovery ─────────────────────────────────────────────────────────────

# Ports système de base à ignorer
_DISCOVERY_DENY_PORTS = {22, 53, 111, 443, 631, 5355, 8788}
# Processus système à ignorer
_DISCOVERY_DENY_PROCS = {
    "systemd", "systemd-resolved", "systemd-journald", "dbus", "rpcbind",
    "cups", "cupsd", "accounts-daemon", "polkitd", "networkd", "chronyd",
    "unattended-upg", "snapd", "multipathd",
}

# Signature des browser tools éphémères (ports aléatoires, durée de vie courte).
# Préventif : tout service dont le cmdline ou le nom match cette regex n'est JAMAIS découvert.
_EPHEMERAL_BROWSER_RE = re.compile(
    r'agent browser|swiftshader|disable-dev-shm-usage|--window-size|ozone-platform|use-angle=swiftshader|linux arm64',
    re.I,
)

# Denylist persistante pour le bouton "Ignorer" : services auto-discovered que l'utilisateur
# ne veut plus voir réapparaître. Stockée dans data/ignored-signatures.json.
IGNORED_FILE = os.path.join(DASHBOARD_DIR, "data", "ignored-signatures.json")
_ignored_cache = None
_ignored_mtime = 0


def _load_ignored():
    """Charge la denylist avec cache mtime. Retourne une liste de dicts {name, signature, ignored_at}."""
    global _ignored_cache, _ignored_mtime
    try:
        m = os.path.getmtime(IGNORED_FILE)
    except OSError:
        return []
    if _ignored_cache is not None and m == _ignored_mtime:
        return _ignored_cache
    try:
        with open(IGNORED_FILE, "r", encoding="utf-8") as f:
            _ignored_cache = json.load(f)
            _ignored_mtime = m
            return _ignored_cache
    except (OSError, ValueError):
        return []


def _save_ignored(items):
    """Persiste la denylist."""
    global _ignored_cache, _ignored_mtime
    os.makedirs(os.path.dirname(IGNORED_FILE), exist_ok=True)
    with open(IGNORED_FILE, "w", encoding="utf-8") as f:
        json.dump(items, f, indent=2)
    _ignored_cache = items
    _ignored_mtime = os.path.getmtime(IGNORED_FILE)


def _make_signature(name):
    """Normalise un nom en signature: lower, sans UUID ni port.
    'Agent Browser Chrome F5E4E49E 5649...' -> 'agent browser chrome'."""
    import re as _re
    parts = name.lower().split()
    kept = []
    for p in parts:
        # saute les fragments uuid (8+ hex) et ports
        if _re.fullmatch(r"[0-9a-f]{8,}", p):
            continue
        if p.isdigit():
            continue
        kept.append(p)
    sig = " ".join(kept).strip()
    return sig or name.lower()


def _is_ignored(name):
    """True si le nom (exact) ou sa signature figure dans la denylist."""
    sig = _make_signature(name)
    for it in _load_ignored():
        if name == it.get("name"):
            return True
        itsig = it.get("signature")
        if itsig and itsig == sig:
            return True
        if itsig and len(itsig) >= 6 and itsig in name.lower():
            return True
    return False

def _resolve_unit_from_pid(pid):
    """Résout la systemd unit (system ou user) depuis le cgroup d'un PID.
    Returns (unit_name, is_user) ou (None, False)."""
    try:
        with open(f"/proc/{pid}/cgroup") as f:
            content = f.read()
        # System unit: /system.slice/<unit>.service
        m = re.search(r'/system\.slice/([a-zA-Z0-9@\-_:.]+\.service)', content)
        if m:
            return m.group(1), False
        # User unit: user@<uid>.service/.../<unit>.service
        m = re.search(r'/user@\d+\.service/.+/([a-zA-Z0-9@\-_:.]+\.service)', content)
        if m:
            return m.group(1), True
    except (IOError, OSError):
        pass
    return None, False

def _clean_name(raw):
    """Génère un nom propre depuis un nom d'unit systemd ou un chemin de script."""
    base = raw
    # Retirer le chemin
    if "/" in base:
        base = os.path.basename(base)
    # Retirer les extensions
    for ext in (".service", ".py", ".js", ".sh"):
        if base.endswith(ext):
            base = base[:-len(ext)]
    # Nettoyer les séparateurs
    return base.replace("-", " ").replace("_", " ").replace(".", " ").strip().title()

def discover_services():
    """Scanne les ports TCP en écoute et découvre les services non monitorés.
    Combine ss (ports) + /proc (cgroup, cmdline) pour identifier chaque service."""
    discovered = []
    
    # Ports et noms déjà connus
    current = get_services()
    known_ports = {s["port"] for s in current if s.get("port")}
    known_names = {s["name"] for s in current}
    
    # Scanner les ports en écoute
    try:
        result = subprocess.run(
            ["ss", "-tlnp"], capture_output=True, text=True, timeout=10
        )
        lines = result.stdout.strip().split("\n")[1:]  # skip header
    except Exception:
        return discovered
    
    # Pattern: ... addr:port ... users:(("proc",pid=N,...
    pattern = re.compile(
        r'\S+:(\d+)\s+\S+\s+.*?users:\(\("([^"]+)",pid=(\d+)'
    )
    
    for line in lines:
        m = pattern.search(line)
        if not m:
            continue
        port = int(m.group(1))
        proc_name = m.group(2)
        pid = int(m.group(3))
        
        # --- Filtrage ---
        if port in _DISCOVERY_DENY_PORTS:
            continue
        if port in known_ports:
            continue
        if proc_name in _DISCOVERY_DENY_PROCS:
            continue
        
        # Déterminer l'host d'écoute (priorité à l'IPv4)
        # Extraire l'adresse IPv4 de la ligne
        ipv4_match = re.search(r'([\d.]+):\d+\s', line)
        if ipv4_match:
            addr = ipv4_match.group(1)
            if addr == "0.0.0.0" or addr.startswith("100."):
                host = addr  # 0.0.0.0 ou IP Tailscale → IP réelle
            else:
                host = addr  # 127.0.0.1 ou autre
        else:
            # Pas d'IPv4, fallback sur IPv6
            host = "127.0.0.1"  # Par défaut pour [::1]
        
        # Résoudre la systemd unit via cgroup
        unit, is_user = _resolve_unit_from_pid(pid)
        systemd_unit = None
        if unit:
            systemd_unit = f"user:{unit}" if is_user else unit
        
        # Générer le nom (priorité au cmdline pour éviter la confusion des child processes)
        name = None
        cmdline_str = ""
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cmd_parts = [c.decode("utf-8", errors="replace")
                             for c in f.read().split(b"\x00") if c]
            cmdline_str = " ".join(cmd_parts)
            script = None
            for part in reversed(cmd_parts):
                if "/" in part or part.endswith((".py", ".js", ".sh")):
                    script = part
                    break
            if script:
                name = _clean_name(script)
        except (IOError, OSError):
            pass
        
        # Fallback sur le nom de l'unit systemd si pas de cmdline exploitable
        if not name and unit:
            name = _clean_name(unit)
        
        # Dernier fallback : nom du processus
        if not name:
            name = _clean_name(proc_name)
        
        # ── Filtrage préventif ──
        # 1. Browser éphémère (agent-browser tool) : jamais découvert, quelle que soit la version UUID.
        if _EPHEMERAL_BROWSER_RE.search(name) or _EPHEMERAL_BROWSER_RE.search(cmdline_str):
            continue
        # 2. Denylist utilisateur (bouton "Ignorer") : par nom exact ou signature normalisée.
        if _is_ignored(name):
            continue
        
        # Éviter les doublons de nom
        base_name = name
        suffix = 2
        while name in known_names:
            name = f"{base_name} {suffix}"
            suffix += 1
        
        # Déterminer le type de check : HTTP si le port répond à HTTP
        check_type = "tcp"
        try:
            from http.client import HTTPConnection
            conn = HTTPConnection("127.0.0.1", port, timeout=1)
            conn.request("HEAD", "/")
            conn.getresponse()
            conn.close()
            check_type = "http"
        except Exception:
            check_type = "tcp"
        
        svc = {
            "name": name,
            "category": "Auto-discovered",
            "port": port,
            "check": check_type,
            "host": host,
            "url_hint": f"http://{os.environ.get('DASH_PUBLIC_HOST', 'localhost')}:{port}",
            "systemd_unit": systemd_unit,
            "discovered_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        discovered.append(svc)
        known_ports.add(port)
        known_names.add(name)
    
    return discovered

def auto_sync_services():
    """Découvre et ajoute automatiquement les nouveaux services à services.json.
    Prune ensuite les services auto-discovered devenus morts (browser tools éphémères).
    Ne supprime jamais les services définis manuellement (sans discovered_at)."""
    discovered = discover_services()
    services = get_services()
    if discovered:
        services.extend(discovered)
        save_services(services)
    # Nettoyage rétroactif : retire les services auto-discovered désormais bloqués
    # par le filtre préventif (browser éphémère) ou la denylist utilisateur.
    pruned_now = _purge_blocked_discovered()
    return discovered


def _purge_blocked_discovered():
    """Retire des services.json les entrées auto-discovered (discovered_at présent)
    qui matchent désormais le filtre préventif (browser éphémère) ou la denylist.
    Ne touche jamais aux services manuels. Retourne le nb d'entrées retirées."""
    services = get_services()
    kept, removed = [], []
    for svc in services:
        if not isinstance(svc, dict) or not svc.get("discovered_at"):
            kept.append(svc)
            continue
        nm = svc.get("name", "")
        if _EPHEMERAL_BROWSER_RE.search(nm) or _is_ignored(nm):
            removed.append(svc)
        else:
            kept.append(svc)
    if removed:
        save_services(kept)
    return removed


# (La signature des browser éphémères _EPHEMERAL_BROWSER_RE est désormais définie
# plus haut, près des constantes _DISCOVERY_DENY, car elle sert aussi au filtrage
# préventif dans discover_services.)

def prune_stale_services():
    """Retire les services auto-discovered dont le port ne répond plus.
    Sécurité : ne touche JAMAIS aux services définis manuellement (sans discovered_at),
    et ne prune que les services dont le port est mort ET qui sont soit un browser
    éphémère (signature nom) soit sur un port dynamique (>32768, plage éphémère).
    Ainsi un vrai service qui redémarre temporairement n'est jamais supprimé."""
    services = get_services()
    if not services:
        return []
    try:
        ss = subprocess.run(["ss", "-tlnp"], capture_output=True, text=True, timeout=10).stdout
    except Exception:
        return []
    live_ports = set(re.findall(r':(\d+)\s', ss))
    kept, pruned = [], []
    for svc in services:
        if not isinstance(svc, dict):
            kept.append(svc); continue
        # Protection absolue : services définis à la main (sans discovered_at) jamais touchés
        if not svc.get("discovered_at"):
            kept.append(svc); continue
        port = svc.get("port")
        name = svc.get("name", "")
        port_dead = not port or str(port) not in live_ports
        is_ephemeral = bool(_EPHEMERAL_BROWSER_RE.search(name)) or (isinstance(port, int) and port > 32768)
        if port_dead and is_ephemeral:
            pruned.append(svc)
        else:
            kept.append(svc)
    if pruned:
        save_services(kept)
    return pruned

# ── SQLite Database ──────────────────────────────────────────────────────────

def init_db():
    """Create database tables if they don't exist."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS status_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        service_name TEXT NOT NULL,
        status TEXT NOT NULL,
        response_ms REAL,
        timestamp REAL NOT NULL
    )""")
    c.execute("""CREATE INDEX IF NOT EXISTS idx_history_name_ts
        ON status_history(service_name, timestamp)""")
    c.execute("""CREATE TABLE IF NOT EXISTS alert_config (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        service_name TEXT NOT NULL,
        metric TEXT NOT NULL DEFAULT 'offline_duration',
        threshold REAL NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 1,
        created_at REAL NOT NULL
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS alert_state (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        service_name TEXT NOT NULL,
        alert_type TEXT NOT NULL,
        triggered_at REAL NOT NULL,
        resolved_at REAL,
        active INTEGER NOT NULL DEFAULT 1
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS system_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        cpu_percent REAL NOT NULL,
        ram_percent REAL NOT NULL,
        ram_used_gb REAL NOT NULL,
        disk_percent REAL NOT NULL,
        disk_used_gb REAL NOT NULL,
        timestamp REAL NOT NULL
    )""")
    c.execute("""CREATE INDEX IF NOT EXISTS idx_system_ts
        ON system_history(timestamp)""")
    conn.commit()
    conn.close()

def record_status(service_name, status, response_ms):
    """Record a status snapshot to the database."""
    try:
        conn = sqlite3.connect(DB_PATH, timeout=5)
        conn.execute(
            "INSERT INTO status_history (service_name, status, response_ms, timestamp) VALUES (?, ?, ?, ?)",
            (service_name, status, response_ms, time.time())
        )
        conn.commit()
        conn.close()
    except Exception:
        pass

def get_db():
    """Get a database connection."""
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    return conn

def cleanup_old_data():
    """Remove data older than 7 days."""
    cutoff = time.time() - (7 * 86400)
    try:
        conn = sqlite3.connect(DB_PATH, timeout=5)
        conn.execute("DELETE FROM status_history WHERE timestamp < ?", (cutoff,))
        conn.commit()
        conn.close()
    except Exception:
        pass


def record_system_metrics():
    """Record system CPU/RAM/Disk to database."""
    try:
        cpu = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        conn = sqlite3.connect(DB_PATH, timeout=5)
        conn.execute(
            "INSERT INTO system_history (cpu_percent, ram_percent, ram_used_gb, disk_percent, disk_used_gb, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
            (cpu, mem.percent, round(mem.used / (1024**3), 2), disk.percent, round(disk.used / (1024**3), 2), time.time())
        )
        conn.commit()
        conn.close()
    except Exception:
        pass

# ── Background recorder ─────────────────────────────────────────────────────

_recorder_running = True

def background_recorder():
    """Record service statuses every 5 minutes."""
    global _recorder_running
    # Initial delay to let the app start
    time.sleep(10)
    while _recorder_running:
        try:
            services = []
            with ThreadPoolExecutor(max_workers=8) as pool:
                futs = {pool.submit(check_service, s): s for s in get_services()}
                for f in as_completed(futs):
                    result = f.result()
                    record_status(result["name"], result["status"], result.get("response_ms"))
                    services.append(result)
            # Evaluate alert rules
            evaluate_alerts(services)
        except Exception:
            pass
        # Record system metrics (CPU/RAM/Disk)
        try:
            record_system_metrics()
        except Exception:
            pass
        # Cleanup old data once per hour (every 12 cycles)
        try:
            cleanup_old_data()
        except Exception:
            pass
        # Prune stale auto-discovered services whose port died (browser tools éphémères)
        try:
            pruned = prune_stale_services()
            if pruned:
                print(f"[prune] {len(pruned)} stale service(s) removed: "
                      f"{', '.join(s.get('name', '?')[:30] for s in pruned)}")
        except Exception as e:
            print(f"[prune] error: {e}")
        # Auto-discover new services every cycle (fast scan)
        try:
            new_services = auto_sync_services()
            if new_services:
                print(f"[auto-discovery] {len(new_services)} new service(s) found: "
                      f"{', '.join(s['name'] for s in new_services)}")
        except Exception as e:
            print(f"[auto-discovery] error: {e}")
        # Sleep in small increments to allow clean shutdown
        for _ in range(30):
            if not _recorder_running:
                return
            time.sleep(10)

# ── Check helpers ────────────────────────────────────────────────────────────

def check_tcp(host, port):
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT):
            return "online", round((time.monotonic() - start) * 1000, 1)
    except (OSError, socket.timeout):
        return "offline", None

def check_http(host, port):
    from http.client import HTTPConnection
    start = time.monotonic()
    try:
        conn = HTTPConnection(host, port, timeout=TIMEOUT)
        conn.request("HEAD", "/")
        conn.getresponse()
        ms = round((time.monotonic() - start) * 1000, 1)
        conn.close()
        return "online", ms
    except Exception:
        return "offline", None

def check_process(match_str, exclude=None):
    start = time.monotonic()
    for proc in psutil.process_iter(["cmdline"]):
        try:
            cmdline = " ".join(proc.info["cmdline"] or [])
            if match_str in cmdline:
                if exclude and exclude in cmdline:
                    continue
                return "online", round((time.monotonic() - start) * 1000, 1)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return "offline", None

def check_service(svc):
    ct = svc["check"]
    host = svc.get("host", HOST)
    if ct == "tcp":
        status, ms = check_tcp(host, svc["port"])
    elif ct == "http":
        # Essayer HTTP d'abord, fallback TCP si échou
        status, ms = check_http(host, svc["port"])
        if status != "online":
            # Fallback automatique HTTP → TCP
            status, ms = check_tcp(host, svc["port"])
    elif ct == "process":
        status, ms = check_process(svc["match"], svc.get("exclude"))
    else:
        status, ms = "unknown", None
    return {
        "name": svc["name"], "category": svc["category"],
        "port": svc.get("port"), "status": status,
        "response_ms": ms, "url_hint": svc.get("url_hint", ""),
        "systemd_unit": svc.get("systemd_unit"),
        "muted": bool(svc.get("muted", False)),
    }

# ── System metrics ───────────────────────────────────────────────────────────

def get_system_metrics():
    cpu = psutil.cpu_percent(interval=0.5)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    l1, l5, l15 = os.getloadavg()
    uptime_s = int(time.time() - psutil.boot_time())
    d, r = divmod(uptime_s, 86400)
    h, r = divmod(r, 3600)
    m, _ = divmod(r, 60)
    return {
        "hostname": socket.gethostname(),
        "os": "Ubuntu 24.04 LTS",
        "cpu_count": os.cpu_count(),
        "cpu_percent": cpu,
        "ram": {
            "total_gb": round(mem.total / (1024**3), 1),
            "used_gb": round(mem.used / (1024**3), 1),
            "free_gb": round(mem.available / (1024**3), 1),
            "percent": mem.percent,
        },
        "disk": {
            "total_gb": round(disk.total / (1024**3), 1),
            "used_gb": round(disk.used / (1024**3), 1),
            "free_gb": round(disk.free / (1024**3), 1),
            "percent": disk.percent,
        },
        "load": {"1min": round(l1, 2), "5min": round(l5, 2), "15min": round(l15, 2)},
        "uptime_human": f"{d}d {h}h {m}m",
    }

# ── Service action helpers ───────────────────────────────────────────────────

def _split_user_unit(unit):
    """Return (is_user, unit_name) from a systemd_unit string.

    Convention: prefix "user:" indicates a systemd --user unit.
    """
    if unit and unit.startswith("user:"):
        return True, unit.split(":", 1)[1]
    return False, unit


def _user_systemctl_env():
    """Find ubuntu user's D-Bus session for systemctl --user invocations.

    The dashboard runs as a system service, so `systemctl --user` would
    otherwise try to talk to root's user bus and fail with
    "No medium found" / "Failed to connect to bus".
    """
    import pwd
    try:
        pw = pwd.getpwnam("ubuntu")
    except KeyError:
        return {}, None
    uid = pw.pw_uid
    runtime = f"/run/user/{uid}"
    bus = f"{runtime}/bus"
    env = {
        "XDG_RUNTIME_DIR": runtime,
        "DBUS_SESSION_BUS_ADDRESS": f"unix:path={bus}",
    }
    return env, uid


def run_systemctl(unit, action):
    """Run a systemctl command. Returns (success, output).

    Supports "user:NAME" prefix to invoke systemctl --user for the ubuntu user
    (needs D-Bus env since the dashboard runs as a system service).
    """
    is_user, unit = _split_user_unit(unit)
    # Sécurité : validation stricte unit + action
    if action not in ("start", "stop", "restart", "status"):
        return False, "Invalid action"
    if not re.fullmatch(r"[A-Za-z0-9_.@:\\-]+", unit or ""):
        return False, "Invalid unit name"
    try:
        if is_user:
            env, uid = _user_systemctl_env()
            cmd = ["systemctl", "--user", action, unit]
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30,
                env={**os.environ, **env}, user=uid,
            )
        else:
            result = subprocess.run(
                ["sudo", "systemctl", action, unit],
                capture_output=True, text=True, timeout=30
            )
        output = result.stdout.strip() or result.stderr.strip() or "OK"
        return result.returncode == 0, output
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except Exception as e:
        return False, str(e)

def run_docker_action(container_name, action):
    """Run a docker start/stop/restart command."""
    docker_action = {"start": "start", "stop": "stop", "restart": "restart"}.get(action, "restart")
    try:
        result = subprocess.run(
            ["sudo", "docker", docker_action, container_name],
            capture_output=True, text=True, timeout=60
        )
        output = result.stdout.strip() or result.stderr.strip() or "OK"
        return result.returncode == 0, output
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except Exception as e:
        return False, str(e)

def get_service_logs(systemd_unit, lines=50):
    """Get recent logs for a service."""
    if not systemd_unit:
        return "No log source configured for this service."
    
    # Docker containers
    if systemd_unit.startswith("docker:"):
        container = systemd_unit.split(":", 1)[1]
        try:
            result = subprocess.run(
                ["sudo", "docker", "logs", "--tail", str(lines), container],
                capture_output=True, text=True, timeout=15
            )
            return result.stdout[-3000:] if len(result.stdout) > 3000 else result.stdout
        except Exception as e:
            return f"Error fetching logs: {e}"
    
    # Systemd services
    is_user, unit = _split_user_unit(systemd_unit)
    try:
        if is_user:
            env, uid = _user_systemctl_env()
            cmd = ["journalctl", "--user", "-u", unit, "-n", str(lines), "--no-pager"]
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=15,
                env={**os.environ, **env}, user=uid,
            )
        else:
            cmd = ["sudo", "journalctl", "-u", unit, "-n", str(lines), "--no-pager"]
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=15
            )
        return result.stdout[-3000:] if len(result.stdout) > 3000 else result.stdout
    except Exception as e:
        return f"Error fetching logs: {e}"

def get_service_action_target(svc):
    """Get the actionable target (systemd unit or docker container)."""
    unit = svc.get("systemd_unit")
    if not unit:
        return None, None
    if unit.startswith("docker:"):
        return "docker", unit.split(":", 1)[1]
    if unit.startswith("user:"):
        return "systemd", unit  # keep prefix so run_systemctl picks --user
    return "systemd", unit


@app.route("/")
def serve_dashboard():
    return send_from_directory(DASHBOARD_DIR, "index.html")

@app.route("/favicon.svg")
def favicon_svg():
    return send_from_directory(DASHBOARD_DIR, "favicon.svg", mimetype="image/svg+xml")

@app.route("/favicon.ico")
def favicon_ico():
    # Redirect legacy .ico requests to the SVG (all modern browsers handle this)
    return send_from_directory(DASHBOARD_DIR, "favicon.svg", mimetype="image/svg+xml")

@app.route("/api/status")
def status():
    services = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        futs = {pool.submit(check_service, s): s for s in get_services()}
        for f in as_completed(futs):
            services.append(f.result())
    services.sort(key=lambda s: (0 if s["status"] == "online" else 1, s["name"]))
    return jsonify({
        "services": services,
        "system": get_system_metrics(),
        "timestamp": time.time(),
    })

@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "service": "vps-dashboard-api"})

# ── Agent-friendly endpoints ────────────────────────────────────────────────

@app.route("/api/summary")
def summary():
    """Agent-friendly text summary of the VPS. Designed for LLM consumption."""
    services = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        futs = {pool.submit(check_service, s): s for s in get_services()}
        for f in as_completed(futs):
            services.append(f.result())
    
    system = get_system_metrics()
    
    online = [s for s in services if s["status"] == "online" and not s.get("muted")]
    offline = [s for s in services if s["status"] == "offline" and not s.get("muted")]
    
    # Active alerts
    conn = get_db()
    alert_count = conn.execute("SELECT COUNT(*) as c FROM alert_state WHERE active = 1").fetchone()["c"]
    conn.close()
    
    # Build text summary
    lines = []
    lines.append(f"🖥️ **VPS Dashboard** — {system['hostname']}")
    lines.append(f"⏱️ Uptime: {system['uptime_human']} | CPU: {system['cpu_percent']}% | RAM: {system['ram']['percent']}% ({system['ram']['used_gb']}/{system['ram']['total_gb']}GB)")
    lines.append(f"💾 Disk: {system['disk']['percent']}% ({system['disk']['used_gb']}/{system['disk']['total_gb']}GB) | Load: {system['load']['1min']}/{system['load']['5min']}/{system['load']['15min']}")
    lines.append("")
    lines.append(f"✅ **{len(online)} online** | ❌ **{len(offline)} offline** | 🔔 **{alert_count} alerts**")
    
    if offline:
        lines.append("")
        lines.append("**❌ OFFLINE:**")
        for s in offline:
            ms = f" ({s['response_ms']}ms)" if s.get("response_ms") else ""
            lines.append(f"  • {s['name']} [{s['category']}]{ms}")
    
    if alert_count > 0:
        conn = get_db()
        alerts = conn.execute(
            "SELECT service_name, alert_type, triggered_at FROM alert_state WHERE active = 1 ORDER BY triggered_at DESC"
        ).fetchall()
        conn.close()
        lines.append("")
        lines.append("**🔔 ACTIVE ALERTS:**")
        for a in alerts:
            dur = int(time.time() - a["triggered_at"])
            if dur > 3600:
                dur_str = f"{dur//3600}h{(dur%3600)//60}m"
            else:
                dur_str = f"{dur//60}m"
            lines.append(f"  • {a['service_name']}: {a['alert_type']} (since {dur_str})")
    
    return jsonify({
        "text": "\n".join(lines),
        "online_count": len(online),
        "offline_count": len(offline),
        "alert_count": alert_count,
        "offline_services": [s["name"] for s in offline],
        "system": system,
    })

@app.route("/api/services")
def list_services():
    """List all monitored services with names, categories, and ports."""
    result = []
    for s in get_services():
        result.append({
            "name": s["name"],
            "category": s["category"],
            "port": s.get("port"),
            "check": s["check"],
            "url_hint": s.get("url_hint", ""),
            "systemd_unit": s.get("systemd_unit"),
        })
    return jsonify({"services": result, "count": len(result)})

# ── Detail & Action endpoints ────────────────────────────────────────────────

@app.route("/api/service/<name>/detail")
def service_detail(name):
    """Get detailed info for a service: sparkline data, logs, uptime stats."""
    svc = next((s for s in get_services() if s["name"] == name), None)
    if not svc:
        return jsonify({"error": "Service not found"}), 404
    
    # Current status
    current = check_service(svc)
    
    # Sparkline: last 30 minutes of data, 1 point per minute
    now = time.time()
    thirty_min_ago = now - 1800
    conn = get_db()
    rows = conn.execute(
        "SELECT timestamp, status, response_ms FROM status_history "
        "WHERE service_name = ? AND timestamp > ? ORDER BY timestamp",
        (name, thirty_min_ago)
    ).fetchall()
    conn.close()
    
    sparkline = []
    for r in rows:
        sparkline.append({
            "ts": r["timestamp"],
            "status": r["status"],
            "response_ms": r["response_ms"],
        })
    
    # Uptime stats: last 7 days
    seven_days_ago = now - (7 * 86400)
    conn = get_db()
    total_checks = conn.execute(
        "SELECT COUNT(*) as c FROM status_history "
        "WHERE service_name = ? AND timestamp > ?",
        (name, seven_days_ago)
    ).fetchone()["c"]
    online_checks = conn.execute(
        "SELECT COUNT(*) as c FROM status_history "
        "WHERE service_name = ? AND timestamp > ? AND status = 'online'",
        (name, seven_days_ago)
    ).fetchone()["c"]
    
    # Count status transitions to online (restarts)
    transitions = conn.execute(
        "SELECT COUNT(*) as c FROM status_history h1 "
        "WHERE h1.service_name = ? AND h1.timestamp > ? AND h1.status = 'online' "
        "AND EXISTS (SELECT 1 FROM status_history h2 "
        "WHERE h2.service_name = ? AND h2.timestamp < h1.timestamp "
        "AND h2.timestamp > ? AND h2.status = 'offline' "
        "ORDER BY h2.timestamp DESC LIMIT 1)",
        (name, seven_days_ago, name, seven_days_ago)
    ).fetchone()["c"]
    conn.close()
    
    uptime_pct = round((online_checks / total_checks * 100), 1) if total_checks > 0 else None
    
    # Actionable target
    action_type, action_target = get_service_action_target(svc)
    
    # Recent logs
    logs = get_service_logs(svc.get("systemd_unit"), 50)
    
    return jsonify({
        "name": name,
        "category": current["category"],
        "status": current["status"],
        "response_ms": current["response_ms"],
        "port": current["port"],
        "url_hint": current["url_hint"],
        "sparkline": sparkline,
        "uptime_7d_pct": uptime_pct,
        "restarts_7d": transitions,
        "total_checks_7d": total_checks,
        "action_type": action_type,
        "action_target": action_target,
        "logs": logs,
        "systemd_unit": svc.get("systemd_unit"),
        "muted": current.get("muted", False),
    })

@app.route("/api/service/<name>/action", methods=["POST"])
def service_action(name):
    """Execute an action on a service: start, stop, restart.
    After the action, polls the service until the status matches the expected state.
    Returns the confirmed status so the frontend can update immediately."""
    svc = next((s for s in get_services() if s["name"] == name), None)
    if not svc:
        return jsonify({"error": "Service not found"}), 404
    
    body = request.get_json(silent=True) or {}
    action = body.get("action")
    if action not in ("start", "stop", "restart"):
        return jsonify({"error": "Invalid action. Use: start, stop, restart"}), 400
    
    action_type, action_target = get_service_action_target(svc)
    
    if not action_target:
        return jsonify({"error": "No action target configured for this service"}), 400
    
    if action_type == "docker":
        success, output = run_docker_action(action_target, action)
    else:
        success, output = run_systemctl(action_target, action)
    
    if not success:
        return jsonify({
            "success": False,
            "action": action,
            "target": action_target,
            "output": output,
            "status": None,
        })
    
    # Expected final state
    expected = "online" if action in ("start", "restart") else "offline"
    
    # Poll the service until status matches (max 15 seconds)
    confirmed_status = None
    for i in range(15):
        time.sleep(1)
        result = check_service(svc)
        confirmed_status = result["status"]
        if confirmed_status == expected:
            break
    
    return jsonify({
        "success": True,
        "action": action,
        "target": action_target,
        "output": output,
        "status": confirmed_status,
        "response_ms": result.get("response_ms"),
    })

@app.route("/api/service/<name>/logs")
def service_logs(name):
    """Get recent logs for a service. Query params: lines (default 50)."""
    svc = next((s for s in get_services() if s["name"] == name), None)
    if not svc:
        return jsonify({"error": "Service not found"}), 404

    try:
        lines = int(request.args.get("lines", 50))
        lines = max(1, min(lines, 500))
    except (ValueError, TypeError):
        lines = 50

    action_type, action_target = get_service_action_target(svc)

    logs = get_service_logs(svc.get("systemd_unit"), lines)

    return jsonify({
        "service": name,
        "lines": lines,
        "log_type": action_type or "unknown",
        "logs": logs,
    })

@app.route("/api/service/<name>/timeline")
def service_timeline(name):
    """Get 24h uptime timeline with 10-minute granularity."""
    svc = next((s for s in get_services() if s["name"] == name), None)
    if not svc:
        return jsonify({"error": "Service not found"}), 404
    
    now = time.time()
    twenty_four_h_ago = now - 86400
    
    conn = get_db()
    rows = conn.execute(
        "SELECT timestamp, status FROM status_history "
        "WHERE service_name = ? AND timestamp > ? ORDER BY timestamp",
        (name, twenty_four_h_ago)
    ).fetchall()
    conn.close()
    
    # Bucket into 10-minute segments
    bucket_size = 600  # 10 min
    buckets = {}
    for r in rows:
        bucket_start = int(r["timestamp"] // bucket_size) * bucket_size
        if bucket_start not in buckets:
            buckets[bucket_start] = {"online": 0, "offline": 0}
        if r["status"] == "online":
            buckets[bucket_start]["online"] += 1
        else:
            buckets[bucket_start]["offline"] += 1
    
    # Build timeline segments
    timeline = []
    current_bucket = int(twenty_four_h_ago // bucket_size) * bucket_size
    while current_bucket <= now:
        data = buckets.get(current_bucket)
        if data:
            total = data["online"] + data["offline"]
            status = "online" if data["online"] > data["offline"] else "offline"
        else:
            status = "no_data"
            total = 0
        
        timeline.append({
            "start": current_bucket,
            "end": current_bucket + bucket_size,
            "status": status,
            "sample_count": total,
        })
        current_bucket += bucket_size
    
    return jsonify({
        "service": name,
        "timeline": timeline,
        "bucket_seconds": bucket_size,
    })

# ── Alerts endpoints ─────────────────────────────────────────────────────────

def evaluate_alerts(current_services):
    """Evaluate alert rules against current service states. Returns list of active alerts."""
    now = time.time()
    conn = get_db()
    
    # Get all enabled alert configs
    configs = conn.execute(
        "SELECT * FROM alert_config WHERE enabled = 1"
    ).fetchall()
    
    # Build service lookup
    svc_map = {}
    for s in current_services:
        svc_map[s["name"]] = s
    
    new_alerts = []
    
    for cfg in configs:
        svc_name = cfg["service_name"]
        metric = cfg["metric"]
        threshold = cfg["threshold"]
        svc = svc_map.get(svc_name)
        if not svc:
            continue
        
        triggered = False
        alert_desc = ""
        
        if metric == "offline_duration":
            # Check how long the service has been offline
            if svc["status"] == "offline":
                # Find last online timestamp
                last_online = conn.execute(
                    "SELECT MAX(timestamp) as ts FROM status_history "
                    "WHERE service_name = ? AND status = 'online'",
                    (svc_name,)
                ).fetchone()["ts"]
                if last_online:
                    offline_seconds = now - last_online
                    if offline_seconds >= threshold:
                        triggered = True
                        mins = int(offline_seconds / 60)
                        alert_desc = f"Offline for {mins} min (threshold: {int(threshold/60)} min)"
                else:
                    triggered = True
                    alert_desc = f"Never seen online (threshold: {int(threshold/60)} min)"
        
        elif metric == "response_ms":
            if svc["status"] == "online" and svc.get("response_ms") is not None:
                if svc["response_ms"] > threshold:
                    triggered = True
                    alert_desc = f"Latency {svc['response_ms']:.0f}ms (threshold: {threshold:.0f}ms)"
        
        # Check if there's already an active alert for this
        existing = conn.execute(
            "SELECT id FROM alert_state "
            "WHERE service_name = ? AND alert_type = ? AND active = 1",
            (svc_name, metric)
        ).fetchone()
        
        if triggered:
            if not existing:
                # Create new alert
                conn.execute(
                    "INSERT INTO alert_state (service_name, alert_type, triggered_at, active) VALUES (?, ?, ?, 1)",
                    (svc_name, metric, now)
                )
                new_alerts.append({"service": svc_name, "type": metric, "desc": alert_desc})
        else:
            if existing:
                # Resolve existing alert
                conn.execute(
                    "UPDATE alert_state SET active = 0, resolved_at = ? WHERE id = ?",
                    (now, existing["id"])
                )
    
    conn.commit()
    conn.close()
    return new_alerts

@app.route("/api/alerts")
def get_alerts():
    """Get all active alerts."""
    conn = get_db()
    alerts = conn.execute(
        "SELECT * FROM alert_state WHERE active = 1 ORDER BY triggered_at DESC"
    ).fetchall()
    conn.close()
    
    result = []
    for a in alerts:
        result.append({
            "id": a["id"],
            "service_name": a["service_name"],
            "alert_type": a["alert_type"],
            "triggered_at": a["triggered_at"],
            "duration_sec": round(time.time() - a["triggered_at"]),
        })
    
    return jsonify({"alerts": result, "count": len(result)})

@app.route("/api/alerts/config", methods=["GET"])
def get_alert_configs():
    """Get all alert configurations."""
    conn = get_db()
    configs = conn.execute("SELECT * FROM alert_config ORDER BY service_name").fetchall()
    conn.close()
    result = [dict(c) for c in configs]
    return jsonify({"configs": result, "count": len(result)})

@app.route("/api/alerts/config", methods=["POST"])
def create_alert_config():
    """Create or update an alert configuration."""
    body = request.get_json(silent=True) or {}
    service_name = body.get("service_name")
    metric = body.get("metric", "offline_duration")
    threshold = body.get("threshold")
    
    if not service_name or threshold is None:
        return jsonify({"error": "service_name and threshold are required"}), 400
    
    if metric not in ("offline_duration", "response_ms"):
        return jsonify({"error": "metric must be 'offline_duration' or 'response_ms'"}), 400
    
    # Verify service exists
    svc = next((s for s in get_services() if s["name"] == service_name), None)
    if not svc:
        return jsonify({"error": "Service not found"}), 404
    
    conn = get_db()
    # Check if config already exists for this service+metric
    existing = conn.execute(
        "SELECT id FROM alert_config WHERE service_name = ? AND metric = ?",
        (service_name, metric)
    ).fetchone()
    
    if existing:
        conn.execute(
            "UPDATE alert_config SET threshold = ?, enabled = 1 WHERE id = ?",
            (threshold, existing["id"])
        )
    else:
        conn.execute(
            "INSERT INTO alert_config (service_name, metric, threshold, enabled, created_at) VALUES (?, ?, ?, 1, ?)",
            (service_name, metric, threshold, time.time())
        )
    
    conn.commit()
    conn.close()
    
    return jsonify({"success": True, "service_name": service_name, "metric": metric, "threshold": threshold})

@app.route("/api/alerts/config/<int:config_id>", methods=["DELETE"])
def delete_alert_config(config_id):
    """Delete an alert configuration."""
    conn = get_db()
    conn.execute("DELETE FROM alert_config WHERE id = ?", (config_id,))
    conn.commit()
    conn.close()
    return jsonify({"success": True})

@app.route("/api/alerts/config/<int:config_id>/toggle", methods=["POST"])
def toggle_alert_config(config_id):
    """Enable or disable an alert configuration."""
    conn = get_db()
    cfg = conn.execute("SELECT enabled FROM alert_config WHERE id = ?", (config_id,)).fetchone()
    if not cfg:
        conn.close()
        return jsonify({"error": "Config not found"}), 404
    new_state = 0 if cfg["enabled"] else 1
    conn.execute("UPDATE alert_config SET enabled = ? WHERE id = ?", (new_state, config_id))
    conn.commit()
    conn.close()
    return jsonify({"success": True, "enabled": bool(new_state)})

# ── Ollama Model Management ──────────────────────────────────────────────────

OLLAMA_URL = "http://localhost:11434"

def _ollama_get(path, timeout=5):
    """Simple GET to Ollama API, returns parsed JSON or raises."""
    req = Request(f"{OLLAMA_URL}{path}")
    resp = urlopen(req, timeout=timeout)
    return json.loads(resp.read().decode())

@app.route("/api/ollama/models")
def ollama_models():
    """List downloaded models with running status."""
    try:
        downloaded = _ollama_get("/api/tags").get("models", [])
    except Exception:
        return jsonify({"models": [], "error": "Ollama not reachable"})

    try:
        running_list = _ollama_get("/api/ps").get("models", [])
        running_names = {m["name"] for m in running_list}
        running_details = {m["name"]: m for m in running_list}
    except Exception:
        running_names = set()
        running_details = {}

    models = []
    for m in downloaded:
        name = m["name"]
        is_running = name in running_names
        details = running_details.get(name, {})
        size_gb = m.get("size", 0) / (1024**3)
        model_details = m.get("details", {})

        models.append({
            "name": name,
            "id": m.get("digest", "")[:12],
            "size_gb": round(size_gb, 1),
            "family": model_details.get("family", ""),
            "parameter_size": model_details.get("parameter_size", ""),
            "quantization": model_details.get("quantization_level", ""),
            "format": model_details.get("format", ""),
            "running": is_running,
            "context_length": details.get("context_length"),
            "expires_at": details.get("expires_at"),
            "size_vram_gb": round(details.get("size_vram", 0) / (1024**3), 2) if is_running else 0,
        })

    models.sort(key=lambda m: (not m["running"], m["name"]))
    return jsonify({"models": models, "count": len(models)})


@app.route("/api/ollama/models/<path:name>/stop", methods=["POST"])
def ollama_model_stop(name):
    """Unload a model from RAM."""
    # Sécurité : validation du nom de modèle (pas d'injection d'options)
    if name.startswith("-") or not re.fullmatch(r"[A-Za-z0-9_.:/\-]+", name or ""):
        return jsonify({"success": False, "error": "Invalid model name"}), 400
    try:
        result = subprocess.run(
            ["ollama", "stop", name],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            return jsonify({"success": True, "action": "stop", "model": name})
        else:
            return jsonify({"success": False, "error": result.stderr.strip() or "Unknown error"})
    except subprocess.TimeoutExpired:
        return jsonify({"success": False, "error": "Timeout stopping model"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/api/ollama/models/<path:name>/start", methods=["POST"])
def ollama_model_start(name):
    """Load a model into RAM. Runs in background thread, returns immediately."""
    # Sécurité : validation du nom de modèle (pas d'injection d'options)
    if name.startswith("-") or not re.fullmatch(r"[A-Za-z0-9_.:/\-]+", name or ""):
        return jsonify({"success": False, "error": "Invalid model name"}), 400
    def _load_model(model_name):
        try:
            subprocess.run(
                ["ollama", "run", model_name, "--keepalive", "30m", "/noload"],
                capture_output=True, text=True, timeout=300
            )
        except Exception:
            pass

    # Check model exists
    try:
        downloaded = {m["name"] for m in _ollama_get("/api/tags").get("models", [])}
        if name not in downloaded:
            return jsonify({"success": False, "error": f"Model '{name}' not found"}), 404
    except Exception:
        return jsonify({"success": False, "error": "Ollama not reachable"}), 503

    # Check already running
    try:
        running = {m["name"] for m in _ollama_get("/api/ps").get("models", [])}
        if name in running:
            return jsonify({"success": True, "action": "start", "model": name, "status": "already_running"})
    except Exception:
        pass

    # Fire background load
    t = threading.Thread(target=_load_model, args=(name,), daemon=True)
    t.start()
    return jsonify({"success": True, "action": "start", "model": name, "status": "loading"})


# ── System History (Charts 24h) ──────────────────────────────────────────────

@app.route("/api/system/history")
def system_history():
    """Get 24h system metrics for charts. Returns CPU, RAM, Disk time series."""
    now = time.time()
    twenty_four_h_ago = now - 86400

    conn = get_db()
    rows = conn.execute(
        "SELECT cpu_percent, ram_percent, ram_used_gb, disk_percent, disk_used_gb, timestamp "
        "FROM system_history WHERE timestamp > ? ORDER BY timestamp",
        (twenty_four_h_ago,)
    ).fetchall()
    conn.close()

    data = []
    for r in rows:
        data.append({
            "ts": r["timestamp"],
            "cpu": r["cpu_percent"],
            "ram_pct": r["ram_percent"],
            "ram_gb": r["ram_used_gb"],
            "disk_pct": r["disk_percent"],
            "disk_gb": r["disk_used_gb"],
        })

    return jsonify({"data": data, "count": len(data)})

# ── Service Process Info ─────────────────────────────────────────────────────

def get_process_info(match_str, exclude=None):
    """Get detailed process info for a service by matching cmdline."""
    for proc in psutil.process_iter(["pid", "cmdline", "cpu_percent", "memory_percent", "create_time", "name"]):
        try:
            cmdline = " ".join(proc.info["cmdline"] or [])
            if match_str in cmdline:
                if exclude and exclude in cmdline:
                    continue
                mem_info = proc.memory_info()
                cpu_times = proc.cpu_times()
                uptime_s = int(time.time() - proc.info["create_time"])
                d, r = divmod(uptime_s, 86400)
                h, r = divmod(r, 3600)
                m, _ = divmod(r, 60)
                return {
                    "pid": proc.info["pid"],
                    "name": proc.info["name"],
                    "uptime_human": f"{d}d {h}h {m}m",
                    "uptime_seconds": uptime_s,
                    "cpu_percent": round(proc.cpu_percent(interval=0.1), 1),
                    "memory_percent": round(proc.info["memory_percent"] or 0, 1),
                    "memory_rss_mb": round(mem_info.rss / (1024**2), 1),
                    "memory_vms_mb": round(mem_info.vms / (1024**2), 1),
                    "cmdline": cmdline[:200],
                }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return None

@app.route("/api/service/<name>/process")
def service_process_info(name):
    """Get process details for a service: PID, RAM, CPU, uptime."""
    svc = next((s for s in get_services() if s["name"] == name), None)
    if not svc:
        return jsonify({"error": "Service not found"}), 404

    if svc["check"] == "process":
        info = get_process_info(svc["match"], svc.get("exclude"))
    else:
        # For TCP/HTTP services, try to find the process listening on the port
        info = None
        if svc.get("port"):
            try:
                for conn in psutil.net_connections(kind="inet"):
                    if conn.laddr.port == svc["port"] and conn.status == "LISTEN":
                        try:
                            proc = psutil.Process(conn.pid)
                            mem_info = proc.memory_info()
                            uptime_s = int(time.time() - proc.create_time())
                            d, r = divmod(uptime_s, 86400)
                            h, r = divmod(r, 3600)
                            m, _ = divmod(r, 60)
                            info = {
                                "pid": proc.pid,
                                "name": proc.name(),
                                "uptime_human": f"{d}d {h}h {m}m",
                                "uptime_seconds": uptime_s,
                                "cpu_percent": round(proc.cpu_percent(interval=0.1), 1),
                                "memory_percent": round(proc.memory_percent(), 1),
                                "memory_rss_mb": round(mem_info.rss / (1024**2), 1),
                                "memory_vms_mb": round(mem_info.vms / (1024**2), 1),
                                "cmdline": " ".join(proc.cmdline())[:200],
                            }
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                        break
            except Exception:
                pass

    return jsonify({
        "service": name,
        "process": info,
    })


@app.route("/api/restart-offline", methods=["POST"])
def restart_all_offline():
    """Restart all offline services that have an action target. Returns results."""
    results = []
    services = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        futs = {pool.submit(check_service, s): s for s in get_services()}
        for f in as_completed(futs):
            services.append(f.result())

    # Exclude muted services — user has acknowledged they're intentionally down
    offline = [s for s in services if s["status"] == "offline" and not s.get("muted")]
    restarted = 0
    failed = 0

    for s in offline:
        svc = next((x for x in get_services() if x["name"] == s["name"]), None)
        if not svc:
            continue
        action_type, action_target = get_service_action_target(svc)
        if not action_target:
            results.append({"service": s["name"], "status": "skipped", "reason": "No action target"})
            continue

        if action_type == "docker":
            success, output = run_docker_action(action_target, "start")
        else:
            success, output = run_systemctl(action_target, "start")

        if success:
            restarted += 1
            results.append({"service": s["name"], "status": "restarted", "output": output})
        else:
            failed += 1
            results.append({"service": s["name"], "status": "failed", "error": output})

    return jsonify({
        "total_offline": len(offline),
        "restarted": restarted,
        "failed": failed,
        "results": results,
    })


# ── Restart All Services ─────────────────────────────────────────────────────

# Services excluded from "Restart All" for safety reasons
RESTART_ALL_EXCLUDE = {
    "SSH",                   # would kill our own connection
    "vps-dashboard.service",  # would kill the dashboard mid-restart
}


@app.route("/api/restart-all", methods=["POST"])
def restart_all_services():
    """Restart every service that has an action target, except safety-excluded ones."""
    results = []
    restarted = 0
    failed = 0
    skipped = 0

    for svc in get_services():
        name = svc["name"]
        unit = svc.get("systemd_unit") or ""
        if name in RESTART_ALL_EXCLUDE or unit in RESTART_ALL_EXCLUDE:
            skipped += 1
            results.append({"service": name, "status": "skipped", "reason": "safety-excluded"})
            continue

        action_type, action_target = get_service_action_target(svc)
        if not action_target:
            skipped += 1
            results.append({"service": name, "status": "skipped", "reason": "No action target"})
            continue

        if action_type == "docker":
            success, output = run_docker_action(action_target, "restart")
        else:
            success, output = run_systemctl(action_target, "restart")

        if success:
            restarted += 1
            results.append({"service": name, "status": "restarted", "output": output})
        else:
            failed += 1
            results.append({"service": name, "status": "failed", "error": output})

    return jsonify({
        "total": len(get_services()),
        "restarted": restarted,
        "failed": failed,
        "skipped": skipped,
        "results": results,
    })


# ── Top Processes ────────────────────────────────────────────────────────────

@app.route("/api/top-processes")
def top_processes():
    """Return top 10 processes by CPU (sampled) and top 10 by RAM."""
    # Collect all processes with fresh cpu sample
    procs = []
    for p in psutil.process_iter(['pid', 'name', 'memory_percent',
                                   'memory_info', 'username', 'cmdline']):
        try:
            info = p.info
            # Skip kernel threads (no cmdline, pid < 100 often, but check rss=0 and no cmdline)
            mem_mb = info['memory_info'].rss / (1024 * 1024) if info['memory_info'] else 0.0
            cmd = ' '.join(info['cmdline']) if info['cmdline'] else ''
            if not cmd and mem_mb == 0:
                continue
            procs.append({
                "pid": info['pid'],
                "name": info['name'],
                "cpu_percent": 0.0,  # filled below
                "memory_mb": round(mem_mb, 1),
                "memory_percent": round(info['memory_percent'] or 0.0, 2),
                "username": info['username'] or '',
                "cmdline": cmd[:120],
            })
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
            continue

    # Quick CPU sample (non-blocking, uses /proc/stat delta)
    try:
        cpu_map = {p.pid: p for p in psutil.process_iter(['pid', 'cpu_percent'])}
        for proc in procs:
            entry = cpu_map.get(proc['pid'])
            if entry:
                try:
                    proc['cpu_percent'] = round(entry.info['cpu_percent'] or 0.0, 1)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
    except Exception:
        pass

    by_cpu = sorted(procs, key=lambda x: x['cpu_percent'], reverse=True)[:10]
    by_ram = sorted(procs, key=lambda x: x['memory_mb'], reverse=True)[:10]

    return jsonify({"cpu": by_cpu, "ram": by_ram})


# ── Top Disk Consumers ───────────────────────────────────────────────────────

_DISK_CACHE = os.path.join(os.path.dirname(__file__), "data", "top-disk.json")


@app.route("/api/top-disk")
def api_top_disk():
    """Return cached top 10 largest files and directories."""
    try:
        with open(_DISK_CACHE, "r") as f:
            data = json.load(f)
        return jsonify(data)
    except FileNotFoundError:
        return jsonify({"files": [], "dirs": [], "error": "Cache not found. Run cache-top-disk.py first."})
    except Exception as e:
        return jsonify({"files": [], "dirs": [], "error": str(e)})


# ── Disk Recommendations (LLM-powered) ───────────────────────────────────────

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
DISK_RECO_MODEL = os.environ.get("DISK_RECO_MODEL", "gemma4:12b")


@app.route("/api/disk-recommendations")
def api_disk_recommendations():
    """Serve pre-cached disk recommendations (generated by cron every 30min)."""
    reco_cache = os.path.join(os.path.dirname(__file__), "data", "disk-recommendations.json")
    executed_file = os.path.join(os.path.dirname(__file__), "data", "disk-executed-actions.json")
    
    # Load executed commands
    executed_cmds = set()
    try:
        with open(executed_file) as f:
            executed_list = json.load(f)
        executed_cmds = {e.get("command", "").strip() for e in executed_list if e.get("command")}
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    
    try:
        with open(reco_cache) as f:
            data = json.load(f)
        # Mark executed recommendations
        for reco in data.get("recommendations", []):
            cmd = reco.get("command", "").strip()
            if cmd in executed_cmds:
                reco["executed"] = True
            else:
                reco["executed"] = False
        # Check freshness (max 2 hours old)
        generated = data.get("generated_at", "")
        if generated:
            from datetime import datetime, timedelta, timezone
            gen_time = datetime.fromisoformat(generated.replace("Z", "+00:00"))
            age = datetime.now(timezone.utc) - gen_time
            if age > timedelta(hours=2):
                return jsonify({**data, "warning": f"Cache is {age}".replace("0:00:00", "") + " old, cron may be down"})
        return jsonify(data)
    except FileNotFoundError:
        return jsonify({"error": "Recommendations not yet generated. Wait for next cron run.", "recommendations": []})
    except Exception as e:
        return jsonify({"error": f"Failed to read cache: {e}", "recommendations": []})


@app.route("/api/disk-cleanup", methods=["POST"])
def api_disk_cleanup():
    """Execute selected cleanup commands. Requires approval-style confirmation."""
    data = request.get_json(silent=True) or {}
    actions = data.get("actions", [])
    if not actions:
        return jsonify({"error": "No actions provided", "results": []})

    # Sécurité : ALLOWLIST stricte — seules les commandes générées par le serveur
    # (data/disk-recommendations.json, rafraîchi par cron) sont exécutables.
    # La blocklist reste en seconde couche.
    def _iter_cmds(o):
        if isinstance(o, dict):
            if isinstance(o.get("command"), str):
                yield o["command"].strip()
            for v in o.values():
                yield from _iter_cmds(v)
        elif isinstance(o, list):
            for v in o:
                yield from _iter_cmds(v)
    allowed_cmds = set()
    try:
        with open(os.path.join(DASHBOARD_DIR, "data", "disk-recommendations.json")) as f:
            allowed_cmds = {c for c in _iter_cmds(json.load(f)) if c}
    except (FileNotFoundError, json.JSONDecodeError):
        pass

    # Safety: blocklist of dangerous patterns
    BLOCKED = [
        "rm -rf / ", "rm -rf /", "rm -rf ~", "rm -rf /home ", "rm -rf " + os.path.expanduser("~"),
        "rm -rf /etc", "rm -rf /var", "rm -rf /usr", "rm -rf /opt",
        "mkfs", "dd if=", ":(){ :|:& };:",
        "shutdown", "reboot", "init 0", "init 6",
        "systemctl stop", "systemctl disable",
        "apt remove", "apt purge", "snap remove",
    ]

    # 2026-09-19: exécution sans TTY — docker prune sans -f bloque sur [y/N].
    # Auto-ajout du flag force pour ne jamais attendre un stdin.
    INTERACTIVE_FIXES = [
        # (préfixe command, version forcée)
        ("docker volume prune", "docker volume prune -f"),
        ("docker network prune", "docker network prune -f"),
        ("docker builder prune", "docker builder prune -f"),
        ("docker container prune", "docker container prune -f"),
        ("docker image prune", None),   # géré ci-dessous (garde le --filter)
        ("docker system prune", "docker system prune -f"),
    ]
    def make_non_interactive(c):
        low = c.lower().rstrip()
        if low == "docker image prune":
            return "docker image prune -af"
        if low.startswith("docker image prune ") and " -f" not in low and " -a" not in low.split("prune",1)[1][:3]:
            return c.rstrip() + " -f"
        if low.startswith("docker image prune") and " -f" not in low:
            return c.rstrip() + " -f"
        for prefix, forced in INTERACTIVE_FIXES:
            if forced and (low == prefix or low.startswith(prefix + " ") and " -f" not in low):
                return forced
        if (low.startswith("apt ") or low.startswith("apt-get ") or low.startswith("sudo apt ") or low.startswith("sudo apt-get ")) and " -y" not in low and any(w in low for w in ("autoremove", "clean", "purge", "remove", "install", "upgrade")):
            return c.rstrip() + " -y"
        return c

    results = []
    for action in actions:
        cmd = action.get("command", "").strip()
        title = action.get("action", "Unknown")

        if not cmd:
            results.append({"action": title, "success": False, "output": "Empty command"})
            continue

        # Sécurité : commande hors allowlist serveur → refus
        if cmd not in allowed_cmds:
            results.append({"action": title, "success": False, "output": "BLOCKED: command not in server-generated recommendations"})
            continue

        # Safety check — exact prefix match, not substring
        cmd_lower = cmd.lower().rstrip()
        blocked = False
        for b in BLOCKED:
            b_lower = b.lower()
            if cmd_lower == b_lower or cmd_lower.startswith(b_lower + " ") or cmd_lower.startswith(b_lower + "/"):
                # Allow /tmp and <home>/.cache subdirs for cleanup
                if b_lower.startswith("rm -rf"):
                    target = cmd_lower[len("rm -rf "):].strip()
                    home = os.path.expanduser("~").lower()
                    if target.startswith("/tmp") or target.startswith(home + "/.cache") or target.startswith(home + "/.npm") or target.startswith(home + "/.local"):
                        blocked = False
                        continue
                blocked = True
                break
        if blocked:
            results.append({"action": title, "success": False, "output": "BLOCKED: command matches dangerous pattern"})
            continue

        # 2026-09-19: garantir non-interactif (auto -f/-y), exécution sans TTY
        fixed_cmd = make_non_interactive(cmd)
        if fixed_cmd != cmd:
            print(f"[disk-cleanup] auto-force non-interactive: {cmd!r} -> {fixed_cmd!r}")
            cmd = fixed_cmd

        try:
            # Sécurité : exécution sans shell (argv + shell=False),
            # commande déjà validée par l'allowlist serveur
            argv = shlex.split(cmd)
            result = subprocess.run(
                argv, shell=False, capture_output=True, text=True, timeout=60,
                stdin=subprocess.DEVNULL,
            )
            output = result.stdout.strip() or result.stderr.strip() or f"Exit code: {result.returncode}"
            results.append({
                "action": title,
                "command": cmd,
                "success": result.returncode == 0,
                "output": output[:500],
            })
        except subprocess.TimeoutExpired:
            results.append({"action": title, "command": cmd, "success": False, "output": "TIMEOUT after 60s"})
        except Exception as e:
            results.append({"action": title, "command": cmd, "success": False, "output": str(e)})

    # Track successful actions
    executed_file = os.path.join(os.path.dirname(__file__), "data", "disk-executed-actions.json")
    executed_list = []
    try:
        with open(executed_file) as f:
            executed_list = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    
    from datetime import datetime, timezone
    for r in results:
        if r.get("success"):
            executed_list.append({
                "action": r.get("action", ""),
                "command": r.get("command", ""),
                "executed_at": datetime.now(timezone.utc).isoformat(),
            })
    
    # Keep only last 50 entries
    executed_list = executed_list[-50:]
    with open(executed_file, "w") as f:
        json.dump(executed_list, f, indent=2)

    return jsonify({"results": results})


# ── Dynamic Services Management ───────────────────────────────────────────────────

@app.route("/api/services", methods=["GET"])
def list_all_services():
    """Get all services definitions."""
    services = get_services()
    return jsonify({"services": services})


# Sécurité : validation stricte du schéma service.
# Interdit notamment un '-' en tête des noms d'unité/conteneur/modèle (injection d'options).
_ALLOWED_CHECKS = {"http", "tcp", "process", "docker", "none"}

def validate_service_schema(data, partial=False):
    if not isinstance(data, dict):
        return "Invalid payload: object expected"
    def _bad(field, why):
        return f"Invalid {field}: {why}"
    if not partial or "name" in data:
        name = data.get("name")
        if not isinstance(name, str) or not (1 <= len(name.strip()) <= 100):
            return _bad("name", "1-100 characters expected")
    if not partial or "check" in data:
        if data.get("check") not in _ALLOWED_CHECKS:
            return _bad("check", f"allowed values {sorted(_ALLOWED_CHECKS)}")
    if "port" in data and data.get("port") is not None:
        port = data["port"]
        if not isinstance(port, int) or isinstance(port, bool) or not (1 <= port <= 65535):
            return _bad("port", "integer 1-65535 expected")
    if not partial or "category" in data:
        cat = data.get("category")
        if not isinstance(cat, str) or not (1 <= len(cat.strip()) <= 50):
            return _bad("category", "1-50 characters expected")
    for field in ("systemd_unit", "docker_container", "model", "profile"):
        v = data.get(field)
        if v is None:
            continue
        if not isinstance(v, str) or v.startswith("-"):
            return _bad(field, "leading '-' forbidden")
        if len(v) > 200 or not re.fullmatch(r"[A-Za-z0-9_.@:/\\-]*", v):
            return _bad(field, "forbidden characters")
    uh = data.get("url_hint")
    if uh is not None:
        if not isinstance(uh, str) or len(uh) > 300 or not (uh.startswith("http://") or uh.startswith("https://")):
            return _bad("url_hint", "absolute http(s) URL expected")
    return None


@app.route("/api/services", methods=["POST"])
def add_service():
    """Add a new service to the monitoring list."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "No data provided"}), 400
    
    # Required fields
    required_fields = ["name", "category", "check"]
    for field in required_fields:
        if field not in data:
            return jsonify({"error": f"Missing required field: {field}"}), 400

    # Sécurité : validation stricte du schéma
    err = validate_service_schema(data)
    if err:
        return jsonify({"error": err}), 400
    
    services = get_services()
    
    # Check if service with same name already exists
    if any(s["name"] == data["name"] for s in services):
        return jsonify({"error": "Service with this name already exists"}), 400
    
    # Add service
    services.append(data)
    
    if save_services(services):
        return jsonify({"success": True, "service": data}), 201
    else:
        return jsonify({"error": "Failed to save services"}), 500


@app.route("/api/services/<name>", methods=["PUT"])
def update_service(name):
    """Update an existing service."""
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "No data provided"}), 400

    # Sécurité : validation stricte du schéma (update partiel)
    err = validate_service_schema(data, partial=True)
    if err:
        return jsonify({"error": err}), 400
    services = get_services()
    
    # Find service
    service_index = None
    for i, s in enumerate(services):
        if s["name"] == name:
            service_index = i
            break
    
    if service_index is None:
        return jsonify({"error": "Service not found"}), 404
    
    # Update service (merge instead of replace to preserve fields)
    existing = services[service_index]
    existing.update(data)
    # Handle rename: if name changed, update it; otherwise keep old
    if "name" not in data:
        existing["name"] = name
    services[service_index] = existing
    
    if save_services(services):
        return jsonify({"success": True, "service": data})
    else:
        return jsonify({"error": "Failed to save services"}), 500


@app.route("/api/services/<name>", methods=["DELETE"])
def delete_service(name):
    """Delete a service from the monitoring list."""
    services = get_services()
    
    # Find and remove service
    initial_length = len(services)
    services = [s for s in services if s["name"] != name]
    
    if len(services) == initial_length:
        return jsonify({"error": "Service not found"}), 404
    
    if save_services(services):
        return jsonify({"success": True, "message": f"Service '{name}' deleted"})
    else:
        return jsonify({"error": "Failed to save services"}), 500


# ── Bouton "Ignorer" (denylist persistante) ──────────────────────────────────

@app.route("/api/services/<name>/ignore", methods=["POST"])
def ignore_service(name):
    """Ajoute un service à la denylist (nom + signature), et le retire immédiatement
    de services.json pour qu'il disparaisse du dashboard. Les futures occurrences
    (même nom ou même signature) ne seront plus auto-découvertes."""
    ignored = _load_ignored()
    # Évite les doublons
    if not any(it.get("name") == name for it in ignored):
        ignored.append({
            "name": name,
            "signature": _make_signature(name),
            "ignored_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        })
        _save_ignored(ignored)
    # Retire le service actuel de services.json s'il existe
    services = get_services()
    filtered = [s for s in services if s.get("name") != name]
    if len(filtered) != len(services):
        save_services(filtered)
    return jsonify({
        "success": True,
        "message": f"Service '{name}' ignoré et masqué",
        "signature": _make_signature(name),
        "ignored_count": len(ignored),
    })


@app.route("/api/services/<name>/unignore", methods=["POST"])
def unignore_service(name):
    """Retire un service de la denylist. Il pourra réapparaître à la prochaine découverte."""
    ignored = _load_ignored()
    before = len(ignored)
    ignored = [it for it in ignored if it.get("name") != name]
    _save_ignored(ignored)
    removed = before - len(ignored)
    return jsonify({
        "success": True,
        "message": f"Service '{name}' restauré" if removed else f"'{name}' n'était pas ignoré",
        "removed": removed,
        "ignored_count": len(ignored),
    })


@app.route("/api/services/ignored", methods=["GET"])
def list_ignored():
    """Liste les signatures actuellement dans la denylist."""
    return jsonify({"ignored": _load_ignored(), "count": len(_load_ignored())})


@app.route("/api/services/reload", methods=["POST"])
def reload_services():
    """Force reload services from file."""
    load_services(force_reload=True)
    services = get_services()
    return jsonify({
        "success": True,
        "message": "Services reloaded from file",
        "count": len(services)
    })


@app.route("/api/services/discover", methods=["POST"])
def discover_endpoint():
    """Trigger auto-discovery: scanne les ports en écoute et ajoute les services inconnus."""
    discovered = auto_sync_services()
    return jsonify({
        "success": True,
        "discovered_count": len(discovered),
        "discovered": discovered,
        "total_services": len(get_services()),
    })


@app.route("/api/services/suggest-categories", methods=["POST"])
def suggest_categories_endpoint():
    """Analyse les services Auto-discovered et propose une réorganisation intelligente.
    Utilise des règles heuristiques basées sur les noms, ports, systemd_units."""
    services = get_services()
    
    # Récupérer les catégories existantes (pour proposer de les utiliser)
    existing_categories = set(s.get("category") for s in services if s.get("category") != "Auto-discovered")
    
    # Filtrer les services Auto-discovered
    auto_services = [s for s in services if s.get("category") == "Auto-discovered"]
    
    if not auto_services:
        return jsonify({
            "success": True,
            "message": "Aucun service Auto-discovered à réorganiser",
            "suggestions": []
        })
    
    # Règles heuristiques pour suggérer des catégories
    suggestions = []
    
    # Catégories existantes avec leurs patterns
    category_patterns = {
        "Web": ["web", "http", "html", "dashboard", "panel", "ui", "front"],
        "AI Agents": ["agent", "ai", "llm", "gpt", "claude", "model", "gateway"],
        "Automation": ["automation", "cron", "scheduler", "job", "worker", "bot"],
        "Network": ["network", "proxy", "vpn", "tailscale", "wireguard", "router"],
        "Database": ["db", "database", "sql", "postgres", "mysql", "mongo", "redis"],
        "Storage": ["storage", "file", "s3", "minio", "nfs", "samba"],
        "Media": ["media", "video", "audio", "stream", "transcode", "ffmpeg"],
    }
    
    for svc in auto_services:
        name = svc.get("name", "").lower()
        systemd_unit = (svc.get("systemd_unit") or "").lower()
        port = svc.get("port", 0)
        
        # Chercher une catégorie correspondante
        suggested_cat = None
        confidence = 0
        
        for cat, patterns in category_patterns.items():
            if cat in existing_categories:
                # Priorité aux catégories existantes
                for pattern in patterns:
                    if pattern in name or pattern in systemd_unit:
                        suggested_cat = cat
                        confidence = 0.8
                        break
                if suggested_cat:
                    break
        
        # Règles spéciales basées sur systemd_unit
        if not suggested_cat:
            if "gateway" in systemd_unit:
                suggested_cat = "AI Agents" if "AI Agents" in existing_categories else "AI Agents (nouveau)"
                confidence = 0.9
            elif "n8n" in systemd_unit:
                suggested_cat = "Automation" if "Automation" in existing_categories else "Automation (nouveau)"
                confidence = 0.9
            elif "tailscale" in systemd_unit:
                suggested_cat = "Network" if "Network" in existing_categories else "Network (nouveau)"
                confidence = 0.9
        
        # Règles basées sur le port
        if not suggested_cat:
            if port in [3000, 8080, 8000, 5000]:
                suggested_cat = "Web"
                confidence = 0.6
            elif port in [5432, 3306, 6379, 27017]:
                suggested_cat = "Database"
                confidence = 0.8
        
        # Si toujours pas de catégorie, proposer "Other"
        if not suggested_cat:
            suggested_cat = "Other"
            confidence = 0.3
        
        suggestions.append({
            "service_name": svc.get("name"),
            "service_port": svc.get("port"),
            "suggested_category": suggested_cat,
            "confidence": confidence,
            "reason": f"Basé sur: name='{name}', systemd_unit='{systemd_unit}', port={port}"
        })
    
    # Trier par confiance décroissante
    suggestions.sort(key=lambda x: x["confidence"], reverse=True)
    
    return jsonify({
        "success": True,
        "existing_categories": sorted(list(existing_categories)),
        "auto_discovered_count": len(auto_services),
        "suggestions": suggestions,
    })


@app.route("/api/services/apply-suggestions", methods=["POST"])
def apply_category_suggestions_endpoint():
    """Applique les suggestions de catégories aux services Auto-discovered."""
    data = request.get_json()
    suggestions = data.get("suggestions", [])
    
    if not suggestions:
        return jsonify({
            "success": False,
            "message": "Aucune suggestion à appliquer"
        }), 400
    
    services = get_services()
    updated_count = 0
    
    for svc in services:
        # Trouver la suggestion correspondante
        suggestion = next((s for s in suggestions if s["service_name"] == svc.get("name")), None)
        if suggestion and svc.get("category") == "Auto-discovered":
            # Nettoyer le nom de catégorie (enlever "(nouveau)")
            suggested_cat = suggestion["suggested_category"].replace(" (nouveau)", "")
            svc["category"] = suggested_cat
            updated_count += 1
    
    if updated_count > 0:
        save_services(services)
        load_services(force_reload=True)
    
    return jsonify({
        "success": True,
        "updated_count": updated_count,
        "message": f"{updated_count} services réorganisés"
    })


# ── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    init_db()
    
    # Start background recorder thread
    recorder_thread = threading.Thread(target=background_recorder, daemon=True)
    recorder_thread.start()
    
    port = int(os.environ.get("API_PORT", 8788))
    print(f"Starting VPS Dashboard on http://127.0.0.1:{port}")
    print(f"Database: {DB_PATH}")
    print(f"Background recorder: every 5 min")
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=port, debug=False)
