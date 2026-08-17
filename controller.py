#!/usr/bin/env python3
import argparse
import json
import os
import re
import shlex
import shutil
import socket
import signal
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CONFIG_PATH = ROOT / "config" / "config.json"
BIN_PATH = ROOT / "bin" / "sentinelwaf"
SERVICE_NAME = "SentinelWAF WAF"
PID_NAME = "waf.pid"
OUT_NAME = "waf.out.log"

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
WHITE = "\033[97m"
DIM = "\033[2m"
RESET = "\033[0m"
BOLD = "\033[1m"


def color(text, code):
    if sys.stdout.isatty() and os.environ.get("NO_COLOR") is None:
        return f"{code}{text}{RESET}"
    return text


def logo():
    lines = [                                 
    "             +++",                  
    "              ++++",                
    "             *+++++",               
    "             +++++++",              
    "           ++++++++++",             
    "       ++ +++++++++++ +",           
    "      +++ +++++=+++++ ++",          
    "     +++++++++===++++++++",         
    "     ++++++++=====+++++++*",        
    "     ++++==+======+=+++++*",        
    "     ++++============++++",         
    "      +++============+++",          
    "       +++===========++",           
    "         ++========+*",
    ]
    ansi = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
    for line in lines:
        if not ansi:
            print(line)
            continue
        out = []
        inner = False
        for ch in line:
            if ch in "=\n":
                inner = True
            if ch == "=" or (inner and ch == "+"):
                out.append(f"\033[38;5;208m{ch}\033[0m")
            elif ch in "+*":
                out.append(f"\033[38;5;196m{ch}\033[0m")
            else:
                out.append(ch)
        print("".join(out))
    print()
    print(color("S E N T I N E L  W A F", BOLD + CYAN))
    print(color("Terminal WAF Controller", DIM))

def section(title):
    print()
    print(color(f"==== {title} ====", CYAN))


def now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def project_path(value):
    path = Path(value)
    return path if path.is_absolute() else ROOT / path


def load_config():
    with CONFIG_PATH.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def save_config(cfg):
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    validate_config(cfg)
    fd, name = tempfile.mkstemp(prefix="config.", suffix=".tmp", dir=CONFIG_PATH.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(cfg, fh, indent=2)
            fh.write("\n")
        os.replace(name, CONFIG_PATH)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def validate_config(cfg):
    if not isinstance(cfg, dict):
        raise ValueError("configuration must be a JSON object")
    waf = cfg.get("waf", {})
    if not waf.get("listen_address"):
        raise ValueError("waf.listen_address is required")
    if not waf.get("target_url"):
        raise ValueError("waf.target_url is required")
    rules = cfg.get("custom_rules", [])
    ids = set()
    for rule in rules:
        rid = str(rule.get("id", "")).strip()
        if not rid:
            raise ValueError("custom rule id is required")
        if rid in ids:
            raise ValueError(f"duplicate rule id: {rid}")
        ids.add(rid)
        patterns = rule.get("patterns", [])
        if not isinstance(patterns, list) or not patterns:
            raise ValueError(f"rule {rid}: at least one pattern is required")
        paranoia = int(rule.get("paranoia", 1))
        if paranoia < 1 or paranoia > 4:
            raise ValueError(f"rule {rid}: paranoia must be between 1 and 4")
        for pattern in patterns:
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError(f"rule {rid}: invalid regex: {exc}") from exc
    for key in ("allowlist", "blocklist"):
        if not isinstance(cfg.get(key, {}), dict):
            raise ValueError(f"{key} must be an object")


def runtime_paths(cfg):
    runtime = cfg.get("runtime", {})
    pid_dir = project_path(runtime.get("pid_dir", "runtime"))
    return {
        "pid_dir": pid_dir,
        "state": project_path(runtime.get("state_file", "runtime/state.json")),
        "log": project_path(runtime.get("log_file", "logs/sentinelwaf.log")),
        "pid": pid_dir / PID_NAME,
        "out": pid_dir / OUT_NAME,
    }


def ensure_runtime(cfg):
    paths = runtime_paths(cfg)
    paths["pid_dir"].mkdir(parents=True, exist_ok=True)
    paths["log"].parent.mkdir(parents=True, exist_ok=True)
    BIN_PATH.parent.mkdir(parents=True, exist_ok=True)
    return paths


def read_pid(path):
    try:
        return int(path.read_text(encoding="utf-8").strip())
    except (FileNotFoundError, ValueError, OSError):
        return None


def ps_command(pid):
    if not shutil.which("ps"):
        return ""
    try:
        result = subprocess.run(["ps", "-p", str(pid), "-o", "command="], capture_output=True, text=True, timeout=1)
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout.strip()


def pid_is_sentinelwaf(pid):
    if not pid:
        return False
    try:
        os.kill(pid, 0)
    except (ProcessLookupError, PermissionError):
        return False
    except OSError:
        return False
    command = ps_command(pid).lower()
    return "sentinelwaf" in command


def running(pid_path):
    pid = read_pid(pid_path)
    if not pid:
        return False
    if not pid_is_sentinelwaf(pid):
        pid_path.unlink(missing_ok=True)
        return False
    return True


def split_listen_address(address):
    address = str(address or "").strip()
    if address.startswith("["):
        host, _, rest = address[1:].partition("]")
        return host, rest[1:] if rest.startswith(":") else ""
    if ":" in address:
        return address.rsplit(":", 1)
    return address, ""


def listen_port(address):
    _, port = split_listen_address(address)
    try:
        return int(port)
    except (TypeError, ValueError):
        return None


def port_available(address):
    host, port = split_listen_address(address)
    try:
        port_number = int(port)
    except (TypeError, ValueError):
        return True
    bind_host = host or "0.0.0.0"
    family = socket.AF_INET6 if ":" in bind_host else socket.AF_INET
    if bind_host == "0.0.0.0":
        family = socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((bind_host, port_number))
        return True
    except OSError:
        return False


def listener_pid(address):
    port = listen_port(address)
    if not port:
        return None
    if shutil.which("lsof"):
        try:
            result = subprocess.run(
                ["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN"],
                capture_output=True,
                text=True,
                timeout=1,
            )
            for line in result.stdout.splitlines()[1:]:
                parts = line.split()
                if len(parts) < 2:
                    continue
                try:
                    pid = int(parts[1])
                except ValueError:
                    continue
                if pid_is_sentinelwaf(pid):
                    return pid
        except (OSError, subprocess.SubprocessError):
            pass
    if shutil.which("ss"):
        try:
            result = subprocess.run(["ss", "-ltnp"], capture_output=True, text=True, timeout=1)
            for line in result.stdout.splitlines():
                if f":{port} " not in line and f":{port}\n" not in line:
                    continue
                match = re.search(r"pid=(\d+)", line)
                if match:
                    pid = int(match.group(1))
                    if pid_is_sentinelwaf(pid):
                        return pid
        except (OSError, subprocess.SubprocessError):
            pass
    return None


def health_url(cfg):
    host, port = split_listen_address(cfg.get("waf", {}).get("listen_address", "127.0.0.1:8080"))
    if host in ("", "0.0.0.0", "::"):
        host = "127.0.0.1"
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"http://{host}:{port}/healthz" if port else f"http://{host}/healthz"


def waf_healthy(cfg, timeout=0.8):
    import urllib.request
    try:
        request = urllib.request.Request(health_url(cfg), headers={"User-Agent": "SentinelWAF-controller/2.0"})
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(128).decode("utf-8", "replace")
            return response.status == 200 and "SentinelWAF healthy" in body
    except Exception:
        return False


def adopt_pid(cfg, paths):
    pid = listener_pid(cfg.get("waf", {}).get("listen_address", "127.0.0.1:8080"))
    if pid:
        paths["pid"].write_text(f"{pid}\n", encoding="utf-8")
        return pid
    return None


def build_binary():
    if not shutil.which("go"):
        raise RuntimeError("Go is required to build SentinelWAF")
    env = os.environ.copy()
    env["GOCACHE"] = str(Path(tempfile.gettempdir()) / "sentinelwaf-gocache")
    result = subprocess.run(["go", "build", "-o", str(BIN_PATH), "."], cwd=ROOT, env=env)
    if result.returncode != 0:
        raise RuntimeError(f"Go build failed with exit code {result.returncode}")


def service_status():
    cfg = load_config()
    paths = ensure_runtime(cfg)
    pid = read_pid(paths["pid"])
    healthy = waf_healthy(cfg)
    if not pid and healthy:
        pid = adopt_pid(cfg, paths)
    running_state = healthy or pid_is_sentinelwaf(pid)
    if not running_state:
        paths["pid"].unlink(missing_ok=True)
        pid = None
    state = read_state(paths)
    return {
        "running": running_state,
        "healthy": healthy,
        "pid": pid,
        "enabled": bool(state.get("enabled", True)),
        "listen": cfg.get("waf", {}).get("listen_address", "127.0.0.1:8080"),
        "target": cfg.get("waf", {}).get("target_url", ""),
        "log": str(paths["log"]),
        "config": str(CONFIG_PATH),
    }


def read_state(paths):
    try:
        data = json.loads(paths["state"].read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
    except (OSError, json.JSONDecodeError):
        pass
    return {"enabled": True, "updated_at": "", "updated_by": ""}


def write_state(enabled, updated_by="controller"):
    cfg = load_config()
    paths = ensure_runtime(cfg)
    data = {"enabled": bool(enabled), "updated_at": now(), "updated_by": updated_by}
    fd, name = tempfile.mkstemp(prefix="state.", suffix=".tmp", dir=paths["state"].parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
            fh.write("\n")
        os.replace(name, paths["state"])
    finally:
        if os.path.exists(name):
            os.unlink(name)


def write_controller_audit(action, details=None):
    cfg = load_config()
    paths = ensure_runtime(cfg)
    entry = {
        "timestamp": now(),
        "service": "SentinelWAF-controller",
        "decision": "control",
        "action": action,
        "details": details or {},
    }
    with paths["log"].open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, separators=(",", ":")) + "\n")


def start():
    cfg = load_config()
    validate_config(cfg)
    paths = ensure_runtime(cfg)
    write_state(True, "controller:start")
    existing = service_status()
    if existing["running"]:
        if existing["healthy"]:
            print(color(f"{SERVICE_NAME}: already running with pid {existing['pid'] or 'unknown'}", YELLOW))
            return 0
        if existing["pid"]:
            print(color(f"{SERVICE_NAME}: process exists with pid {existing['pid']} but health check failed", YELLOW))
            return 1
    listen_address = cfg.get("waf", {}).get("listen_address", "127.0.0.1:8080")
    if not port_available(listen_address) and not waf_healthy(cfg):
        print(color(f"{SERVICE_NAME}: listen address {listen_address} is already in use by another process", RED))
        print("Choose another waf.listen_address or stop the process using that port.")
        return 1
    build_binary()
    paths["out"].parent.mkdir(parents=True, exist_ok=True)
    with paths["out"].open("ab") as output:
        process = subprocess.Popen(
            [str(BIN_PATH), "waf", "-config", str(CONFIG_PATH)],
            cwd=ROOT,
            stdout=output,
            stderr=output,
            start_new_session=True,
        )
    paths["pid"].write_text(f"{process.pid}\n", encoding="utf-8")
    deadline = time.time() + 8
    while time.time() < deadline:
        if process.poll() is not None:
            paths["pid"].unlink(missing_ok=True)
            print(color(f"{SERVICE_NAME}: exited with code {process.returncode}", RED))
            print(f"Check: {paths['out']}")
            return 1
        if waf_healthy(cfg):
            write_controller_audit("start", {"pid": process.pid})
            print(color(f"{SERVICE_NAME}: started with pid {process.pid}", GREEN))
            return 0
        time.sleep(0.15)
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        pass
    paths["pid"].unlink(missing_ok=True)
    print(color(f"{SERVICE_NAME}: failed health check after start", RED))
    print(f"Check: {paths['out']}")
    return 1


def stop():
    cfg = load_config()
    paths = ensure_runtime(cfg)
    pid = read_pid(paths["pid"]) or listener_pid(cfg.get("waf", {}).get("listen_address", ""))
    if not pid or not pid_is_sentinelwaf(pid):
        paths["pid"].unlink(missing_ok=True)
        write_state(False, "controller:stop")
        print(color(f"{SERVICE_NAME}: already stopped", YELLOW))
        return 0
    try:
        os.killpg(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    except PermissionError:
        try:
            os.kill(pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
    deadline = time.time() + 8
    while time.time() < deadline:
        if not pid_is_sentinelwaf(pid):
            paths["pid"].unlink(missing_ok=True)
            write_state(False, "controller:stop")
            write_controller_audit("stop", {"pid": pid})
            print(color(f"{SERVICE_NAME}: stopped", GREEN))
            return 0
        time.sleep(0.2)
    try:
        os.killpg(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        try:
            os.kill(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
    time.sleep(0.3)
    paths["pid"].unlink(missing_ok=True)
    if pid_is_sentinelwaf(pid):
        print(color(f"{SERVICE_NAME}: failed to stop pid {pid}", RED))
        return 1
    write_state(False, "controller:stop")
    write_controller_audit("stop_force", {"pid": pid})
    print(color(f"{SERVICE_NAME}: force stopped", GREEN))
    return 0


def restart():
    result = stop()
    if result not in (0, 1):
        return result
    return start()


def cmd_status(watch=False):
    while True:
        data = service_status()
        print(f"{color('WAF', BOLD)}  {color('RUNNING' if data['running'] else 'STOPPED', GREEN if data['running'] else RED)}  "
              f"{color('PROTECTED' if data['enabled'] else 'BYPASS', GREEN if data['enabled'] else YELLOW)}")
        print(f"PID       : {data['pid'] or '-'}")
        print(f"Healthy   : {'yes' if data['healthy'] else 'no'}")
        print(f"Listen    : {data['listen']}")
        print(f"Backend   : {data['target']}")
        print(f"Log       : {data['log']}")
        if not watch:
            break
        time.sleep(2)
        print("\033[H\033[J", end="")


def log_entries(limit=50, blocked_only=False):
    cfg = load_config()
    path = ensure_runtime(cfg)["log"]
    if not path.exists():
        return []
    entries = []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if blocked_only and item.get("decision") != "blocked":
                continue
            entries.append(item)
    return entries[-limit:][::-1]


def cmd_events(limit=30, blocked_only=False):
    rows = log_entries(limit, blocked_only)
    if not rows:
        print("No events recorded.")
        return
    for e in rows:
        if e.get("decision") == "control":
            print(f"{e.get('timestamp','-')}  CONTROL  {e.get('action','-')}  {json.dumps(e.get('details', {}), separators=(',', ':'))}")
            continue
        action = e.get("decision", "-").upper()
        status = e.get("status", "-")
        print(f"{e.get('timestamp','-')}  {action:7}  {e.get('remote_ip','-'):15}  {e.get('method','-'):6}  {e.get('path','-')[:50]:50}  {e.get('rule_id','-'):24}  {status}")


def cmd_stats():
    cfg = load_config()
    entries = log_entries(100000)
    requests = [e for e in entries if e.get("decision") in ("allowed", "blocked")]
    allowed = sum(e.get("decision") == "allowed" for e in requests)
    blocked = sum(e.get("decision") == "blocked" for e in requests)
    reasons = {}
    ips = {}
    rules = {}
    paths = {}
    for e in requests:
        if e.get("decision") == "blocked":
            reason = e.get("reason") or "unknown"
            reasons[reason] = reasons.get(reason, 0) + 1
            rid = e.get("rule_id") or "unknown"
            rules[rid] = rules.get(rid, 0) + 1
            ip = e.get("remote_ip") or "unknown"
            ips[ip] = ips.get(ip, 0) + 1
        p = e.get("path") or "/"
        paths[p] = paths.get(p, 0) + 1
    print(f"Requests      : {len(requests)}")
    print(f"Allowed       : {allowed}")
    print(f"Blocked       : {blocked}")
    print(f"Block ratio   : {(blocked / len(requests) * 100) if requests else 0:.2f}%")
    section("Top blocked rules")
    for key, value in sorted(rules.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"{value:6}  {key}")
    section("Top attacking IPs")
    for key, value in sorted(ips.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"{value:6}  {key}")
    section("Top targeted paths")
    for key, value in sorted(paths.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"{value:6}  {key}")
    if not entries:
        print("No traffic has been recorded yet.")


def default_rule_ids():
    return [
        "920-001", "920-002", "920-003", "921-001", "930-001", "931-001",
        "932-001", "932-002", "933-001", "934-001", "934-002", "934-003",
        "941-001", "941-002", "942-001", "942-002", "942-003", "943-001",
        "944-001", "944-002", "944-003", "944-004", "944-005", "949-001"
    ]


def all_rule_meta(cfg):
    rules = [
        ("920-001", "HTTP protocol CRLF injection", "OWASP CRS 920", "high", 1),
        ("920-002", "HTTP request smuggling marker", "OWASP CRS 920", "critical", 2),
        ("920-003", "Malformed payload or NUL byte", "OWASP CRS 920", "medium", 1),
        ("921-001", "HTTP method or URI abuse", "OWASP CRS 921", "medium", 2),
        ("930-001", "Local file inclusion", "OWASP CRS 930", "high", 1),
        ("931-001", "Remote file inclusion", "OWASP CRS 931", "high", 1),
        ("932-001", "Unix/Windows command injection", "OWASP CRS 932", "critical", 1),
        ("932-002", "SSTI / expression injection", "OWASP CRS 932", "high", 2),
        ("933-001", "PHP code injection", "OWASP CRS 933", "critical", 2),
        ("934-001", "Node.js deserialization/prototype pollution", "OWASP CRS 934", "high", 2),
        ("934-002", "Java deserialization/reflection", "OWASP CRS 934", "critical", 2),
        ("934-003", "Generic code execution", "OWASP CRS 934", "high", 2),
        ("941-001", "XSS HTML/script injection", "OWASP CRS 941", "high", 1),
        ("941-002", "XSS event handler/DOM sink", "OWASP CRS 941", "high", 2),
        ("942-001", "SQLi union/select", "OWASP CRS 942", "high", 1),
        ("942-002", "SQLi boolean/comment", "OWASP CRS 942", "high", 1),
        ("942-003", "SQLi time-based/file access", "OWASP CRS 942", "critical", 2),
        ("943-001", "Session fixation marker", "OWASP CRS 943", "medium", 2),
        ("944-001", "XML external entity injection", "OWASP CRS 944", "high", 2),
        ("944-002", "LDAP/XPath injection", "OWASP CRS 944", "high", 2),
        ("944-003", "NoSQL injection operator", "OWASP CRS 944", "high", 2),
        ("944-004", "SSRF URL scheme", "OWASP CRS 944", "high", 2),
        ("944-005", "Executable file upload marker", "OWASP CRS 944", "high", 3),
        ("949-001", "Scanner/automated attack client", "OWASP CRS 949", "high", 1),
    ]
    for item in cfg.get("custom_rules", []):
        rules.append((item["id"], item.get("name", item["id"]), item.get("category", "custom"), item.get("severity", "medium"), int(item.get("paranoia", 1))))
    return rules


def cmd_rules_list():
    cfg = load_config()
    disabled = set(cfg.get("disabled_rules", []))
    for rid, name, category, severity, pl in all_rule_meta(cfg):
        state = "OFF" if rid in disabled else "ON"
        print(f"{state:3}  {severity.upper():8}  PL{pl}  {rid:28}  {name}  [{category}]")


def cmd_rule_state(rule_id, enabled):
    cfg = load_config()
    disabled = set(cfg.get("disabled_rules", []))
    known = {item[0] for item in all_rule_meta(cfg)}
    if rule_id not in known:
        raise ValueError(f"unknown rule: {rule_id}")
    if enabled:
        disabled.discard(rule_id)
    else:
        disabled.add(rule_id)
    cfg["disabled_rules"] = sorted(disabled)
    save_config(cfg)
    write_controller_audit("rule_enable" if enabled else "rule_disable", {"rule_id": rule_id})
    print(color(f"Rule {rule_id}: {'enabled' if enabled else 'disabled'}", GREEN))
    if service_status()["running"]:
        print(color("Configuration changed; restart WAF to apply it.", YELLOW))


def cmd_rule_add(args):
    cfg = load_config()
    if any(r.get("id") == args.id for r in cfg.get("custom_rules", [])) or args.id in default_rule_ids():
        raise ValueError(f"rule already exists: {args.id}")
    patterns = args.pattern if args.pattern else []
    if not patterns:
        raise ValueError("at least one --pattern is required")
    rule = {
        "id": args.id,
        "name": args.name or args.id,
        "category": args.category,
        "severity": args.severity,
        "action": "block",
        "targets": [x.strip() for x in args.targets.split(",") if x.strip()],
        "patterns": patterns,
        "paranoia": args.paranoia,
        "tags": [x.strip() for x in args.tags.split(",") if x.strip()],
    }
    cfg.setdefault("custom_rules", []).append(rule)
    save_config(cfg)
    write_controller_audit("rule_add", {"rule_id": args.id})
    print(color(f"Added rule {args.id}", GREEN))
    if service_status()["running"]:
        print(color("Restart WAF to apply the new rule.", YELLOW))


def cmd_rule_remove(rule_id):
    cfg = load_config()
    before = len(cfg.get("custom_rules", []))
    cfg["custom_rules"] = [r for r in cfg.get("custom_rules", []) if r.get("id") != rule_id]
    if len(cfg["custom_rules"]) == before:
        raise ValueError("only custom rules can be removed")
    disabled = set(cfg.get("disabled_rules", []))
    disabled.discard(rule_id)
    cfg["disabled_rules"] = sorted(disabled)
    save_config(cfg)
    write_controller_audit("rule_remove", {"rule_id": rule_id})
    print(color(f"Removed rule {rule_id}", GREEN))
    if service_status()["running"]:
        print(color("Restart WAF to apply the change.", YELLOW))


def list_values(kind, scope):
    cfg = load_config()
    section_name = "allowlist" if scope == "allow" else "blocklist"
    section_data = cfg.setdefault(section_name, {})
    key = {"ip": "ips", "path": "paths", "ua": "user_agents"}[kind]
    values = section_data.get(key, [])
    print(f"{scope}/{kind}")
    for item in values:
        print(f"  {item}")
    if not values:
        print("  empty")


def modify_list(scope, kind, value, remove=False):
    cfg = load_config()
    section_name = "allowlist" if scope == "allow" else "blocklist"
    section_data = cfg.setdefault(section_name, {})
    key = {"ip": "ips", "path": "paths", "ua": "user_agents"}[kind]
    values = list(section_data.get(key, []))
    if remove:
        if value not in values:
            raise ValueError(f"not present: {value}")
        values.remove(value)
    else:
        if value in values:
            print(color("Already present.", YELLOW))
            return 0
        values.append(value)
    section_data[key] = values
    save_config(cfg)
    write_controller_audit("list_remove" if remove else "list_add", {"scope": scope, "kind": kind, "value": value})
    print(color(f"{'Removed' if remove else 'Added'} {scope}/{kind}: {value}", GREEN))
    if service_status()["running"]:
        print(color("Restart WAF to apply the change.", YELLOW))
    return 0


def get_dotted(cfg, key):
    cur = cfg
    for part in key.split("."):
        if not isinstance(cur, dict) or part not in cur:
            raise KeyError(key)
        cur = cur[part]
    return cur


def set_dotted(cfg, key, raw):
    parts = key.split(".")
    cur = cfg
    for part in parts[:-1]:
        if part not in cur or not isinstance(cur[part], dict):
            raise KeyError(key)
        cur = cur[part]
    current = cur.get(parts[-1])
    if isinstance(current, bool):
        value = raw.lower() in ("1", "true", "yes", "on")
    elif isinstance(current, int):
        value = int(raw)
    elif isinstance(current, float):
        value = float(raw)
    elif isinstance(current, list):
        value = json.loads(raw)
    elif isinstance(current, dict):
        value = json.loads(raw)
    else:
        value = raw
    cur[parts[-1]] = value


def cmd_config(args):
    cfg = load_config()
    if args.action == "show":
        print(json.dumps(cfg, indent=2))
        return
    if args.action == "get":
        print(json.dumps(get_dotted(cfg, args.key), indent=2))
        return
    if args.action == "set":
        set_dotted(cfg, args.key, args.value)
        save_config(cfg)
        write_controller_audit("config_set", {"key": args.key})
        print(color(f"Updated {args.key}", GREEN))
        if service_status()["running"]:
            print(color("Restart WAF to apply configuration changes.", YELLOW))


def cmd_logs(follow=False, lines=40):
    cfg = load_config()
    path = ensure_runtime(cfg)["log"]
    if not path.exists():
        print("No log file yet.")
        return
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        content = fh.readlines()
        for line in content[-lines:]:
            print(line.rstrip())
        if follow:
            print(color("Following log. Press Ctrl+C to stop.", DIM))
            while True:
                line = fh.readline()
                if line:
                    print(line.rstrip(), flush=True)
                else:
                    time.sleep(0.25)


def cmd_validate():
    cfg = load_config()
    validate_config(cfg)
    print(color("Configuration syntax: OK", GREEN))
    if shutil.which("go"):
        build_binary()
        print(color("Go build: OK", GREEN))
    else:
        print(color("Go build: SKIPPED (Go not installed)", YELLOW))


def cmd_reset():
    stop()
    cfg = load_config()
    paths = ensure_runtime(cfg)
    for key in ("pid", "out"):
        paths[key].unlink(missing_ok=True)
    write_state(True, "controller:reset")
    print(color("Runtime state reset. Configuration and logs were preserved.", GREEN))


def interactive():
    logo()
    print("Type 'help' for commands. 'exit' quits the controller.")
    while True:
        try:
            command = input(color("sentinelwaf> ", MAGENTA)).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if not command:
            continue
        if command in ("exit", "quit", "q"):
            return 0
        if command == "help":
            parser().print_help()
            continue
        try:
            args = parser().parse_args(shlex.split(command))
            result = dispatch(args)
            if isinstance(result, int) and result:
                print(color(f"Command failed with code {result}", RED))
        except SystemExit:
            continue
        except Exception as exc:
            print(color(f"Error: {exc}", RED))


def parser():
    p = argparse.ArgumentParser(prog="controller.py", description="SentinelWAF terminal controller")
    sub = p.add_subparsers(dest="command")

    for name, func_name in (("start", "start"), ("stop", "stop"), ("restart", "restart")):
        sub.add_parser(name)
    status = sub.add_parser("status")
    status.add_argument("--watch", action="store_true")
    sub.add_parser("enable")
    sub.add_parser("disable")
    sub.add_parser("reset")
    sub.add_parser("validate")

    events = sub.add_parser("events")
    events.add_argument("--limit", type=int, default=30)
    events.add_argument("--blocked", action="store_true")
    sub.add_parser("stats")

    logs = sub.add_parser("logs")
    logs.add_argument("--follow", action="store_true")
    logs.add_argument("--lines", type=int, default=40)

    rules = sub.add_parser("rules")
    rs = rules.add_subparsers(dest="rules_command", required=True)
    rs.add_parser("list")
    re_ = rs.add_parser("enable")
    re_.add_argument("id")
    rd = rs.add_parser("disable")
    rd.add_argument("id")
    rr = rs.add_parser("remove")
    rr.add_argument("id")
    ra = rs.add_parser("add")
    ra.add_argument("--id", required=True)
    ra.add_argument("--name")
    ra.add_argument("--category", default="Custom")
    ra.add_argument("--severity", choices=["low", "medium", "high", "critical"], default="medium")
    ra.add_argument("--targets", default="path,query,body,headers")
    ra.add_argument("--paranoia", type=int, choices=[1, 2, 3, 4], default=1)
    ra.add_argument("--tags", default="custom")
    ra.add_argument("--pattern", action="append", required=True)

    ip = sub.add_parser("ip")
    ips = ip.add_subparsers(dest="ip_command", required=True)
    for scope in ("allow", "block"):
        sc = ips.add_parser(scope)
        ss = sc.add_subparsers(dest="action", required=True)
        ls = ss.add_parser("list")
        ls.add_argument("kind", choices=["ip", "path", "ua"])
        for action in ("add", "remove"):
            aa = ss.add_parser(action)
            aa.add_argument("kind", choices=["ip", "path", "ua"])
            aa.add_argument("value")

    config = sub.add_parser("config")
    cs = config.add_subparsers(dest="action", required=True)
    cs.add_parser("show")
    cg = cs.add_parser("get")
    cg.add_argument("key")
    cset = cs.add_parser("set")
    cset.add_argument("key")
    cset.add_argument("value")
    return p


def dispatch(args):
    if args.command == "start": return start()
    if args.command == "stop": return stop()
    if args.command == "restart": return restart()
    if args.command == "status": return cmd_status(args.watch)
    if args.command == "enable": write_state(True, "controller:enable"); print(color("Protection enabled", GREEN)); return 0
    if args.command == "disable": write_state(False, "controller:disable"); print(color("Protection disabled; traffic will be proxied without WAF inspection", YELLOW)); return 0
    if args.command == "reset": return cmd_reset()
    if args.command == "validate": return cmd_validate()
    if args.command == "events": return cmd_events(args.limit, args.blocked)
    if args.command == "stats": return cmd_stats()
    if args.command == "logs": return cmd_logs(args.follow, args.lines)
    if args.command == "rules":
        if args.rules_command == "list": return cmd_rules_list()
        if args.rules_command == "enable": return cmd_rule_state(args.id, True)
        if args.rules_command == "disable": return cmd_rule_state(args.id, False)
        if args.rules_command == "remove": return cmd_rule_remove(args.id)
        if args.rules_command == "add": return cmd_rule_add(args)
    if args.command == "ip":
        if args.action == "list": return list_values(args.kind, args.ip_command)
        return modify_list(args.ip_command, args.kind, args.value, args.action == "remove")
    if args.command == "config": return cmd_config(args)
    return 0


def main():
    p = parser()
    if len(sys.argv) == 1:
        return interactive()
    args = p.parse_args()
    try:
        return dispatch(args) or 0
    except KeyboardInterrupt:
        print()
        return 130
    except Exception as exc:
        print(color(f"Error: {exc}", RED), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
