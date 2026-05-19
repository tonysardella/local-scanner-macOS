"""
List which TCP/UDP ports on this Mac are currently LISTENING and which
process owns each.

We shell out to `lsof -nP -iTCP -sTCP:LISTEN` and `lsof -nP -iUDP` and parse
the output.  No third-party Python deps.  All commands are hardcoded; no
user input ever reaches the shell.
"""

import re
import shutil
import subprocess

# Ports that listen on 0.0.0.0 / :: are reachable from the network and
# therefore deserve attention.  These ports are commonly attacker-targeted
# when exposed to non-loopback addresses.
RISKY_SERVICES = {
    22:    ("HIGH",   "SSH"),
    23:    ("HIGH",   "telnet"),
    3306:  ("HIGH",   "MySQL"),
    5432:  ("HIGH",   "PostgreSQL"),
    6379:  ("HIGH",   "Redis"),
    27017: ("HIGH",   "MongoDB"),
    9200:  ("HIGH",   "Elasticsearch"),
    11211: ("HIGH",   "Memcached"),
    5900:  ("HIGH",   "VNC / Screen Sharing"),
    548:   ("MEDIUM", "AFP / file sharing"),
    445:   ("MEDIUM", "SMB"),
    139:   ("MEDIUM", "NetBIOS"),
    3389:  ("HIGH",   "RDP"),
}

_LSOF_LINE = re.compile(
    r"^(?P<cmd>\S+)\s+(?P<pid>\d+)\s+(?P<user>\S+)\s+\S+\s+\S+\s+\S+\s+\S+\s+(?P<proto>\S+)\s+(?P<addr>\S+)"
)


def _run_lsof(args: list[str]) -> str:
    if not shutil.which("lsof"):
        return ""
    try:
        proc = subprocess.run(["lsof"] + args, capture_output=True, text=True, timeout=20)
        return proc.stdout
    except subprocess.SubprocessError:
        return ""


def _parse(output: str):
    """Yield (command, pid, user, proto, addr) tuples."""
    for line in output.splitlines()[1:]:  # skip header
        m = _LSOF_LINE.match(line)
        if m:
            yield m.group("cmd"), m.group("pid"), m.group("user"), m.group("proto"), m.group("addr")


def _split_addr(addr: str):
    """`*:22` -> ('*', 22).  `127.0.0.1:5000` -> ('127.0.0.1', 5000)."""
    # IPv6 addresses are enclosed in [..]
    if addr.startswith("["):
        host, _, port = addr.rpartition("]:")
        return host.lstrip("["), int(port) if port.isdigit() else None
    host, _, port = addr.rpartition(":")
    return host, int(port) if port.isdigit() else None


def check() -> list[dict]:
    findings: list[dict] = []
    if not shutil.which("lsof"):
        return [{
            "category": "ports",
            "id": "lsof-missing",
            "title": "lsof is not available - cannot enumerate ports",
            "severity": "INFO",
            "evidence": "",
            "remediation": "Install Xcode command line tools (`xcode-select --install`)",
        }]

    listening = []
    tcp = _run_lsof(["-nP", "-iTCP", "-sTCP:LISTEN"])
    for cmd, pid, user, proto, addr in _parse(tcp):
        host, port = _split_addr(addr)
        listening.append((cmd, pid, user, "TCP", host, port))

    # UDP doesn't have a LISTEN state; we collect all UDP bindings.
    udp = _run_lsof(["-nP", "-iUDP"])
    for cmd, pid, user, proto, addr in _parse(udp):
        host, port = _split_addr(addr)
        listening.append((cmd, pid, user, "UDP", host, port))

    if not listening:
        return [{
            "category": "ports",
            "id": "no-listeners",
            "title": "No listening TCP/UDP ports detected",
            "severity": "INFO",
            "evidence": "",
            "remediation": "",
        }]

    for cmd, pid, user, proto, host, port in listening:
        is_public = host in ("*", "0.0.0.0", "::") or (host and not host.startswith("127.") and host != "::1")

        sev_default = "INFO" if not is_public else "LOW"
        title = f"{proto} {port or '?'} listening ({cmd})"
        severity = sev_default

        if port in RISKY_SERVICES and is_public:
            risk_sev, svc = RISKY_SERVICES[port]
            severity = risk_sev
            title = f"{svc} ({proto} {port}) exposed to the network via {cmd}"

        findings.append({
            "category": "ports",
            "id": f"port:{proto}:{port}:{host}",
            "title": title,
            "severity": severity,
            "evidence": f"{cmd} pid={pid} user={user} {proto} bind={host}:{port}",
            "remediation": (
                "Bind to 127.0.0.1 if this service is only used locally, or close it via System Settings → General → Sharing"
                if is_public else ""
            ),
        })

    # Sort worst-first within the category
    sev_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    findings.sort(key=lambda f: sev_order.get(f["severity"], 0), reverse=True)
    return findings
