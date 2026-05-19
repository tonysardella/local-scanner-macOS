"""
Orchestrator: runs whichever scans the user picked and aggregates findings.
"""

from . import config, ports, secrets, updates

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

CATEGORY_LABELS = {
    "secrets": "Secrets in files",
    "ports":   "Open ports",
    "config":  "Security configuration",
    "updates": "Pending updates",
}


def run_scan(scans: list[str], secrets_path: str = "") -> dict:
    """
    `scans` is a subset of {"secrets","ports","config","updates"}.
    `secrets_path` is the directory to scan for secrets (only consulted if
    "secrets" is in `scans`).
    """
    requested = [s for s in scans if s in CATEGORY_LABELS]
    if not requested:
        return {"error": "Pick at least one scan to run.", "findings": [], "counts": {}}

    findings: list[dict] = []
    ran: list[str] = []

    if "secrets" in requested:
        if not secrets_path:
            findings.append({
                "category": "secrets",
                "id": "no-path",
                "title": "Secrets scan was requested but no folder was supplied",
                "severity": "INFO",
                "evidence": "",
                "remediation": "Enter a folder path (e.g. ~/Projects) before scanning",
            })
        else:
            findings.extend(secrets.check(secrets_path))
        ran.append("secrets")

    if "ports" in requested:
        findings.extend(ports.check())
        ran.append("ports")

    if "config" in requested:
        findings.extend(config.check())
        ran.append("config")

    if "updates" in requested:
        findings.extend(updates.check())
        ran.append("updates")

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 0), reverse=True)

    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1

    actionable = sum(counts[s] for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"))
    summary_line = (
        f"{actionable} actionable finding(s) across "
        f"{', '.join(CATEGORY_LABELS[c].lower() for c in ran)}"
    )

    return {
        "ran": ran,
        "findings": findings,
        "counts": counts,
        "summary_line": summary_line,
    }
