"""
Orchestrator: runs whichever scans the user picked and aggregates findings.

Two entry points:
  * run_scan(...)            - synchronous, returns the full report dict
  * run_scan_streaming(...)  - generator, yields progress events while running
                               and finally emits a 'done' event with the report.
"""

from . import config, ports, secrets, updates

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

CATEGORY_LABELS = {
    "secrets": "Secrets in files",
    "ports":   "Open ports",
    "config":  "Security configuration",
    "updates": "Pending updates",
}


def _build_report(findings: list[dict], ran: list[str]) -> dict:
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


def run_scan_streaming(scans: list[str], secrets_path: str = ""):
    """
    Generator that yields progress events as each category runs, then a final
    'done' event whose payload is the full report dict.

    Event shapes:
      {"type": "start", "categories": [...]}
      {"type": "category_start", "category": "secrets"}
      {"type": "progress", "category": "secrets",
                           "files_scanned": N, "current_path": "..."}
      {"type": "category_done", "category": "secrets", "new_findings": K}
      {"type": "done", "report": {...}}
      {"type": "error", "message": "..."}
    """
    requested = [s for s in scans if s in CATEGORY_LABELS]
    if not requested:
        yield {"type": "error", "message": "Pick at least one scan to run."}
        return

    yield {"type": "start", "categories": requested}

    findings: list[dict] = []
    ran: list[str] = []

    for category in requested:
        yield {"type": "category_start", "category": category}
        before = len(findings)

        try:
            if category == "secrets":
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
                    for event in secrets.check_iter(secrets_path):
                        if event["type"] == "progress":
                            yield {
                                "type": "progress",
                                "category": "secrets",
                                "files_scanned": event.get("files_scanned", 0),
                                "current_path": event.get("current_path", ""),
                            }
                        elif event["type"] == "done":
                            findings.extend(event.get("findings", []))
            elif category == "ports":
                findings.extend(ports.check())
            elif category == "config":
                findings.extend(config.check())
            elif category == "updates":
                findings.extend(updates.check())
        except Exception as exc:  # noqa: BLE001
            findings.append({
                "category": category,
                "id": f"{category}-error",
                "title": f"{CATEGORY_LABELS[category]} scan crashed",
                "severity": "INFO",
                "evidence": str(exc),
                "remediation": "See the server logs for the full traceback",
            })

        ran.append(category)
        yield {
            "type": "category_done",
            "category": category,
            "new_findings": len(findings) - before,
        }

    yield {"type": "done", "report": _build_report(findings, ran)}


def run_scan(scans: list[str], secrets_path: str = "") -> dict:
    """
    Synchronous wrapper kept for backward compatibility.

    `scans` is a subset of {"secrets","ports","config","updates"}.
    `secrets_path` is the directory to scan for secrets (only consulted if
    "secrets" is in `scans`).
    """
    for event in run_scan_streaming(scans, secrets_path=secrets_path):
        if event["type"] == "done":
            return event["report"]
        if event["type"] == "error":
            return {"error": event["message"], "findings": [], "counts": {}}
    return {"error": "Scan ended without a result", "findings": [], "counts": {}}
