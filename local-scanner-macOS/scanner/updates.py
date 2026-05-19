"""
Pending updates check.

  softwareupdate --list   -> macOS system updates (can take ~30s)
  brew outdated --json    -> Outdated Homebrew packages (skipped if no brew)

Both calls have generous timeouts and bail gracefully if the tool is missing.
"""

import json
import shutil
import subprocess


def _run(cmd: list[str], timeout: float = 60.0):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.SubprocessError as exc:
        return -1, "", str(exc)
    except FileNotFoundError:
        return -1, "", "not installed"


def _check_softwareupdate() -> list[dict]:
    findings: list[dict] = []
    if not shutil.which("softwareupdate"):
        return findings
    rc, out, err = _run(["softwareupdate", "--list", "--no-scan"])
    text = (out + err).strip()
    # Each available update appears as a line starting with "* Label:" on newer
    # macOS versions, or "   * <name>" on older ones.
    updates = [ln.strip() for ln in text.splitlines()
               if ln.strip().startswith("*") and "Label" not in ln.split(":")[0]]
    if updates:
        findings.append({
            "category": "updates",
            "id": "macos-updates-available",
            "title": f"{len(updates)} macOS update(s) available",
            "severity": "HIGH",
            "evidence": "\n".join(updates[:10]),
            "remediation": "Install via System Settings → General → Software Update",
        })
    elif "No new software available" in text or "No updates" in text:
        findings.append({
            "category": "updates",
            "id": "macos-updates-clean",
            "title": "macOS is up to date",
            "severity": "INFO",
            "evidence": "softwareupdate --list reports no available updates",
            "remediation": "",
        })
    return findings


def _check_brew() -> list[dict]:
    findings: list[dict] = []
    if not shutil.which("brew"):
        return findings
    rc, out, _ = _run(["brew", "outdated", "--json=v2"], timeout=30)
    if rc != 0:
        return findings
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return findings
    formulae = data.get("formulae") or []
    casks = data.get("casks") or []
    if formulae:
        names = ", ".join(f"{x['name']} ({x['installed_versions'][0]} → {x['current_version']})"
                          for x in formulae[:15])
        findings.append({
            "category": "updates",
            "id": "brew-outdated-formulae",
            "title": f"{len(formulae)} outdated Homebrew formula(e)",
            "severity": "MEDIUM",
            "evidence": names,
            "remediation": "Run `brew upgrade` (review the list first)",
        })
    if casks:
        names = ", ".join(f"{x['name']} ({x.get('installed_versions', ['?'])[0]} → {x['current_version']})"
                          for x in casks[:15])
        findings.append({
            "category": "updates",
            "id": "brew-outdated-casks",
            "title": f"{len(casks)} outdated Homebrew cask(s)",
            "severity": "LOW",
            "evidence": names,
            "remediation": "Run `brew upgrade --cask`",
        })
    if not formulae and not casks:
        findings.append({
            "category": "updates",
            "id": "brew-clean",
            "title": "Homebrew packages are up to date",
            "severity": "INFO",
            "evidence": "",
            "remediation": "",
        })
    return findings


def check() -> list[dict]:
    findings: list[dict] = []
    findings.extend(_check_softwareupdate())
    findings.extend(_check_brew())
    if not findings:
        findings.append({
            "category": "updates",
            "id": "no-update-tools",
            "title": "No update tools detected",
            "severity": "INFO",
            "evidence": "softwareupdate / brew not found on PATH",
            "remediation": "",
        })
    return findings
