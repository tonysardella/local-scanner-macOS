"""
Local Mac Scanner - audit your own computer.

Modules (each implements one scan):
  secrets.py - walk a folder, regex-match API keys / tokens / private keys
  ports.py   - list listening TCP/UDP ports & owning processes (lsof)
  config.py  - macOS hardening checks (FileVault, SIP, firewall, GateKeeper, sharing, etc.)
  updates.py - pending OS updates and outdated Homebrew packages
  engine.py  - orchestrator; runs whichever scans the user requested

All findings share the same shape so the UI can render them uniformly:

    {
      "category":    "secrets" | "ports" | "config" | "updates",
      "id":          "stable-id",
      "title":       "Short headline",
      "severity":    "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
      "evidence":    "verbatim string you can verify",
      "remediation": "one-line fix",
    }
"""

from .engine import run_scan, run_scan_streaming  # noqa: F401
