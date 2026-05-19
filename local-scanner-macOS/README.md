# Local Mac Scanner

A small, **read-only** security audit tool for your own Mac. Open it in a browser, pick which scans to run, and read the findings.

It is intentionally not antivirus — it does not detect malware. For that, use a real AV product. What it *does* check is the day-to-day stuff that quietly drifts on a personal machine: hardcoded secrets in your code folders, services listening on the network, security toggles that may have been turned off, and pending updates.

## What it scans

| Scan | What it does | Tool used |
| --- | --- | --- |
| **Secrets in files** | Walks a folder you choose and matches text files against curated regexes for AWS keys, GitHub PATs, Slack tokens, Stripe keys, Google API keys, JWTs, PEM private keys, and generic env-style credential assignments. Skips heavy dirs (`node_modules`, `.git`, `.venv`, `Library`…), binary files, and anything over 1 MB. | Pure Python |
| **Open network ports** | Lists every TCP port in `LISTEN` state and every UDP binding, with the owning process and user. Flags services exposed to non-loopback addresses (SSH, MySQL, Postgres, Redis, Mongo, etc.). | `lsof -nP -iTCP -sTCP:LISTEN`, `lsof -nP -iUDP` |
| **Security configuration** | Reads macOS hardening settings — FileVault, System Integrity Protection, GateKeeper, the application firewall, automatic login, Remote Login (SSH), and automatic-update preference. | `fdesetup`, `csrutil`, `spctl`, `defaults`, `systemsetup` |
| **Pending updates** | Lists available macOS updates and outdated Homebrew formulae/casks. Gracefully skips if a tool is not installed. | `softwareupdate --list`, `brew outdated --json=v2` |

Every command is hardcoded — no user input ever reaches the shell.

## Run it

```bash
cd local-scanner
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open <http://127.0.0.1:5002>, tick the boxes you want, and click **Run selected scans**.

## File layout

```
local-scanner/
├── app.py                  # Flask routes (small)
├── requirements.txt        # Flask only - everything else is stdlib
├── templates/
│   └── index.html          # Single-page UI
├── scanner/
│   ├── __init__.py
│   ├── engine.py           # Orchestrator
│   ├── secrets.py          # Regex-based file walker
│   ├── ports.py            # lsof parsing + risky-port table
│   ├── config.py           # macOS hardening checks
│   └── updates.py          # softwareupdate + brew outdated
└── README.md
```

## Findings format

Every check returns the same shape so the UI is consistent:

```python
{
  "category":    "secrets" | "ports" | "config" | "updates",
  "id":          "stable-id-for-diffing",
  "title":       "Short headline",
  "severity":    "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
  "evidence":    "verbatim string you can verify",
  "remediation": "one-line fix",
}
```

Secret values are **redacted** in the report (first/last 4 characters only) so the output itself is safe to copy/paste or share with a teammate.

## What this tool is NOT

- It is not antivirus. It does not look for malware signatures.
- It does not crawl your whole disk by default — you pick the folder for the secrets scan.
- It does not phone home. There is no telemetry, no third-party services, no API calls. All scanning is local.
- It does not change anything. Every command is `read`/`list`/`status` — never `set`/`enable`/`install`.

## Permissions notes

Most checks work without sudo. A few — for example `systemsetup -getremotelogin` — may report nothing if you don't have admin rights. The scanner treats unreadable results as "skip", not "fail".

If you want updates to scan, install Homebrew (`brew`) and make sure `softwareupdate` is on your PATH (it ships with macOS by default).

## Suggested next steps

If you want to grow this scanner, the pattern is: drop a new file into `scanner/`, export a `check(...)` function, and call it from `engine.py`.

Good additions:

- A **launchd / login items** scan that lists what's set to run at startup.
- A **stale SSH keys** check (last access time on `~/.ssh/id_*`).
- A **Time Machine status** check via `tmutil status`.
- An **export to JSON** button so you can diff scans over time.
- A **scheduled run** option (e.g. nightly) so drift gets flagged automatically.
