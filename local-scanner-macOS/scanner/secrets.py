"""
Secrets scanner: walk a directory and flag files that contain API keys,
tokens, or private keys.

Design notes
------------
* We use a curated regex table.  Each entry has a name, severity, and a
  compiled pattern.  Patterns are tight - we'd rather miss a few hits than
  drown the user in false positives.
* We skip binary files, common heavy directories (node_modules, .git, etc.),
  and files larger than MAX_FILE_BYTES.
* Matched secret values are REDACTED in the output (show the first/last
  4 chars only) so the report itself is safe to share.
"""

import os
import re
from pathlib import Path

MAX_FILE_BYTES = 1_000_000     # 1 MB
MAX_FINDINGS   = 500           # bail out after this many to keep UI snappy
SKIP_DIR_NAMES = {
    ".git", ".hg", ".svn",
    "node_modules", "bower_components",
    ".venv", "venv", "env",
    "__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache",
    "dist", "build", "target", ".next", ".nuxt",
    "Library",                 # macOS user library is huge & noisy
    ".Trash", ".cache",
}

# (id, severity, compiled pattern, description)
PATTERNS = [
    ("aws-access-key",     "HIGH",     re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
     "AWS access key id"),
    ("github-pat",         "HIGH",     re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
     "GitHub personal access token"),
    ("github-oauth",       "HIGH",     re.compile(r"\bgho_[A-Za-z0-9]{36}\b"),
     "GitHub OAuth token"),
    ("github-fine-grained","HIGH",     re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b"),
     "GitHub fine-grained PAT"),
    ("slack-token",        "HIGH",     re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
     "Slack token"),
    ("stripe-live",        "CRITICAL", re.compile(r"\bsk_live_[A-Za-z0-9]{20,}\b"),
     "Stripe live secret key"),
    ("google-api",         "HIGH",     re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
     "Google API key"),
    ("openai-key",         "HIGH",     re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
     "OpenAI-style secret key"),
    ("jwt",                "MEDIUM",   re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
     "JSON Web Token"),
    ("private-key-pem",    "CRITICAL", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |)PRIVATE KEY-----"),
     "Private key in PEM format"),
    # Generic env-style assignment, captured loosely:
    ("env-assignment",     "LOW",      re.compile(
        r"""(?ix)
          (password|passwd|secret|api[_-]?key|access[_-]?key|token)\s*[:=]\s*
          ['"]([A-Za-z0-9_\-+/=]{12,})['"]
        """),
     "Hardcoded credential assignment"),
]


def _redact(s: str) -> str:
    if len(s) <= 8:
        return "*" * len(s)
    return f"{s[:4]}{'*' * (len(s) - 8)}{s[-4:]}"


def _is_probably_binary(sample: bytes) -> bool:
    """Cheap binary sniff - if there are NUL bytes in the first chunk, skip."""
    return b"\x00" in sample


def _iter_text_files(root: Path):
    """Yield Path objects for text-ish files under `root`, skipping the noisy dirs."""
    for dirpath, dirnames, filenames in os.walk(root):
        # In-place prune of skip dirs and any hidden dotted directory
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES]
        for name in filenames:
            p = Path(dirpath) / name
            try:
                if p.is_symlink() or not p.is_file():
                    continue
                if p.stat().st_size > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield p


PROGRESS_EVERY = 200   # emit a progress event every N files


def check_iter(root_dir: str):
    """
    Generator version of `check` that yields progress events while walking
    and a final 'done' event with the full findings list.

    Yielded events:
      {"type": "progress", "files_scanned": N, "current_path": "..."}
      {"type": "done", "findings": [...]}
    """
    findings: list[dict] = []
    root = Path(root_dir).expanduser().resolve()
    if not root.exists() or not root.is_dir():
        yield {"type": "done", "findings": [{
            "category": "secrets",
            "id": "bad-path",
            "title": "Folder does not exist or is not a directory",
            "severity": "INFO",
            "evidence": str(root),
            "remediation": "Pick a folder you want scanned for secrets",
        }]}
        return

    files_scanned = 0
    for path in _iter_text_files(root):
        if len(findings) >= MAX_FINDINGS:
            findings.append({
                "category": "secrets",
                "id": "truncated",
                "title": f"Reached the {MAX_FINDINGS}-finding limit; stopping",
                "severity": "INFO",
                "evidence": str(path),
                "remediation": "Re-run on a smaller folder, or raise MAX_FINDINGS in secrets.py",
            })
            break
        try:
            with path.open("rb") as f:
                sample = f.read(2048)
            if _is_probably_binary(sample):
                continue
            text = sample.decode("utf-8", errors="replace")
            if path.stat().st_size > len(sample):
                with path.open("r", encoding="utf-8", errors="replace") as f:
                    text = f.read(MAX_FILE_BYTES)
        except OSError:
            continue

        files_scanned += 1
        if files_scanned % PROGRESS_EVERY == 0:
            yield {"type": "progress",
                   "files_scanned": files_scanned,
                   "current_path": str(path)}

        for fid, severity, pattern, description in PATTERNS:
            for m in pattern.finditer(text):
                line_no = text.count("\n", 0, m.start()) + 1
                value = m.group(0)
                findings.append({
                    "category": "secrets",
                    "id": f"{fid}",
                    "title": f"Possible {description}",
                    "severity": severity,
                    "evidence": f"{path}:{line_no}  {_redact(value)}",
                    "remediation": "Move the secret out of source - use environment variables or a secrets manager",
                })
                if len(findings) >= MAX_FINDINGS:
                    break

    if files_scanned and not findings:
        findings.append({
            "category": "secrets",
            "id": "secrets-clean",
            "title": f"No secrets found in {files_scanned} text file(s)",
            "severity": "INFO",
            "evidence": str(root),
            "remediation": "",
        })

    yield {"type": "done", "findings": findings, "files_scanned": files_scanned}


def check(root_dir: str) -> list[dict]:
    """Non-streaming wrapper kept for the synchronous /api/scan endpoint."""
    for event in check_iter(root_dir):
        if event["type"] == "done":
            return event["findings"]
    return []
