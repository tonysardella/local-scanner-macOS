"""
macOS hardening checks.

Each check shells out to a built-in macOS tool and interprets the output.
Nothing here modifies system state - we only READ.

  fdesetup status                                 -> FileVault
  csrutil status                                  -> System Integrity Protection
  spctl --status                                  -> GateKeeper
  defaults read /Library/Preferences/com.apple.alf globalstate
                                                  -> Application firewall
  systemsetup -getremotelogin                     -> SSH remote login (needs sudo)
  defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled
  defaults read com.apple.loginwindow autoLoginUser
                                                  -> Automatic login
  systemsetup -getsleep / -getdisplaysleep        -> Screen lock proxy
"""

import shutil
import subprocess


def _run(cmd: list[str], timeout: float = 8.0):
    """Run a command and return (returncode, stdout, stderr).  Never raises."""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except (subprocess.SubprocessError, FileNotFoundError) as exc:
        return -1, "", str(exc)


def _finding(fid, title, severity, evidence, remediation):
    return {
        "category": "config",
        "id": fid,
        "title": title,
        "severity": severity,
        "evidence": evidence,
        "remediation": remediation,
    }


def check() -> list[dict]:
    findings: list[dict] = []

    # ---- FileVault (disk encryption) ---------------------------------------
    rc, out, _ = _run(["fdesetup", "status"])
    if rc == 0:
        if "FileVault is On" in out:
            findings.append(_finding("filevault-on", "FileVault disk encryption is ON",
                                     "INFO", out, ""))
        else:
            findings.append(_finding("filevault-off", "FileVault disk encryption is OFF",
                                     "HIGH", out,
                                     "Enable in System Settings → Privacy & Security → FileVault"))

    # ---- System Integrity Protection ---------------------------------------
    if shutil.which("csrutil"):
        rc, out, _ = _run(["csrutil", "status"])
        if rc == 0:
            if "enabled" in out.lower() and "disabled" not in out.lower():
                findings.append(_finding("sip-on", "System Integrity Protection is enabled",
                                         "INFO", out, ""))
            else:
                findings.append(_finding("sip-off", "System Integrity Protection is DISABLED",
                                         "HIGH", out,
                                         "Boot to Recovery (hold Cmd-R) and run `csrutil enable`"))

    # ---- GateKeeper --------------------------------------------------------
    if shutil.which("spctl"):
        rc, out, _ = _run(["spctl", "--status"])
        if rc == 0:
            if "enabled" in out.lower():
                findings.append(_finding("gatekeeper-on", "GateKeeper is enabled",
                                         "INFO", out, ""))
            else:
                findings.append(_finding("gatekeeper-off", "GateKeeper is disabled",
                                         "MEDIUM", out, "Run `sudo spctl --master-enable`"))

    # ---- Application firewall ---------------------------------------------
    rc, out, _ = _run(["defaults", "read", "/Library/Preferences/com.apple.alf", "globalstate"])
    if rc == 0:
        state = out.strip()
        if state in ("1", "2"):
            label = "block all incoming" if state == "2" else "specific services"
            findings.append(_finding("firewall-on", f"Application firewall is ON ({label})",
                                     "INFO", f"globalstate={state}", ""))
        else:
            findings.append(_finding("firewall-off", "Application firewall is OFF",
                                     "MEDIUM", f"globalstate={state}",
                                     "Enable in System Settings → Network → Firewall"))

    # ---- Remote login (SSH) ------------------------------------------------
    # `systemsetup -getremotelogin` traditionally needs sudo; we still try and
    # gracefully skip if the result is unreadable.
    rc, out, _ = _run(["systemsetup", "-getremotelogin"])
    if rc == 0 and out:
        if "On" in out:
            findings.append(_finding("ssh-on", "Remote Login (SSH) is enabled",
                                     "LOW", out,
                                     "Disable in System Settings → General → Sharing → Remote Login (if not needed)"))
        elif "Off" in out:
            findings.append(_finding("ssh-off", "Remote Login (SSH) is disabled",
                                     "INFO", out, ""))

    # ---- Automatic login ---------------------------------------------------
    rc, out, _ = _run(["defaults", "read", "/Library/Preferences/com.apple.loginwindow", "autoLoginUser"])
    if rc == 0 and out:
        findings.append(_finding("auto-login", f"Automatic login is enabled for `{out}`",
                                 "HIGH", out,
                                 "Disable Automatic Login in System Settings → Users & Groups"))
    elif rc != 0:
        findings.append(_finding("auto-login-off", "Automatic login is disabled",
                                 "INFO", "", ""))

    # ---- Software-update auto-check ---------------------------------------
    rc, out, _ = _run(["defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled"])
    if rc == 0:
        if out.strip() == "1":
            findings.append(_finding("auto-update-on", "Automatic update checks are enabled",
                                     "INFO", out, ""))
        else:
            findings.append(_finding("auto-update-off", "Automatic update checks are disabled",
                                     "MEDIUM", out,
                                     "Enable in System Settings → General → Software Update → Automatic Updates (info icon)"))

    return findings
