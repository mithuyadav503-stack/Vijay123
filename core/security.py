"""Security manager: permission levels, path sandboxing, command validation, secret redaction."""

import os
import re
import datetime
from pathlib import Path

LEVEL_DESCRIPTIONS = {
    1: "Read-only operations (list, read, search)",
    2: "Create and edit files inside the workspace",
    3: "Execute scripts and validated shell commands",
    4: "Install packages and modify project configuration",
    5: "Destructive operations (delete, overwrite outside project)",
}

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Filename patterns that may contain secrets: their CONTENT is never read or logged.
SECRET_FILE_PATTERNS = re.compile(
    r"(^|/)(\.env|\.env\..*|id_rsa.*|id_dsa.*|id_ed25519.*|.*\.pem|.*\.key|.*\.p12|"
    r".*\.pfx|.*keystore.*|credentials.*|\.netrc|wallet\.dat|.*seed.*phrase.*|"
    r"\.git-credentials|\.aws/credentials|\.ssh/known_hosts)$",
    re.IGNORECASE,
)

# Secret-like values that must be redacted from any output or log line.
REDACTION_RULES = [
    (re.compile(r"sk-or-v1-[A-Za-z0-9\-_]{16,}"), "[REDACTED_API_KEY]"),
    (re.compile(r"sk-[A-Za-z0-9\-_]{16,}"), "[REDACTED_API_KEY]"),
    (re.compile(r"(?i)(api[_-]?key|token|secret|password)\s*[=:]\s*\S+"), r"\1=[REDACTED]"),
    (re.compile(r"\b(?:[5-9][1-9HK])\b[1-9A-HJ-NP-Za-km-z]{25,34}"), "[REDACTED_PRIVATE_KEY_DATA]"),
    (re.compile(r"\b[A-Fa-f0-9]{64,}\b"), "[REDACTED_HEX_BLOB]"),
    (
        re.compile(
            r"\b(?:abandon|ability|absurd|access|acid|actress)(?:\s+(?:abandon|ability|absurd|access|acid|actress|\w+)){11,23}\b"
        ),
        "[REDACTED_SEED_PHRASE]",
    ),
]

DANGEROUS_COMMAND_PATTERNS = [
    (re.compile(r"\brm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+)*(/|~|\$HOME|\.\.)", re.IGNORECASE), "recursive delete of a system/home path"),
    (re.compile(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f", re.IGNORECASE), "rm -rf"),
    (re.compile(r"\bmkfs(\.\w+)?\b"), "filesystem formatting"),
    (re.compile(r"\bdd\s+if="), "raw disk write (dd)"),
    (re.compile(r":\(\)\s*\{.*\};\s*:"), "fork bomb"),
    (re.compile(r"\b(shutdown|reboot|poweroff|halt)\b"), "system power control"),
    (re.compile(r"chmod\s+(-R\s+)?777\s+/( |$)"), "chmod 777 on filesystem root"),
    (re.compile(r">\s*/dev/(sd|mmcblk|block)"), "direct block-device write"),
    (re.compile(r"\bhistory\s+-c\b"), "shell history wipe"),
    (re.compile(r"\b(?:curl|wget)\b[^|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b"), "pipe remote script into shell"),
    (re.compile(r"\bpasswd\b|\buseradd\b|\buserdel\b|\busermod\b"), "user account modification"),
    (re.compile(r"\btermux-change-repo\b|\bsu\b|\bsudo\b"), "privilege escalation attempt"),
    (re.compile(r"\benv\b.*-i\b|\bunset\s+PATH\b"), "environment tampering"),
    (re.compile(r"\bkill(all)?\b.*-9\s+1\b"), "killing PID 1"),
    (re.compile(r"\bchown\b.*\s/\s*$"), "ownership change on root"),
]

# Commands that are always allowed without extra prompting (read-only, level 1).
SAFE_COMMANDS = {
    "ls", "pwd", "echo", "cat", "head", "tail", "wc", "file", "which", "whoami",
    "uname", "date", "df", "du", "grep", "find", "stat", "tree", "id", "env",
    "python", "python3", "pip", "pip3", "git", "tar", "unzip", "gzip", "gunzip",
    "mkdir", "touch", "cp", "mv", "diff", "sort", "uniq", "sed", "awk", "ping",
    "pkg", "termux-info", "curl", "wget", "nano", "vim", "less", "md5sum",
    "sha256sum", "openssl", "jq", "ps", "top",
}


class PermissionDenied(Exception):
    """Raised when an action is not permitted at the current level or fails validation."""


class SecurityManager:
    def __init__(self, workspace, settings, log_file=None):
        self.workspace = Path(workspace).expanduser().resolve()
        self.settings = settings
        self.max_level = int(settings.get("max_permission_level", 3))
        self.log_file = Path(log_file) if log_file else PROJECT_ROOT / "logs" / "security.log"
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        self.auto_confirm = None  # set to True/False to bypass interactive prompts (tests/automation)

    # ---------- permission levels ----------
    def check(self, level, action):
        """Verify an action is allowed at the configured permission level."""
        if level > self.max_level:
            self.log("DENY", f"level {level} required for: {action} (max {self.max_level})")
            raise PermissionDenied(
                f"This action needs permission LEVEL {level} ({LEVEL_DESCRIPTIONS.get(level, '?')}), "
                f"but the agent is limited to LEVEL {self.max_level}. "
                f"Raise the level with /settings if you accept the risk."
            )
        return True

    def confirm(self, prompt, level=None):
        """Explicit interactive y/N confirmation (mandatory for level 5)."""
        if level:
            print(f"  [PERMISSION LEVEL {level}] {LEVEL_DESCRIPTIONS.get(level, '')}")
        if self.auto_confirm is not None:
            ok = bool(self.auto_confirm)
            self.log("CONFIRM-AUTO" if ok else "CONFIRM-AUTO-NO", prompt)
            return ok
        answer = input(f"  CONFIRM: {prompt} [y/N]: ").strip().lower()
        ok = answer in ("y", "yes")
        self.log("CONFIRM" if ok else "CONFIRM-NO", prompt)
        return ok

    def require_confirm(self, level, prompt):
        """check() + explicit confirmation for sensitive levels."""
        self.check(level, prompt)
        if level >= 5 or self.settings.get("confirm_sensitive", True) and level >= 4:
            if not self.confirm(prompt, level=level):
                raise PermissionDenied("Operation cancelled by user.")

    # ---------- path sandboxing ----------
    def validate_path(self, path, for_write=False):
        """Resolve a path and ensure it stays inside the allowed workspace or the project itself."""
        p = Path(path).expanduser()
        if not p.is_absolute():
            p = self.workspace / p
        p = p.resolve()
        allowed = [self.workspace, PROJECT_ROOT]
        inside = any(str(p) == str(root) or str(p).startswith(str(root) + os.sep) for root in allowed)
        if not inside:
            self.log("DENY", f"path outside workspace: {p}")
            raise PermissionDenied(
                f"Path '{p}' is outside the allowed workspace ({self.workspace}). "
                f"Add it with /settings allow_path <path> if you explicitly want access."
            )
        return p

    def add_allowed_path(self, path):
        extra = str(Path(path).expanduser().resolve())
        paths = self.settings.setdefault("extra_allowed_paths", [])
        if extra not in paths:
            paths.append(extra)
        return extra

    def is_secret_file(self, path):
        return bool(SECRET_FILE_PATTERNS.search(str(path)))

    # ---------- command validation ----------
    def validate_command(self, command):
        """Return (allowed, reason). Blocks clearly destructive/escalation commands."""
        for pattern, reason in DANGEROUS_COMMAND_PATTERNS:
            if pattern.search(command):
                self.log("DENY", f"dangerous command ({reason}): {self.redact(command)}")
                return False, f"Blocked: command appears to perform {reason}."
        return True, "ok"

    # ---------- secret redaction ----------
    def redact(self, text):
        """Remove secret-like material from any text before display or logging."""
        if not isinstance(text, str):
            text = str(text)
        for pattern, replacement in REDACTION_RULES:
            text = pattern.sub(replacement, text)
        return text

    def safe_read(self, path):
        """Read a file unless it is classified as a secret file."""
        p = self.validate_path(path)
        if self.is_secret_file(p):
            self.log("DENY", f"refused to read secret file: {p.name}")
            raise PermissionDenied(
                f"'{p.name}' looks like a secret/credential file. Its contents are never read, "
                f"displayed, or sent to the AI model."
            )
        return p

    # ---------- logging ----------
    def audit(self, event, detail="", exit_code=None):
        """Append to audit.log: timestamp | event | exit code | redacted detail."""
        line = (f"{datetime.datetime.now().isoformat(timespec='seconds')} | {event} | "
                f"exit={exit_code if exit_code is not None else '-'} | {self.redact(detail)}")
        audit_file = self.log_file.parent / "audit.log"
        try:
            with open(audit_file, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError:
            pass

    def log(self, event, detail=""):
        line = f"{datetime.datetime.now().isoformat(timespec='seconds')} | {event} | {self.redact(detail)}"
        try:
            with open(self.log_file, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError:
            pass

    def status(self):
        return {
            "workspace": str(self.workspace),
            "max_level": self.max_level,
            "levels": LEVEL_DESCRIPTIONS,
        }
