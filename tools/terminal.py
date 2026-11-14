"""Terminal executor: runs validated shell commands with permission checks, timeouts, and redacted logging."""

import os
import subprocess
import shlex

from core.security import PermissionDenied


class TerminalExecutor:
    # Commands allowed without confirmation at level 3 (still validated against the blocklist).
    WHITELIST = {
        "ls", "pwd", "echo", "cat", "head", "tail", "wc", "file", "which", "whoami",
        "uname", "date", "df", "du", "grep", "find", "stat", "id", "sort", "uniq",
        "diff", "sed", "awk", "python", "python3", "pip", "pip3", "git", "tar",
        "unzip", "gzip", "gunzip", "mkdir", "touch", "cp", "mv", "ping", "curl",
        "wget", "openssl", "jq", "ps", "pkg", "termux-info", "md5sum", "sha256sum",
        "node", "npm", "gcc", "g++", "clang", "make", "cmake", "cargo", "go", "javac", "java", "rustc",
    }

    def __init__(self, security, workdir=None, timeout=60):
        self.sec = security
        self.workdir = workdir
        self.timeout = timeout

    def run(self, command, cwd=None, timeout=None, interactive_confirm=True):
        """Execute a shell command after validation. Returns a structured result."""
        command = command.strip()
        if not command:
            return {"ok": False, "error": "Empty command."}
        if "\n" in command:
            return {"ok": False, "error": "Multi-line command rejected. Run one command at a time."}

        allowed, reason = self.sec.validate_command(command)
        if not allowed:
            return {"ok": False, "error": reason}

        tokens = shlex.split(command)
        base_cmd = tokens[0] if tokens else ""
        base_name = os.path.basename(base_cmd)
        import sys
        self.sec.check(3, f"execute command: {self.sec.redact(command)[:120]}")

        trusted = base_name in self.WHITELIST or (
            sys.executable and os.path.realpath(base_cmd) == os.path.realpath(sys.executable)
        )
        if not trusted:
            if not interactive_confirm:
                return {"ok": False, "error": f"Command '{base_cmd}' is not on the whitelist and confirmation is disabled."}
            answer = input(f"  '{base_cmd}' is not on the safe-command whitelist. Run it anyway? [y/N]: ").strip().lower()
            if answer not in ("y", "yes"):
                self.sec.log("DENY", f"user declined command: {base_cmd}")
                return {"ok": False, "error": "Command cancelled by user."}

        use_cwd = str(cwd) if cwd else (str(self.workdir) if self.workdir else None)
        self.sec.log("EXEC", self.sec.redact(command))
        try:
            proc = subprocess.run(
                command,
                shell=True,
                cwd=use_cwd,
                capture_output=True,
                text=True,
                timeout=timeout or self.timeout,
            )
            result = {
                "ok": proc.returncode == 0,
                "code": proc.returncode,
                "stdout": self.sec.redact(proc.stdout or "")[:20_000],
                "stderr": self.sec.redact(proc.stderr or "")[:20_000],
            }
            self.sec.audit("SHELL", command, exit_code=proc.returncode)
            return result
        except subprocess.TimeoutExpired:
            return {"ok": False, "error": f"Command timed out after {timeout or self.timeout}s."}
        except PermissionError:
            return {"ok": False, "error": "Permission denied by the operating system (Android/Termux sandbox)."}
        except FileNotFoundError:
            if use_cwd and not os.path.isdir(use_cwd):
                return {"ok": False, "error": f"Working directory does not exist: {use_cwd}"}
            return {"ok": False, "error": f"Command not found: '{base_name}'. Install it with: pkg install {base_name}"}

    def run_python(self, script_path, args="", cwd=None, timeout=None):
        """Run a Python script with the same interpreter running the agent."""
        import sys
        return self.run(
            f"{sys.executable or 'python'} {shlex.quote(str(script_path))}" + (f" {args}" if args else ""),
            cwd=cwd, timeout=timeout, interactive_confirm=False,
        )
