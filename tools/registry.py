"""Tool registry: JSON-schema'd tools, dispatch with timeouts, structured results, audit trail."""

import base64
import binascii
import difflib
import hashlib
import json
import sqlite3
import subprocess
import sys
import shlex
import threading
from pathlib import Path

from core.security import PermissionDenied


class Tool:
    def __init__(self, name, description, schema, handler, min_level=1):
        self.name = name
        self.description = description
        self.schema = schema          # {"type":"object","properties":{...},"required":[...]}
        self.handler = handler
        self.min_level = min_level

    def describe(self):
        return {"name": self.name, "description": self.description,
                "min_level": self.min_level, "parameters": self.schema.get("properties", {})}


class ToolRegistry:
    def __init__(self, security, file_manager, terminal, crypto):
        self.sec = security
        self.fm = file_manager
        self.term = terminal
        self.crypto = crypto
        self.tools = {}
        self._register_builtins()

    # ---------------- registration & dispatch ----------------
    def register(self, tool):
        self.tools[tool.name] = tool

    def list(self):
        return [t.describe() for t in self.tools.values()]

    def dispatch(self, name, args=None, timeout=60):
        args = dict(args or {})
        tool = self.tools.get(name)
        if not tool:
            return {"ok": False, "tool": name, "error": f"Unknown tool '{name}'. Use /tools."}
        missing = [k for k in tool.schema.get("required", []) if k not in args]
        if missing:
            return {"ok": False, "tool": name, "error": f"Missing required argument(s): {', '.join(missing)}"}
        try:
            self.sec.check(tool.min_level, f"tool {name}")
        except PermissionDenied as exc:
            return {"ok": False, "tool": name, "error": str(exc)}

        result = {}

        def runner():
            try:
                result["value"] = tool.handler(**args)
                result["ok"] = True
            except Exception as exc:
                result["ok"] = False
                result["error"] = f"{type(exc).__name__}: {exc}"

        thread = threading.Thread(target=runner, daemon=True)
        thread.start()
        thread.join(timeout)
        if thread.is_alive():
            return {"ok": False, "tool": name, "error": f"Tool timed out after {timeout}s."}
        out = {"ok": result.get("ok", False), "tool": name}
        if result.get("ok"):
            out["result"] = result["value"]
        else:
            out["error"] = result.get("error", "unknown error")
        return out

    # ---------------- built-in tools ----------------
    def _register_builtins(self):
        reg = self.register

        reg(Tool("read_file", "Read a text file inside the workspace.",
                 {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
                 self._read_file, min_level=1))

        reg(Tool("write_file", "Create or overwrite a file (backup taken automatically).",
                 {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
                  "required": ["path", "content"]},
                 lambda path, content: self.fm.write_file(path, content), min_level=2))

        reg(Tool("append_file", "Append text to a file.",
                 {"type": "object", "properties": {"path": {"type": "string"}, "content": {"type": "string"}},
                  "required": ["path", "content"]},
                 lambda path, content: self.fm.append_file(path, content), min_level=2))

        reg(Tool("list_dir", "List a directory, optionally recursive.",
                 {"type": "object", "properties": {"path": {"type": "string"}, "recursive": {"type": "boolean"}}},
                 lambda path=".", recursive=False: self.fm.list_dir(path, recursive=recursive), min_level=1))

        reg(Tool("glob", "Find files by wildcard pattern (e.g. *.py).",
                 {"type": "object", "properties": {"pattern": {"type": "string"}, "path": {"type": "string"}},
                  "required": ["pattern"]},
                 lambda pattern, path=".": self.fm.find_names(pattern, path), min_level=1))

        reg(Tool("grep", "Regex search inside files (secret files are skipped).",
                 {"type": "object", "properties": {"pattern": {"type": "string"}, "path": {"type": "string"},
                                                   "max_results": {"type": "integer"}},
                  "required": ["pattern"]},
                 self._grep, min_level=1))

        reg(Tool("file_stat", "File metadata: size, times, permissions.",
                 {"type": "object", "properties": {"path": {"type": "string"}}, "required": ["path"]},
                 self._file_stat, min_level=1))

        reg(Tool("hash", "Hash text or a file. Algos: sha256, sha512, sha3_256, sha3_512, blake2b, md5, sha1.",
                 {"type": "object", "properties": {"text": {"type": "string"}, "path": {"type": "string"},
                                                   "algo": {"type": "string"}}},
                 self._hash, min_level=1))

        reg(Tool("hexdump", "Hex dump of the first bytes of a file.",
                 {"type": "object", "properties": {"path": {"type": "string"}, "limit": {"type": "integer"}},
                  "required": ["path"]},
                 self._hexdump, min_level=1))

        reg(Tool("base64_encode", "Base64-encode text.",
                 {"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]},
                 lambda text: base64.b64encode(text.encode()).decode(), min_level=1))

        reg(Tool("base64_decode", "Decode base64 text.",
                 {"type": "object", "properties": {"text": {"type": "string"}}, "required": ["text"]},
                 self._b64decode, min_level=1))

        reg(Tool("run_shell", "Run a validated shell command (permission level 3).",
                 {"type": "object", "properties": {"command": {"type": "string"}, "cwd": {"type": "string"},
                                                   "timeout": {"type": "integer"}},
                  "required": ["command"]},
                 self._run_shell, min_level=3))

        reg(Tool("python_eval", "Run a short Python snippet and return stdout/stderr (level 3).",
                 {"type": "object", "properties": {"code": {"type": "string"}, "timeout": {"type": "integer"}},
                  "required": ["code"]},
                 self._python_eval, min_level=3))

        reg(Tool("edit_file", "Replace an exact snippet in a file (backup taken first).",
                 {"type": "object", "properties": {"path": {"type": "string"}, "old_text": {"type": "string"},
                                                   "new_text": {"type": "string"}},
                  "required": ["path", "old_text", "new_text"]},
                 self._edit_file, min_level=2))

        reg(Tool("diff", "Unified diff of two files.",
                 {"type": "object", "properties": {"path_a": {"type": "string"}, "path_b": {"type": "string"}},
                  "required": ["path_a", "path_b"]},
                 self._diff, min_level=1))

        reg(Tool("download", "Download a URL into the workspace via curl.",
                 {"type": "object", "properties": {"url": {"type": "string"}, "dest": {"type": "string"}},
                  "required": ["url"]},
                 self._download, min_level=3))

        reg(Tool("extract_archive", "Extract .zip / .tar / .tar.gz / .gz archives.",
                 {"type": "object", "properties": {"path": {"type": "string"}, "dest": {"type": "string"}},
                  "required": ["path"]},
                 lambda path, dest=None: self.fm.extract_archive(path, dest), min_level=2))

        reg(Tool("sqlite_query", "Run SQL on a SQLite database file in the workspace.",
                 {"type": "object", "properties": {"path": {"type": "string"}, "query": {"type": "string"}},
                  "required": ["path", "query"]},
                 self._sqlite_query, min_level=2))

    # ---------------- handlers ----------------
    def _read_file(self, path):
        read = self.fm.read_file(path)
        return {"path": read["path"], "content": read["content"], "truncated": read["truncated"]}

    def _grep(self, pattern, path=".", max_results=50):
        return self.fm.grep(pattern, path, max_results=max_results)

    @staticmethod
    def _file_stat(path):
        p = Path(path).expanduser()
        st = p.stat()
        return {"path": str(p), "size": st.st_size, "mode": oct(st.st_mode)[-3:],
                "is_dir": p.is_dir(), "modified": st.st_mtime}

    def _hash(self, text=None, path=None, algo="sha256"):
        algo = algo.lower().replace("-", "_")
        if path:
            return self.crypto.hash_file(path, algo)
        if text is None:
            raise ValueError("Provide either 'text' or 'path'.")
        return self.crypto.hash_text(text, algo)

    @staticmethod
    def _hexdump(path, limit=512):
        p = Path(path).expanduser()
        data = p.read_bytes()[:limit]
        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i + 16]
            hexpart = " ".join(f"{b:02x}" for b in chunk)
            asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{i:08x}  {hexpart:<47}  |{asc}|")
        return {"path": str(p), "dump": "\n".join(lines), "total_size": p.stat().st_size}

    @staticmethod
    def _b64decode(text):
        try:
            return base64.b64decode(text, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError) as exc:
            raise ValueError(f"Invalid base64 input: {exc}") from exc

    def _run_shell(self, command, cwd=None, timeout=60):
        return self.term.run(command, cwd=cwd, timeout=timeout)

    def _python_eval(self, code, timeout=30):
        self.sec.log("EXEC", f"python_eval({len(code)} chars)")
        try:
            proc = subprocess.run([sys.executable or "python", "-c", code],
                                  capture_output=True, text=True, timeout=timeout)
            self.sec.audit("PYTHON_EVAL", code[:120], exit_code=proc.returncode)
            return {"code": proc.returncode, "stdout": self.sec.redact(proc.stdout)[:10_000],
                    "stderr": self.sec.redact(proc.stderr)[:10_000]}
        except subprocess.TimeoutExpired:
            return {"code": None, "error": f"Timed out after {timeout}s"}

    def _edit_file(self, path, old_text, new_text):
        read = self.fm.read_file(path)
        if old_text not in read["content"]:
            raise ValueError("old_text not found in file; nothing changed.")
        return self.fm.write_file(path, read["content"].replace(old_text, new_text, 1), backup=True)

    @staticmethod
    def _diff(path_a, path_b):
        a = Path(path_a).expanduser().read_text(errors="ignore").splitlines()
        b = Path(path_b).expanduser().read_text(errors="ignore").splitlines()
        return "\n".join(difflib.unified_diff(a, b, fromfile=str(path_a), tofile=str(path_b))) or "(no differences)"

    def _download(self, url, dest=None):
        dest = dest or url.rstrip("/").split("/")[-1] or "download.bin"
        target = self.sec.validate_path(dest, for_write=True)
        if not url.startswith(("http://", "https://")):
            raise ValueError("Only http(s) URLs are allowed.")
        return self.term.run(f"curl -L --max-time 120 -o {shlex_quote(str(target))} {shlex_quote(url)}",
                             timeout=150, interactive_confirm=False)

    def _sqlite_query(self, path, query):
        p = self.sec.safe_read(path)
        if not p.exists():
            raise FileNotFoundError(f"{p} does not exist.")
        conn = sqlite3.connect(str(p))
        conn.row_factory = sqlite3.Row
        try:
            cur = conn.execute(query)
            if query.strip().lower().startswith(("select", "pragma", "explain")):
                rows = [dict(r) for r in cur.fetchmany(200)]
                return {"rows": rows, "count": len(rows)}
            conn.commit()
            return {"rows_affected": cur.rowcount}
        finally:
            conn.close()


def shlex_quote(s):
    import shlex
    return shlex.quote(s)
