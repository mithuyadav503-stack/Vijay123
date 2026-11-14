"""File manager: sandboxed file operations inside the workspace, with secret-file protection."""

import os
import shutil
import zipfile
import tarfile
import gzip
from pathlib import Path

from core.security import PermissionDenied


class FileManager:
    def __init__(self, security, backup_dir=None):
        self.sec = security
        self.backup_dir = Path(backup_dir) if backup_dir else Path(__file__).resolve().parent.parent / "backups"

    # ---------------- listing & search ----------------
    def list_dir(self, path=".", recursive=False, limit=200):
        p = self.sec.validate_path(path)
        if not p.exists():
            raise FileNotFoundError(f"'{p}' does not exist.")
        if not p.is_dir():
            raise NotADirectoryError(f"'{p}' is not a directory.")
        results = []
        if recursive:
            walker = p.rglob("*")
        else:
            walker = p.iterdir()
        for item in sorted(walker, key=lambda x: str(x)):
            if len(results) >= limit:
                results.append({"note": f"... truncated at {limit} entries"})
                break
            try:
                entry = {
                    "path": str(item),
                    "name": item.name,
                    "type": "dir" if item.is_dir() else "file",
                    "size": item.stat().st_size if item.is_file() else None,
                    "secret": self.sec.is_secret_file(item),
                }
            except OSError:
                continue
            results.append(entry)
        return results

    def find_names(self, pattern, path=".", limit=100):
        p = self.sec.validate_path(path)
        matches = []
        for m in p.rglob(pattern):
            matches.append(str(m))
            if len(matches) >= limit:
                break
        return matches

    def grep(self, pattern, path=".", max_results=50, include_secret=False):
        """Search file contents recursively. Secret files are skipped entirely."""
        p = self.sec.validate_path(path)
        results = []
        for f in p.rglob("*"):
            if not f.is_file() or f.stat().st_size > 2_000_000:
                continue
            if self.sec.is_secret_file(f):
                results.append({"file": str(f), "skipped": "secret file - contents never read"})
                continue
            try:
                with open(f, "r", encoding="utf-8", errors="ignore") as fh:
                    for lineno, line in enumerate(fh, 1):
                        if pattern.lower() in line.lower():
                            results.append({"file": str(f), "line": lineno, "text": self.sec.redact(line.strip()[:200])})
                            if len(results) >= max_results:
                                return results
            except OSError:
                continue
        return results

    # ---------------- reading & writing ----------------
    def read_file(self, path, max_bytes=200_000):
        p = self.sec.safe_read(path)
        if not p.exists():
            raise FileNotFoundError(f"'{p}' does not exist.")
        if p.stat().st_size > max_bytes:
            with open(p, "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read(max_bytes)
            return {"path": str(p), "content": self.sec.redact(content), "truncated": True,
                    "size": p.stat().st_size}
        with open(p, "r", encoding="utf-8", errors="ignore") as fh:
            content = fh.read()
        return {"path": str(p), "content": self.sec.redact(content), "truncated": False,
                "size": p.stat().st_size}

    def backup_file(self, path):
        """Back up an existing file into backups/ before modification."""
        p = self.sec.validate_path(path)
        if not p.exists() or not p.is_file():
            return None
        import datetime
        stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = p.name.replace(os.sep, "_")
        dest = self.backup_dir / f"{safe_name}.{stamp}.bak"
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(p, dest)
        self.sec.log("BACKUP", f"{p} -> {dest}")
        return str(dest)

    def write_file(self, path, content, backup=True):
        """Create or overwrite a file. Existing files are backed up first (never silent)."""
        p = self.sec.validate_path(path, for_write=True)
        self.sec.check(2, f"write file {p.name}")
        backed_up = None
        if backup and p.exists():
            backed_up = self.backup_file(p)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(content)
        self.sec.log("WRITE", f"{p} ({len(content)} bytes, backup={backed_up})")
        self.sec.audit("WRITE", f"{p} ({len(content)} bytes)")
        return {"path": str(p), "bytes": len(content), "backup": backed_up, "overwritten": p.exists() and backed_up is not None}

    def append_file(self, path, content):
        p = self.sec.validate_path(path, for_write=True)
        self.sec.check(2, f"append to {p.name}")
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "a", encoding="utf-8") as fh:
            fh.write(content)
        return {"path": str(p), "appended": len(content)}

    # ---------------- structure operations ----------------
    def mkdir(self, path):
        p = self.sec.validate_path(path, for_write=True)
        self.sec.check(2, f"create directory {p.name}")
        p.mkdir(parents=True, exist_ok=True)
        self.sec.log("MKDIR", str(p))
        return str(p)

    def rename(self, src, dst):
        s = self.sec.validate_path(src, for_write=True)
        d = self.sec.validate_path(dst, for_write=True)
        self.sec.check(2, f"rename {s.name} -> {d.name}")
        if d.exists():
            raise PermissionDenied(f"'{d}' already exists. Refusing to overwrite. Choose another name.")
        s.rename(d)
        self.sec.log("RENAME", f"{s} -> {d}")
        return str(d)

    def copy(self, src, dst):
        s = self.sec.validate_path(src)
        d = self.sec.validate_path(dst, for_write=True)
        self.sec.check(2, f"copy {s.name} -> {d.name}")
        if d.exists():
            raise PermissionDenied(f"'{d}' already exists. Refusing to overwrite.")
        if s.is_dir():
            shutil.copytree(s, d)
        else:
            d.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(s, d)
        return str(d)

    def move(self, src, dst):
        s = self.sec.validate_path(src, for_write=True)
        d = self.sec.validate_path(dst, for_write=True)
        self.sec.check(2, f"move {s.name} -> {d.name}")
        if d.exists():
            raise PermissionDenied(f"'{d}' already exists. Refusing to overwrite.")
        shutil.move(str(s), str(d))
        return str(d)

    def delete(self, path):
        """Delete a file or directory. Requires LEVEL 5 + explicit confirmation (handled by caller)."""
        p = self.sec.validate_path(path, for_write=True)
        self.sec.require_confirm(5, f"permanently delete '{p}'")
        if p.is_dir():
            shutil.rmtree(p)
        else:
            p.unlink()
        self.sec.log("DELETE", str(p))
        return str(p)

    # ---------------- archives ----------------
    def extract_archive(self, path, dest=None):
        p = self.sec.validate_path(path)
        self.sec.check(2, f"extract archive {p.name}")
        if dest:
            dest = self.sec.validate_path(dest, for_write=True)
        else:
            dest = p.parent / (p.stem.replace(".tar", "") + "_extracted")
        dest.mkdir(parents=True, exist_ok=True)
        name = p.name.lower()
        if name.endswith(".zip"):
            with zipfile.ZipFile(p) as zf:
                zf.extractall(dest)
        elif name.endswith((".tar.gz", ".tgz", ".tar")):
            mode = "r:gz" if name.endswith((".tar.gz", ".tgz")) else "r:"
            with tarfile.open(p, mode) as tf:
                tf.extractall(dest)
        elif name.endswith(".gz"):
            out = dest / p.stem
            with gzip.open(p, "rb") as src_fh, open(out, "wb") as dst_fh:
                shutil.copyfileobj(src_fh, dst_fh)
        else:
            raise ValueError(f"Unsupported archive type: {p.name} (supported: .zip, .tar, .tar.gz, .tgz, .gz)")
        self.sec.log("EXTRACT", f"{p} -> {dest}")
        return str(dest)

    # ---------------- scanning ----------------
    def scan(self, path=".", max_entries=500):
        """Recursive scan producing a summary; flags potential secret files without reading them."""
        p = self.sec.validate_path(path)
        stats = {"root": str(p), "dirs": 0, "files": 0, "total_bytes": 0,
                 "secret_files": [], "extensions": {}}
        count = 0
        for item in p.rglob("*"):
            count += 1
            if count > max_entries:
                stats["truncated"] = True
                break
            if item.is_dir():
                stats["dirs"] += 1
                continue
            try:
                size = item.stat().st_size
            except OSError:
                continue
            stats["files"] += 1
            stats["total_bytes"] += size
            ext = item.suffix.lower() or "(none)"
            stats["extensions"][ext] = stats["extensions"].get(ext, 0) + 1
            if self.sec.is_secret_file(item):
                stats["secret_files"].append(str(item))
        return stats
