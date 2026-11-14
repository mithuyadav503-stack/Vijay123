"""Coding engine: project scaffolding, code writing with backups, running scripts and tests, README generation."""

import datetime
import json
import sys
from pathlib import Path

from core.security import PermissionDenied

README_TEMPLATE = """# {name}

Created by ULTIMATE AI AGENT on {date}.

## Description

{description}

## Structure

```
{name}/
```

## Usage

```bash
python main.py
```

## Notes

- Workspace: Termux Downloads directory
- Backups of modified files are stored in the agent's `backups/` folder.
"""


class CodingEngine:
    def __init__(self, file_manager, security, terminal, memory):
        self.fm = file_manager
        self.sec = security
        self.term = terminal
        self.mem = memory

    # ---------------- projects ----------------
    def create_project(self, name, description="A project created by ULTIMATE AI AGENT."):
        """Create a new project folder with README and main.py inside the workspace."""
        self.sec.check(2, f"create project '{name}'")
        base = self.sec.workspace
        project_dir = base / name
        if project_dir.exists():
            raise PermissionDenied(
                f"'{project_dir}' already exists. Refusing to overwrite existing files. Choose a new name."
            )
        project_dir.mkdir(parents=True)
        readme = README_TEMPLATE.format(name=name, description=description, date=datetime.date.today().isoformat())
        (project_dir / "README.md").write_text(readme, encoding="utf-8")
        (project_dir / "main.py").write_text(
            'def main():\n    print("Hello from ' + name + '!")\n\n\nif __name__ == "__main__":\n    main()\n',
            encoding="utf-8",
        )
        (project_dir / "__init__.py").touch()
        self.mem.set_project(name, str(project_dir))
        self.mem.add("decisions", f"Created project '{name}' at {project_dir}")
        self.sec.log("PROJECT", f"created {project_dir}")
        return {"path": str(project_dir), "files": ["README.md", "main.py"]}

    # ---------------- code files ----------------
    def write_code_file(self, path, content, backup=True):
        result = self.fm.write_file(path, content, backup=backup)
        if result.get("backup"):
            self.mem.add("decisions", f"Modified {result['path']} (backup: {result['backup']})")
        return result

    def edit_code_file(self, path, old_text, new_text):
        """Edit a file by replacing an exact snippet. Backs up first; refuses if snippet is absent."""
        read = self.fm.read_file(path)
        content = read["content"]
        if old_text not in content:
            raise PermissionDenied(
                f"Snippet not found in {path}. Nothing was modified. Check the exact text (including indentation)."
            )
        updated = content.replace(old_text, new_text, 1)
        return self.fm.write_file(path, updated, backup=True)

    def read_code(self, path):
        return self.fm.read_file(path)

    # ---------------- execution ----------------
    def run_python(self, script_path, args="", timeout=60):
        path = self.sec.safe_read(script_path)
        if not path.exists():
            return {"ok": False, "error": f"Script not found: {path} (paths resolve inside the workspace)"}
        if not path.name.endswith(".py"):
            return {"ok": False, "error": f"Not a Python script: {path.name}"}
        result = self.term.run_python(path, args=args, cwd=str(path.parent), timeout=timeout)
        if not result.get("ok") and result.get("stderr"):
            self.mem.add("errors", f"Running {path.name} failed: {result['stderr'][:300]}")
        return result

    def run_tests(self, project_dir):
        """Discover and run pytest or unittest tests in a project directory."""
        pdir = self.sec.validate_path(project_dir)
        test_files = list(pdir.rglob("test_*.py")) + list(pdir.rglob("*_test.py")) + list(pdir.rglob("tests.py"))
        if not test_files:
            return {"ok": True, "note": "No test files found.", "ran": 0}
        has_pytest = self.term.run(f"{sys.executable or 'python'} -c \"import pytest\"", interactive_confirm=False)
        if has_pytest.get("ok"):
            result = self.term.run(f"{sys.executable or 'python'} -m pytest {shlex_quote(str(pdir))} -q", cwd=str(pdir),
                                   timeout=120, interactive_confirm=False)
        else:
            result = self.term.run(
                f"{sys.executable or 'python'} -m unittest discover -s {shlex_quote(str(pdir))} -p 'test_*.py' -q",
                cwd=str(pdir), timeout=120, interactive_confirm=False,
            )
        result["test_files"] = [str(t) for t in test_files]
        return result

    # ---------------- documentation & reports ----------------
    def generate_readme(self, project_dir, description=None):
        pdir = self.sec.validate_path(project_dir)
        self.sec.check(2, f"generate README for {pdir.name}")
        files = [str(f.relative_to(pdir)) for f in sorted(pdir.rglob("*")) if f.is_file()][:50]
        tree = "\n".join(f"- `{f}`" for f in files) or "- (empty)"
        if description is None:
            existing = pdir / "README.md"
            description = "Project maintained by ULTIMATE AI AGENT."
            if existing.exists():
                description = existing.read_text(encoding="utf-8")[:500]
        readme = README_TEMPLATE.format(name=pdir.name, description=description,
                                        date=datetime.date.today().isoformat()) + "\n## Files\n\n" + tree + "\n"
        result = self.fm.write_file(pdir / "README.md", readme, backup=True)
        return result["path"]

    def generate_report(self, title, content_markdown, fmt="md"):
        """Write a Markdown or JSON report into the agent's reports/ directory."""
        self.sec.check(2, f"generate report '{title}'")
        reports = Path(__file__).resolve().parent.parent / "reports"
        reports.mkdir(parents=True, exist_ok=True)
        stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_title = "".join(c if c.isalnum() or c in "-_" else "_" for c in title)[:60]
        path = reports / f"{safe_title}.{stamp}.{fmt}"
        if fmt == "json":
            path.write_text(json.dumps(content_markdown, indent=2, ensure_ascii=False), encoding="utf-8")
        else:
            header = f"# {title}\n\n_Generated: {datetime.datetime.now().isoformat(timespec='seconds')}_\n\n"
            path.write_text(header + content_markdown, encoding="utf-8")
        self.sec.log("REPORT", str(path))
        return str(path)

    def project_history(self):
        return {
            "project": self.mem.get_project(),
            "decisions": self.mem.list("decisions")[-20:],
            "errors": self.mem.list("errors")[-20:],
            "completed_tasks": self.mem.list("tasks_completed")[-20:],
            "pending_tasks": self.mem.list("tasks_pending")[-20:],
        }


def shlex_quote(s):
    import shlex
    return shlex.quote(s)
