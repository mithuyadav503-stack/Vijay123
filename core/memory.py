"""Persistent conversation memory: facts, project state, instructions, decisions, errors, tasks, history."""

import datetime
import json
import os
import stat
import threading
from pathlib import Path

CATEGORIES = ("facts", "instructions", "decisions", "errors", "tasks_pending", "tasks_completed")


class MemoryManager:
    def __init__(self, data_dir, redact_fn=None):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.memory_file = self.data_dir / "memory.json"
        self.history_file = self.data_dir / "history.jsonl"
        self._redact = redact_fn or (lambda t: t)
        self._lock = threading.Lock()
        self.memory = self._load()

    # ---------------- persistence ----------------
    def _default(self):
        return {
            "facts": [],
            "instructions": [],
            "decisions": [],
            "errors": [],
            "tasks_pending": [],
            "tasks_completed": [],
            "project": {"name": None, "directory": None},
            "created": datetime.datetime.now().isoformat(timespec="seconds"),
        }

    def _load(self):
        if self.memory_file.exists():
            try:
                data = json.loads(self.memory_file.read_text(encoding="utf-8"))
                base = self._default()
                base.update({k: v for k, v in data.items() if v is not None})
                return base
            except Exception:
                pass
        return self._default()

    def _save(self):
        with self._lock:
            payload = json.dumps(self.memory, indent=2, ensure_ascii=False)
            self.memory_file.write_text(payload, encoding="utf-8")
            os.chmod(self.memory_file, stat.S_IRUSR | stat.S_IWUSR)

    # ---------------- structured memory ----------------
    def add(self, category, text):
        if category not in CATEGORIES:
            raise ValueError(f"Unknown memory category '{category}'. Use one of: {', '.join(CATEGORIES)}")
        entry = {
            "text": self._redact(text),
            "time": datetime.datetime.now().isoformat(timespec="seconds"),
        }
        self.memory[category].append(entry)
        self._save()
        return entry

    def list(self, category):
        if category == "all":
            return {c: self.memory[c] for c in CATEGORIES}
        if category not in CATEGORIES:
            raise ValueError(f"Unknown category '{category}'.")
        return self.memory[category]

    def search(self, query):
        q = query.lower()
        hits = []
        for cat in CATEGORIES:
            for i, entry in enumerate(self.memory[cat]):
                if q in entry["text"].lower():
                    hits.append({"category": cat, "index": i, **entry})
        return hits

    def edit(self, category, index, new_text):
        if category not in CATEGORIES:
            raise ValueError(f"Unknown category '{category}'.")
        self.memory[category][index]["text"] = self._redact(new_text)
        self.memory[category][index]["edited"] = datetime.datetime.now().isoformat(timespec="seconds")
        self._save()

    def delete(self, category, index):
        if category not in CATEGORIES:
            raise ValueError(f"Unknown category '{category}'.")
        removed = self.memory[category].pop(index)
        self._save()
        return removed

    def clear(self, category="all"):
        if category == "all":
            for cat in CATEGORIES:
                self.memory[cat] = []
            self.memory["project"] = self._default()["project"]
        elif category in CATEGORIES:
            self.memory[category] = []
        else:
            raise ValueError(f"Unknown category '{category}'.")
        self._save()

    # ---------------- project state ----------------
    def set_project(self, name, directory=None):
        self.memory["project"] = {
            "name": name,
            "directory": str(directory) if directory else self.memory["project"].get("directory"),
        }
        self._save()

    def get_project(self):
        return self.memory.get("project", {})

    # ---------------- conversation history ----------------
    def append_history(self, role, content):
        record = {
            "role": role,
            "content": self._redact(content),
            "time": datetime.datetime.now().isoformat(timespec="seconds"),
        }
        with self._lock, open(self.history_file, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, ensure_ascii=False) + "\n")

    def recent_history(self, limit=12):
        """Return the last `limit` turns as LLM messages (user/assistant only)."""
        if not self.history_file.exists():
            return []
        messages = []
        with open(self.history_file, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if rec.get("role") in ("user", "assistant") and rec.get("content"):
                    messages.append({"role": rec["role"], "content": rec["content"]})
        return messages[-limit:]

    def clear_history(self):
        if self.history_file.exists():
            self.history_file.unlink()

    def history_count(self):
        if not self.history_file.exists():
            return 0
        with open(self.history_file, "r", encoding="utf-8") as fh:
            return sum(1 for line in fh if line.strip())

    # ---------------- export ----------------
    def export(self, out_path):
        out = {
            "memory": self.memory,
            "history_turns": self.history_count(),
            "exported": datetime.datetime.now().isoformat(timespec="seconds"),
        }
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        Path(out_path).write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")
        return str(out_path)

    def status(self):
        counts = {c: len(self.memory[c]) for c in CATEGORIES}
        return {"entries": counts, "history_turns": self.history_count(),
                "project": self.get_project()}
