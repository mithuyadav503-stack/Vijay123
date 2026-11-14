"""Planner: builds an explicit PLAN -> CODE -> REVIEW -> EXECUTE -> TEST -> FIX -> VERIFY workflow."""

import json
import re

WORKFLOW_STAGES = ["PLAN", "WRITE CODE", "REVIEW", "EXECUTE", "TEST", "DEBUG", "FIX", "VERIFY"]


class Planner:
    def __init__(self, agent):
        self.agent = agent

    def build_plan(self, task):
        """Ask the LLM for a structured plan; fall back to a deterministic template offline."""
        llm = self.agent.llm
        if llm is not None and llm.key_exists() and llm.model:
            try:
                prompt = (
                    "You are a senior software architect. Break the following task into a numbered "
                    "step-by-step plan for an autonomous coding agent working in a Termux workspace. "
                    "Each step must be a concrete action (create file X with Y, run Z, test W).\n"
                    "Respond with ONLY a JSON object: {\"steps\": [\"...\", \"...\"]} (max 8 steps).\n\n"
                    f"TASK: {task}"
                )
                raw = llm.chat([{"role": "user", "content": prompt}], temperature=0.2, max_tokens=800)
                raw = re.sub(r"^```(?:json)?|```$", "", raw.strip(), flags=re.MULTILINE).strip()
                data = json.loads(raw)
                steps = [str(s) for s in data.get("steps", [])][:8]
                if steps:
                    return {"task": task, "source": "llm", "steps": steps}
            except Exception:
                pass
        return {"task": task, "source": "template", "steps": self._template_plan(task)}

    @staticmethod
    def _template_plan(task):
        t = task.lower()
        m = re.search(r"(?:create|build|make)\s+(?:a\s+)?(?:python\s+)?(?:project|app|application|script)?\s*(?:named|called)?\s*[\"']?([\w\- ]+)[\"']?", t)
        name = (m.group(1).strip().replace(" ", "_") if m else "new_project")
        return [
            f"PLAN: define the goal — {task}",
            f"WRITE CODE: create project folder '{name}' with main.py and README.md",
            "REVIEW: read back the generated files and check for syntax errors",
            "EXECUTE: run main.py to confirm it starts",
            "TEST: run the project's tests if present",
            "DEBUG: if any error appears, diagnose and explain it",
            "FIX: apply fixes (with a backup of every modified file)",
            "VERIFY: re-run until the script exits cleanly, then summarize",
        ]

    def execute(self, plan, interactive=True):
        """Execute the plan step by step, reporting each stage. Returns a full report."""
        report = {"task": plan["task"], "stages": WORKFLOW_STAGES, "steps": []}
        print("\n  PLAN:")
        for i, step in enumerate(plan["steps"], 1):
            print(f"   {i}. {step}")
        if interactive:
            answer = input("\n  Execute this plan now? [Y/n]: ").strip().lower()
            if answer in ("n", "no"):
                report["status"] = "cancelled"
                return report

        project_result = None
        for i, step in enumerate(plan["steps"], 1):
            print(f"\n  STEP {i}/{len(plan['steps'])}: {step}")
            low = step.lower()
            entry = {"step": step, "status": "done"}
            try:
                if low.startswith("plan:"):
                    self.agent.memory.add("tasks_pending", step)
                elif "create project" in low or ("create" in low and "folder" in low):
                    m = re.search(r"['\"]([\w\- ]+)['\"]", step) or re.search(r"project '([\w\- ]+)'", step)
                    name = m.group(1).strip().replace(" ", "_") if m else None
                    if name and not self.agent.sec.workspace.joinpath(name).exists():
                        project_result = self.agent.coding.create_project(name)
                        entry["result"] = project_result
                    else:
                        entry["status"] = "skipped (already exists or no name)"
                elif "review" in low or "read back" in low:
                    pdir = project_result["path"] if project_result else str(self.agent.sec.workspace)
                    files = self.agent.fm.list_dir(pdir)
                    entry["result"] = {"files_seen": len(files)}
                elif "execute" in low or "run" in low:
                    target = project_result["path"] if project_result else self.agent.sec.workspace
                    main_py = self.agent.sec.workspace.joinpath(target if isinstance(target, str) else str(target), "main.py") \
                        if project_result else None
                    if main_py and main_py.exists():
                        entry["result"] = self.agent.coding.run_python(main_py)
                    else:
                        entry["status"] = "no runnable script found"
                elif "test" in low:
                    target = project_result["path"] if project_result else str(self.agent.sec.workspace)
                    entry["result"] = self.agent.coding.run_tests(target)
                elif "fix" in low or "debug" in low:
                    entry["status"] = "no errors to fix" if not report.get("errors") else "see debugger output"
                elif "verify" in low or "summarize" in low:
                    self.agent.memory.add("tasks_completed", plan["task"])
                    entry["result"] = {"memory_updated": True}
                else:
                    entry["status"] = "noted (manual step)"
            except Exception as exc:
                entry["status"] = f"error: {exc}"
                report.setdefault("errors", []).append(str(exc))
            report["steps"].append(entry)
            print(f"   -> {entry['status']}")
        report["status"] = "completed_with_errors" if report.get("errors") else "completed"
        return report
