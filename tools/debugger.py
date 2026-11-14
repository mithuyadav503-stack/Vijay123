"""Debugging engine: parses tracebacks, classifies errors, explains in Hindi/English, attempts safe repairs."""

import re
import subprocess
import sys

from core.security import PermissionDenied

HINDI_EXPLANATIONS = {
    "ModuleNotFoundError": "Python ko '{module}' naam ka module nahi mila. Iska matlab ye dependency install nahi hai. Fix: `pip install {module}`.",
    "ImportError": "Import fail hua: kisi module se kuch import nahi ho pa raha. Module ka naam ya version check karein.",
    "SyntaxError": "Code mein syntax galti hai (typing/structure mistake). Error ki line number dekhein aur wahan spelling/brackets check karein.",
    "IndentationError": "Indentation (space/tab) galti hai. Us line ke aage-peeche ke spaces theek karein.",
    "NameError": "'{name}' naam ki koi variable/function define nahi hui. Spelling check karein ya use define karein.",
    "TypeError": "Galat type ka data use ho raha hai (jaise number + text). Variables ke types check karein.",
    "ValueError": "Value galat hai — type sahi hai par content/data invalid hai.",
    "KeyError": "Dictionary mein '{name}' key nahi mili. `.get()` ka use karein ya key check karein.",
    "IndexError": "List ke range se bahar index access ho raha hai. `len()` se pehle check karein.",
    "AttributeError": "'{name}' attribute object par exist nahi karta. Object ka type check karein.",
    "FileNotFoundError": "File nahi mili: '{name}'. Path sahi hai ya nahi check karein (workspace ke andar hona chahiye).",
    "PermissionError": "Permission problem hai. Android/Termux sandbox rok raha hai. Storage permission check karein (`termux-setup-storage`).",
    "ConnectionError": "Network connection fail hua. Internet check karein.",
    "ZeroDivisionError": "Zero se division ho rahi hai. Denominator check karein.",
    "RecursionError": "Function khud ko baar-baar call kar raha hai (infinite recursion).",
    "JSONDecodeError": "JSON data galat format mein hai. JSON validate karein.",
    "OverflowError": "Number bahut bada ho gaya computation ke liye.",
    "TimeoutError": "Operation time limit se zyada chala.",
}


class Debugger:
    def __init__(self, coding_engine, terminal, security, llm=None):
        self.coding = coding_engine
        self.term = terminal
        self.sec = security
        self.llm = llm

    # ---------------- diagnosis ----------------
    def diagnose(self, traceback_text):
        """Parse a traceback into a structured diagnosis with Hindi + English explanations."""
        diag = {"error_type": "Unknown", "message": "", "line": None, "file": None,
                "hindi": "", "english": "", "fix_suggestion": ""}
        if not traceback_text:
            diag["english"] = "No error output."
            diag["hindi"] = "Koi error output nahi mila."
            return diag

        m = re.search(r'File "([^"]+)", line (\d+)', traceback_text)
        if m:
            diag["file"], diag["line"] = m.group(1), int(m.group(2))

        m = re.search(r"^(\w+(?:\.\w+)*(?:Error|Exception|Interrupt|Warning))(?::\s*(.*))?$",
                      traceback_text.strip().splitlines()[-1] if traceback_text.strip() else "",
                      re.MULTILINE)
        last_line = traceback_text.strip().splitlines()[-1] if traceback_text.strip() else ""
        m2 = re.match(r"([\w.]+(?:Error|Exception|Interrupt))\s*:?\s*(.*)", last_line)
        if m2:
            diag["error_type"] = m2.group(1).split(".")[-1]
            diag["message"] = m2.group(2)
        else:
            diag["message"] = last_line

        etype = diag["error_type"]
        hindi = HINDI_EXPLANATIONS.get(etype, "Ye error Python ne diya hai. Upar ka message padhein — problem ki line number bhi di gayi hai.")
        diag["hindi"] = hindi.format(
            module=re.search(r"No module named '([\w.]+)'", diag["message"]).group(1)
            if "No module named" in diag["message"] else "module",
            name=re.search(r"name '([\w]+)'", diag["message"]).group(1)
            if "is not defined" in diag["message"] else "name",
        )
        diag["english"] = f"{etype}: {diag['message']}"

        if etype == "ModuleNotFoundError":
            mod = re.search(r"No module named '([\w.]+)'", diag["message"])
            if mod:
                diag["fix_suggestion"] = f"pip install {mod.group(1).split('.')[0]}"
        elif etype in ("SyntaxError", "IndentationError") and diag["line"]:
            diag["fix_suggestion"] = f"Check line {diag['line']} in {diag['file']}"
        return diag

    # ---------------- auto repair ----------------
    def auto_repair(self, script_path, traceback_text, max_attempts=3):
        """Attempt safe repairs: dependency install (level 4, confirmed), then LLM-guided patch."""
        diagnosis = self.diagnose(traceback_text)
        attempts = []

        if diagnosis["error_type"] == "ModuleNotFoundError":
            mod = re.search(r"No module named '([\w.]+)'", diagnosis["message"])
            if mod:
                pkg = mod.group(1).split(".")[0]
                attempts.append({"step": "install_dependency", "package": pkg,
                                 "result": self._install_package(pkg)})

        remaining = max_attempts - len(attempts)
        if remaining > 0 and self.llm is not None and self.llm.key_exists() and self.llm.model:
            attempts.append(self._llm_patch_attempt(script_path, traceback_text, diagnosis))

        retest = self.coding.run_python(script_path, timeout=60)
        return {"diagnosis": diagnosis, "attempts": attempts, "retest": retest}

    def _install_package(self, pkg):
        """Install a pip package. LEVEL 4 requires explicit confirmation."""
        self.sec.check(4, f"install pip package '{pkg}'")
        answer = input(f"  Install Python package '{pkg}' via pip? [y/N]: ").strip().lower()
        if answer not in ("y", "yes"):
            return {"ok": False, "note": "User declined installation."}
        return self.term.run(f"pip install {pkg}", timeout=300, interactive_confirm=False)

    def _llm_patch_attempt(self, script_path, traceback_text, diagnosis):
        """Ask the LLM for a corrected full file, show a diff-style preview, apply only after confirmation."""
        path = self.sec.safe_read(script_path)
        current = path.read_text(encoding="utf-8", errors="ignore")
        prompt = (
            "You are an expert Python debugger. Fix the bug in this file.\n"
            "Return ONLY the complete corrected file content, no explanations, no markdown fences.\n\n"
            f"FILE: {path.name}\n```python\n{current[:12000]}\n```\n\n"
            f"ERROR:\n{traceback_text[:4000]}\n"
        )
        try:
            fixed = self.llm.chat(
                [{"role": "user", "content": prompt}],
                temperature=0.1, max_tokens=4096,
            )
        except Exception as exc:
            return {"step": "llm_patch", "ok": False, "note": f"LLM unavailable: {exc}"}
        fixed = strip_code_fences(fixed)
        if fixed.strip() == current.strip():
            return {"step": "llm_patch", "ok": False, "note": "LLM returned identical content; no change applied."}
        print("\n  --- Proposed fix (first 40 lines) ---")
        for line in fixed.splitlines()[:40]:
            print(f"  {line}")
        if len(fixed.splitlines()) > 40:
            print(f"  ... ({len(fixed.splitlines())} lines total)")
        answer = input("\n  Apply this fix (a backup will be saved first)? [y/N]: ").strip().lower()
        if answer not in ("y", "yes"):
            return {"step": "llm_patch", "ok": False, "note": "User declined the patch."}
        result = self.coding.write_code_file(script_path, fixed, backup=True)
        return {"step": "llm_patch", "ok": True, "result": result}

    # ---------------- run + diagnose loop ----------------
    def run_and_diagnose(self, script_path, args=""):
        result = self.coding.run_python(script_path, args=args)
        if result.get("ok"):
            return {"ok": True, "result": result}
        tb = result.get("stderr", "") or result.get("error", "")
        diagnosis = self.diagnose(tb)
        return {"ok": False, "result": result, "diagnosis": diagnosis}


def strip_code_fences(text):
    text = text.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines)
    return text
