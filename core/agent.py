"""Agent core: routes commands and natural language, selects tools, builds LLM context, auto-repairs."""

import datetime
import json
import os
import re
import sys
from pathlib import Path

from core.providers import PROVIDER_PRESETS, ProviderError
from core.security import PermissionDenied

LLMError = ProviderError

SYSTEM_PROMPT = """You are ULTIMATE AI AGENT, an expert AI coding and cybersecurity assistant running on Android Termux, powered by OpenRouter.

You are an expert in: Python, JavaScript, TypeScript, C, C++, Java, Rust, Go, shell/Bash, Linux, Android/Termux, software architecture, databases, API development, web development, automation, debugging, reverse engineering for authorized research, blockchain technology, Bitcoin architecture, cryptocurrency technology, cryptography, hashing, digital signatures, public/private key cryptography, smart contracts, network security, ethical hacking in authorized environments, vulnerability analysis, secure coding, and malware analysis in isolated authorized research environments.

Rules:
- Be technically accurate and explain your reasoning.
- If you are unsure or need current documentation, say so instead of inventing facts.
- Refuse requests for unauthorized attacks, credential theft, ransomware, destructive malware, stealth persistence, or attacks against third-party systems. Offer defensive/educational alternatives.
- Never ask the user to paste private keys, seed phrases, or passwords into the chat.
- The user may write in Hindi or English. Reply in the language they use (Hindi users get Hindi answers with technical terms in English).
- The agent's workspace is the Termux Downloads directory. File operations and shell commands the user asks for are executed by the agent's tools, not by you; describe what should be done and the agent will act.
- Current date: {date}. Workspace: {workspace}.
"""


class Agent:
    def __init__(self, llm, memory, security, file_manager, terminal, coding, debugger,
                 crypto, blockchain, security_analyzer, planner, settings, tools=None):
        self.llm = llm
        self.memory = memory
        self.sec = security
        self.fm = file_manager
        self.term = terminal
        self.coding = coding
        self.debugger = debugger
        self.crypto = crypto
        self.blockchain = blockchain
        self.sec_analyzer = security_analyzer
        self.planner = planner
        self.settings = settings
        self.tools = tools
        self.running = True

    # ---------------- command routing ----------------
    def handle_command(self, raw):
        """Handle a /command. Returns True if the REPL should continue printing a blank line."""
        parts = raw.strip().split(maxsplit=1)
        cmd = parts[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else ""
        handler = {
            "/help": self.cmd_help, "/model": self.cmd_model, "/apikey": self.cmd_apikey,
            "/status": self.cmd_status, "/files": self.cmd_files, "/scan": self.cmd_scan,
            "/code": self.cmd_code, "/debug": self.cmd_debug, "/run": self.cmd_run,
            "/create": self.cmd_create, "/projects": self.cmd_projects,
            "/memory": self.cmd_memory, "/history": self.cmd_history,
            "/settings": self.cmd_settings, "/clear": self.cmd_clear, "/exit": self.cmd_exit,
            "/provider": self.cmd_provider, "/tools": self.cmd_tools,
            "/plan": self.cmd_plan, "/task": self.cmd_task,
            "/doctor": self.cmd_doctor, "/audit": self.cmd_audit,
        }
        fn = handler.get(cmd)
        if fn is None:
            print(f"  Unknown command '{cmd}'. Type /help for the command list.")
            return True
        try:
            fn(arg)
        except PermissionDenied as exc:
            print(f"\n  [PERMISSION] {exc}")
        except LLMError as exc:
            print(f"\n  [AI ERROR - {exc.kind}] {exc}")
        except FileNotFoundError as exc:
            print(f"\n  [FILE ERROR] {exc}")
        except KeyboardInterrupt:
            print("\n  (cancelled)")
        return True

    # ---------------- natural language ----------------
    def chat(self, user_text):
        """Send a natural-language message to the LLM with memory context; handle local intents first."""
        intent = self.detect_intent(user_text)
        if intent:
            print(f"  [tool: {intent[0]}]")
            return
        self.memory.append_history("user", user_text)
        messages = [{"role": "system", "content": SYSTEM_PROMPT.format(
            date=datetime.date.today().isoformat(), workspace=self.sec.workspace)}]
        project = self.memory.get_project()
        if project.get("name"):
            messages.append({"role": "system", "content":
                f"Current project: {project['name']} at {project.get('directory', 'unknown')}."})
        mem_context = []
        for cat in ("instructions", "decisions", "errors"):
            for entry in self.memory.list(cat)[-5:]:
                mem_context.append(f"[{cat}] {entry['text']}")
        if mem_context:
            messages.append({"role": "system", "content": "Relevant memory:\n" + "\n".join(mem_context)})
        messages.extend(self.trimmed_history())
        messages.append({"role": "user", "content": user_text})
        print("  ...thinking")
        reply = self.llm.chat(messages)
        self.memory.append_history("assistant", reply)
        print(f"\n{reply}\n")

    # ---------------- context trimming (prevents repetition across turns) ----------------
    MAX_CONTEXT_CHARS = 6000
    MAX_MESSAGE_CHARS = 1200

    def trimmed_history(self):
        """Recent history, per-message truncated, total-capped, so the model does not
        parrot earlier turns."""
        history = self.memory.recent_history(8)
        trimmed = [{"role": m["role"], "content": m["content"][:self.MAX_MESSAGE_CHARS]}
                   for m in history]
        total = sum(len(m["content"]) for m in trimmed)
        while total > self.MAX_CONTEXT_CHARS and len(trimmed) > 2:
            total -= len(trimmed[0]["content"])
            trimmed.pop(0)
        return trimmed

    # ---------------- intent detection (local tools without burning tokens) ----------------
    def detect_intent(self, text):
        t = text.strip()
        low = t.lower()

        m = re.match(r"(?i)hash\s+(sha256|sha512|sha3-?256|sha3-?512|blake2b|blake2s)\s*[:=]?\s*(.+)", t)
        if m:
            algo = m.group(1).lower().replace("-", "_").replace("sha3_256", "sha3_256")
            algo = algo.replace("sha3256", "sha3_256").replace("sha3512", "sha3_512")
            result = self.crypto.hash_text(m.group(2).strip(), algo)
            print(f"  {result['algorithm']}: {result['digest']}")
            return ("crypto.hash", result)

        m = re.match(r"(?i)hmac\s+(sha256|sha512)\s+key\s*[:=]\s*(\S+)\s+msg\s*[:=]\s*(.+)", t)
        if m:
            result = self.crypto.hmac_compute(m.group(2), m.group(3), m.group(1))
            print(f"  {result['algorithm']}: {result['digest']}")
            return ("crypto.hmac", result)

        m = re.match(r"(?i)(?:analyze|check|validate)\s+(?:btc|bitcoin)\s+address\s*[:=]?\s*(\S+)", t)
        if m:
            result = self.blockchain.analyze_btc_address(m.group(1))
            print(json.dumps(result, indent=2))
            return ("blockchain.address", result)

        m = re.match(r"(?i)parse\s+(?:raw\s+)?(?:btc|bitcoin)\s+tx\s*[:=]?\s*([0-9a-fA-F]+)", t)
        if m:
            result = self.blockchain.parse_raw_tx(m.group(1))
            print(json.dumps(result, indent=2))
            return ("blockchain.tx", result)

        m = re.match(r"(?i)(?:audit|security\s*check|analyze)\s+(?:the\s+)?(?:file|code)\s+(.+)", t)
        if m and m.group(1).strip().endswith(".py"):
            result = self.sec_analyzer.audit_python_file(m.group(1).strip())
            print(json.dumps(result, indent=2))
            return ("security.audit", result)

        m = re.match(r"(?i)create\s+(?:a\s+)?(?:new\s+)?(?:project|folder|directory)\s+(?:named\s+|called\s+)?[\"']?([\w\-]+)[\"']?", t)
        if m:
            result = self.coding.create_project(m.group(1))
            print(f"  Created project: {result['path']} with files {result['files']}")
            return ("coding.project", result)

        return None

    # ---------------- slash commands ----------------
    def cmd_help(self, arg):
        print("""
  COMMANDS
  /help              Show this help
  /model             List and switch AI models
  /apikey            Change the OpenRouter API key
  /status            Show API, model, workspace, memory status
  /files [path]      List files in the workspace
  /scan [path]       Recursive directory scan with secret-file flagging
  /code <task>       Run the PLAN->CODE->TEST->FIX workflow on a task
  /debug <file.py>   Run a script, diagnose errors, attempt repairs
  /run <file.py>     Execute a Python script (permission level 3)
  /create <name>     Create a new project folder
  /projects          Show current project and history
  /memory [op]       memory show|search <q>|add <cat> <text>|edit|delete|export|clear
  /history           Show recent conversation history
  /settings          View or change settings (permission level, workspace)
  /clear             Clear the screen
  /exit              Save state and quit

  NATURAL LANGUAGE (Hindi ya English dono chalega), for example:
    "hash sha256: hello world"
    "analyze btc address: bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh"
    "audit the file myapp.py"
    "create project myapp"
    "Explain RSA signing in simple Hindi"
""")

    def cmd_model(self, arg):
        if arg:
            self.llm.set_model(arg.strip())
            print(f"  Model set to: {self.llm.model}")
            return
        print("  Fetching available models from OpenRouter...")
        models = self.llm.list_models()
        free = [m for m in models if m["free"]]
        others = [m for m in models if not m["free"]]
        print(f"  {len(models)} models available ({len(free)} free). Showing free models first:\n")
        shown = free[:15] + others[:5]
        for i, m in enumerate(shown, 1):
            ctx = f"ctx {m['context']}" if m.get("context") else "ctx ?"
            print(f"   {i:2}. {m['id']}  ({ctx}{' | FREE' if m['free'] else ''})")
        choice = input("\n  Enter model number, or exact model id, or press Enter to keep current: ").strip()
        if not choice:
            print("  Keeping current model.")
            return
        if choice.isdigit() and 1 <= int(choice) <= len(shown):
            model_id = shown[int(choice) - 1]["id"]
        else:
            model_id = choice
        self.llm.set_model(model_id)
        print(f"  Model set to: {self.llm.model}")

    def cmd_apikey(self, arg):
        import getpass
        print("  Enter your OpenRouter API key (input hidden; get one at https://openrouter.ai/keys).")
        key = getpass.getpass("  API key: ").strip()
        if not key:
            print("  No key entered. Keeping existing configuration.")
            return
        self.llm.save_key(key)
        print("  Key stored (file permissions 600). Validating with OpenRouter...")
        info = self.llm.validate_key()
        print(f"  Valid. Key label: {info['label']} | usage so far: {info['usage']}")
        if not self.llm.model:
            self.cmd_model("")

    def cmd_status(self, arg):
        key_ok = self.llm.key_exists()
        prov = self.llm.status() if hasattr(self.llm, "status") else {"active": "openrouter"}
        session = prov.get("session_usage", {})
        mem = self.memory.status()
        print(f"""
  ULTIMATE AI AGENT - STATUS
  --------------------------
  Provider       : {prov.get('active') or 'not configured'} ({'key set' if key_ok else 'NO KEY'})
  API connection : {'verified' if key_ok and self.llm.model else 'not verified'}
  Model          : {self.llm.model or 'not selected'}
  Workspace      : {self.sec.workspace}
  Permission     : LEVEL {self.sec.max_level} / 5
  Tools          : {len(self.tools.tools) if self.tools else 0} registered (see /tools)
  Memory         : {json.dumps(mem['entries'])}
  History        : {mem['history_turns']} turns
  This session   : {session.get('requests', 0)} AI requests, {session.get('prompt_tokens', 0)}+{session.get('completion_tokens', 0)} tokens, ~${session.get('cost_usd', 0):.4f}, {session.get('fallbacks', 0)} fallbacks
  Crypto library : {'cryptography installed' if self._have_crypto() else 'cryptography NOT installed (AES/RSA disabled)'}
""")

    @staticmethod
    def _have_crypto():
        try:
            import cryptography  # noqa: F401
            return True
        except ImportError:
            return False

    def cmd_files(self, arg):
        path = arg or "."
        entries = self.fm.list_dir(path)
        print(f"\n  Listing of {self.sec.validate_path(path)}:\n")
        for e in entries:
            if "note" in e:
                print(f"  {e['note']}")
                continue
            kind = "DIR " if e["type"] == "dir" else "FILE"
            size = f"{e['size']:>10} B" if e["size"] is not None else "         -"
            flag = "  [SECRET - never read]" if e["secret"] else ""
            print(f"  {kind} {size}  {e['name']}{flag}")

    def cmd_scan(self, arg):
        stats = self.fm.scan(arg or ".")
        print(f"\n  Scan of {stats['root']}")
        print(f"  Directories: {stats['dirs']} | Files: {stats['files']} | Total: {stats['total_bytes']} bytes")
        if stats.get("truncated"):
            print("  (scan truncated at 500 entries)")
        top_ext = sorted(stats["extensions"].items(), key=lambda kv: -kv[1])[:10]
        print("  Top file types: " + ", ".join(f"{k} x{n}" for k, n in top_ext))
        if stats["secret_files"]:
            print("  Potential secret files (contents never read):")
            for s in stats["secret_files"]:
                print(f"   - {s}")

    def cmd_code(self, arg):
        if not arg:
            print("  Usage: /code <what to build>, e.g. /code create a python CLI todo app")
            return
        plan = self.planner.build_plan(arg)
        report = self.planner.execute(plan)
        path = self.coding.generate_report("coding_workflow", json.dumps(report, indent=2), fmt="json")
        print(f"\n  Workflow report saved: {path}")

    def cmd_debug(self, arg):
        if not arg:
            print("  Usage: /debug <script.py> [args]")
            return
        parts = arg.split(maxsplit=1)
        script, args = parts[0], parts[1] if len(parts) > 1 else ""
        print(f"  Running {script} ...")
        outcome = self.debugger.run_and_diagnose(script, args=args)
        if outcome["ok"]:
            print("  Script ran successfully.")
            print(outcome["result"].get("stdout", ""))
            return
        diag = outcome["diagnosis"]
        print(f"\n  ERROR TYPE : {diag['error_type']}")
        print(f"  MESSAGE    : {diag['message']}")
        if diag.get("line"):
            print(f"  LOCATION   : {diag['file']}:{diag['line']}")
        print(f"  HINDI      : {diag['hindi']}")
        print(f"  ENGLISH    : {diag['english']}")
        answer = input("\n  Attempt automatic repair? [y/N]: ").strip().lower()
        if answer in ("y", "yes"):
            repair = self.debugger.auto_repair(script, outcome["result"].get("stderr", ""))
            for att in repair["attempts"]:
                print(f"  Repair step '{att['step']}': {'OK' if att.get('ok') else att.get('note', 'failed')}")
            retest = repair.get("retest", {})
            print(f"  Retest after repair: {'PASSED' if retest.get('ok') else 'STILL FAILING'}")
            if not retest.get("ok"):
                print(retest.get("stderr", "")[:1500])

    def cmd_run(self, arg):
        if not arg:
            print("  Usage: /run <script.py> [args]")
            return
        parts = arg.split(maxsplit=1)
        result = self.coding.run_python(parts[0], args=parts[1] if len(parts) > 1 else "")
        if result.get("stdout"):
            print(result["stdout"])
        if result.get("stderr"):
            print(f"  [stderr]\n{result['stderr']}")
        if not result.get("ok") and "error" in result:
            print(f"  [error] {result['error']}")

    def cmd_create(self, arg):
        if not arg:
            print("  Usage: /create <project_name>")
            return
        result = self.coding.create_project(arg.strip())
        print(f"  Project created at {result['path']}")
        print(f"  Files: {', '.join(result['files'])}")

    def cmd_projects(self, arg):
        hist = self.coding.project_history()
        proj = hist["project"]
        print(f"\n  Current project : {proj.get('name') or '(none)'}")
        print(f"  Directory       : {proj.get('directory') or '-'}")
        print(f"\n  Recent decisions ({len(hist['decisions'])}):")
        for d in hist["decisions"][-10:]:
            print(f"   - {d['text'][:100]}")
        print(f"\n  Pending tasks: {len(hist['pending_tasks'])} | Completed: {len(hist['completed_tasks'])}")

    def cmd_memory(self, arg):
        if not arg or arg == "show":
            st = self.memory.status()
            print(f"\n  Project: {st['project']}")
            for cat, n in st["entries"].items():
                print(f"  {cat}: {n}")
                for e in self.memory.list(cat)[-5:]:
                    print(f"    - {e['text'][:90]}")
            return
        parts = arg.split(maxsplit=1)
        op = parts[0].lower()
        rest = parts[1] if len(parts) > 1 else ""
        if op == "search":
            hits = self.memory.search(rest)
            if not hits:
                print("  No matches.")
            for h in hits:
                print(f"  [{h['category']}#{h['index']}] {h['text'][:100]}")
        elif op == "add":
            sub = rest.split(maxsplit=1)
            if len(sub) < 2:
                print("  Usage: /memory add <category> <text>  (categories: facts, instructions, decisions, errors, tasks_pending, tasks_completed)")
                return
            self.memory.add(sub[0], sub[1])
            print("  Saved.")
        elif op == "edit":
            sub = rest.split(maxsplit=2)
            if len(sub) < 3:
                print("  Usage: /memory edit <category> <index> <new text>")
                return
            self.memory.edit(sub[0], int(sub[1]), sub[2])
            print("  Updated.")
        elif op == "delete":
            sub = rest.split(maxsplit=1)
            if len(sub) < 2:
                print("  Usage: /memory delete <category> <index>")
                return
            removed = self.memory.delete(sub[0], int(sub[1]))
            print(f"  Deleted: {removed['text'][:80]}")
        elif op == "export":
            out = rest or str(Path.home() / "storage" / "downloads" / "memory_export.json")
            path = self.memory.export(out)
            print(f"  Exported to {path}")
        elif op == "clear":
            cat = rest or "all"
            self.sec.require_confirm(5, f"clear memory category '{cat}'")
            self.memory.clear(cat)
            print(f"  Memory '{cat}' cleared.")
        else:
            print("  Unknown memory operation. Use show|search|add|edit|delete|export|clear")

    def cmd_history(self, arg):
        msgs = self.memory.recent_history(20)
        if not msgs:
            print("  History is empty.")
            return
        for m in msgs:
            who = "YOU" if m["role"] == "user" else "AI "
            preview = m["content"][:120].replace("\n", " ")
            print(f"  {who} | {preview}")

    def cmd_settings(self, arg):
        if not arg:
            print(f"""
  SETTINGS
  workspace             : {self.sec.workspace}
  max_permission_level  : {self.sec.max_level}
  extra_allowed_paths   : {self.settings.get('extra_allowed_paths', [])}
  confirm_sensitive     : {self.settings.get('confirm_sensitive', True)}

  Changes:
  /settings level <1-5>            Set max permission level
  /settings allow_path <path>      Grant access to an extra path
  /settings confirm on|off         Require confirmation for level 4 actions
""")
            return
        parts = arg.split(maxsplit=1)
        op = parts[0].lower()
        val = parts[1] if len(parts) > 1 else ""
        if op == "level":
            level = int(val)
            if not 1 <= level <= 5:
                print("  Level must be 1-5.")
                return
            if level >= 5:
                if not self.sec.confirm("Allow DESTRUCTIVE operations (level 5)?", level=5):
                    return
            self.sec.max_level = level
            self.settings["max_permission_level"] = level
            self._save_settings()
            print(f"  Max permission level set to {level}.")
        elif op == "allow_path":
            added = self.sec.add_allowed_path(val)
            self.settings["extra_allowed_paths"] = self.sec.settings.get("extra_allowed_paths", [])
            self._save_settings()
            print(f"  Path allowed: {added} (agent will still ask before sensitive actions)")
        elif op == "confirm":
            self.settings["confirm_sensitive"] = val.lower() != "off"
            self._save_settings()
            print(f"  Sensitive-action confirmation: {self.settings['confirm_sensitive']}")
        else:
            print("  Unknown setting. Run /settings with no arguments for help.")

    def _save_settings(self):
        settings_file = Path(__file__).resolve().parent.parent / "config" / "settings.json"
        settings_file.write_text(json.dumps(self.settings, indent=2), encoding="utf-8")


    # ---------------- provider / tools / plan / task / doctor / audit ----------------
    def cmd_provider(self, arg):
        parts = arg.split(maxsplit=1)
        op = parts[0].lower() if parts else "list"
        if op == "list" or not arg:
            st = self.llm.status()
            print(f"\n  Active provider: {st['active'] or '(none)'}")
            for name, info in st["providers"].items():
                mark = " <- ACTIVE" if name == st["active"] else ""
                print(f"   - {name} [{info['kind']}] key={'yes' if info['has_key'] else 'no'} "
                      f"model={info['model'] or '-'}{mark}")
            print("\n  Known presets: " + ", ".join(PROVIDER_PRESETS.keys()))
            print("  Add: /provider add <name>   (interactive)")
            print("  Use: /provider use <name>   Test: /provider test <name>")
            return
        if op == "add":
            if not parts[1:]:
                print("  Usage: /provider add <preset-name or custom-name>")
                print(f"  Presets: {', '.join(PROVIDER_PRESETS.keys())}")
                return
            name = parts[1].strip()
            if name in self.llm.names():
                print(f"  Provider '{name}' already configured. Overwriting (old key removed).")
            preset = PROVIDER_PRESETS.get(name)
            if preset:
                kind, base_url = preset["kind"], preset["base_url"]
                print(f"  Preset '{name}': {preset['note']}")
            else:
                kind = input("  Kind (openai/gemini/ollama) [openai]: ").strip() or "openai"
                base_url = input("  Base URL (e.g. https://host/v1): ").strip()
                if not base_url:
                    print("  Cancelled: base URL required for custom providers.")
                    return
            api_key = None
            if kind != "ollama":
                import getpass
                api_key = getpass.getpass("  API key (hidden, empty to skip): ").strip()
            try:
                self.llm.add_provider(name, kind, base_url=base_url, api_key=api_key)
                self.llm.set_active(name)
                print(f"  Provider '{name}' added and activated.")
                result = self.llm.validate_key()
                print(f"  Test: {result['detail']}")
                self.cmd_model("")
            except (ValueError, LLMError) as exc:
                print(f"  [!] {exc}")
            return
        if op == "use":
            try:
                self.llm.set_active(parts[1].strip())
                print(f"  Active provider: {parts[1].strip()}")
            except (ValueError, IndexError) as exc:
                print(f"  [!] {exc or 'Usage: /provider use <name>'}")
            return
        if op == "test":
            try:
                result = self.llm.validate_key()
                print(f"  {result['detail']}")
            except LLMError as exc:
                print(f"  [!] {exc}")
            return
        if op == "remove":
            name = parts[1].strip() if parts[1:] else ""
            if name:
                self.llm.remove_provider(name)
                print(f"  Provider '{name}' removed.")
            return
        print("  Unknown provider op. Use list | add | use | test | remove")

    def cmd_tools(self, arg):
        tools = self.tools.list()
        print(f"\n  {len(tools)} tools registered:\n")
        for t in tools:
            print(f"   [{t['min_level']}] {t['name']:<16} {t['description']}")

    def cmd_plan(self, arg):
        state = self.planner.load_state()
        if not state:
            print("  No plan yet. Run /code <task> to create one.")
            return
        print(f"\n  PLAN: {state['task']} (updated {state.get('updated', '?')})")
        for i, step in enumerate(state["steps"], 1):
            print(f"   {i}. [{step.get('status', '?')}] {step.get('step', step)}")
        refl = state.get("reflection") or self.planner.load_state().get("reflection")
        if refl:
            print(f"\n  REFLECT: {refl.get('verdict')} | {refl.get('missing')} | next: {refl.get('next_action')}")

    def cmd_task(self, arg):
        parts = arg.split(maxsplit=1)
        op = parts[0].lower() if parts else "list"
        if op == "add" and parts[1:]:
            self.memory.add("tasks_pending", parts[1].strip())
            pending = self.memory.list("tasks_pending")
            print(f"  Task added (#{len(pending) - 1}). Use /task list to see all.")
        elif op == "done":
            try:
                idx = int(parts[1]) if parts[1:] else -1
                pending = self.memory.list("tasks_pending")
                if not pending:
                    print("  No pending tasks.")
                    return
                task = pending.pop(idx)
                self.memory.add("tasks_completed", task["text"])
                self.memory._save()
                print(f"  Done: {task['text'][:80]}")
            except (ValueError, IndexError) as exc:
                print(f"  [!] {exc}. Usage: /task done <index> (see /task list)")
        elif op == "list":
            pending = self.memory.list("tasks_pending")
            done = self.memory.list("tasks_completed")
            print(f"\n  Pending ({len(pending)}):")
            for i, t in enumerate(pending):
                print(f"   {i}. {t['text'][:90]}")
            print(f"  Completed ({len(done)}):")
            for t in done[-5:]:
                print(f"   + {t['text'][:90]}")
        else:
            print("  Usage: /task add <text> | /task done <index> | /task list")

    def cmd_doctor(self, arg):
        print("\n  DOCTOR - environment check\n" + "  " + "-" * 40)
        checks = []
        checks.append(("python", f"{sys.version.split()[0]} at {sys.executable or 'python'}", True))
        for mod, label in [("requests", "HTTP client"), ("cryptography", "AES/RSA/Ed25519"),
                           ("sqlite3", "SQLite"), ("json", "JSON")]:
            try:
                __import__(mod)
                checks.append((label, "installed", True))
            except ImportError:
                checks.append((label, "MISSING - pip install " + mod, False))
        ws_writable = os.access(self.sec.workspace, os.W_OK) if Path(self.sec.workspace).exists() else False
        checks.append(("workspace writable", str(self.sec.workspace), ws_writable))
        st = self.llm.status() if hasattr(self.llm, "status") else {}
        checks.append(("provider", st.get("active") or "none configured", bool(st.get("active"))))
        checks.append(("model", self.llm.model or "not selected", bool(self.llm.model)))
        try:
            import requests as _rq
            r = _rq.head("https://openrouter.ai", timeout=8)
            net = f"reachable (HTTP {r.status_code})"
            ok = True
        except Exception as exc:
            net = f"UNREACHABLE ({type(exc).__name__})"
            ok = False
        checks.append(("network", net, ok))
        if os.environ.get("PREFIX"):
            checks.append(("termux", f"PREFIX={os.environ['PREFIX']}", True))
        width = max(len(c[0]) for c in checks)
        all_ok = True
        for name, detail, ok in checks:
            all_ok &= ok
            print(f"  {name:<{width}} : {'OK ' if ok else 'FAIL'}  {detail}")
        print(f"\n  VERDICT: {'ALL CHECKS PASSED' if all_ok else 'SOME CHECKS FAILED (see above)'}")

    def cmd_audit(self, arg):
        audit_file = self.sec.log_file.parent / "audit.log"
        if not audit_file.exists():
            print("  Audit log is empty.")
            return
        try:
            n = int(arg) if arg else 20
        except ValueError:
            n = 20
        lines = audit_file.read_text().splitlines()[-n:]
        print(f"\n  Last {len(lines)} audit entries (logs/audit.log):")
        for line in lines:
            print(f"   {line}")

    def cmd_clear(self, arg):
        print("\033[2J\033[H", end="")

    def cmd_exit(self, arg):
        print("  State saved. Goodbye!")
        self.running = False
