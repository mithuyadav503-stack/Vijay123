#!/usr/bin/env python3
"""ULTIMATE AI AGENT - entry point. Welcome screen, first-run setup, interactive REPL."""

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from core.llm import OpenRouterClient, LLMError
from core.memory import MemoryManager
from core.security import SecurityManager
from core.agent import Agent
from core.planner import Planner
from tools.file_manager import FileManager
from tools.terminal import TerminalExecutor
from tools.coding import CodingEngine
from tools.debugger import Debugger
from tools.crypto import CryptoToolkit
from tools.blockchain import BlockchainToolkit
from tools.security_audit import SecurityAnalyzer

BANNER = """
  ==========================================================
     _   _ _   _ __  __    _    _   _ _   _ _____ _____
    | | | | | | |  \\/  |  / \\  | \\ | | \\ | |_   _| ____|
    | | | | | | | |\\/| | / _ \\ |  \\| |  \\| | | | |  _|
    | |_| | |_| | |  | |/ ___ \\| |\\  | |\\  | | | | |___
     \\___/ \\___/|_|  |_/_/   \\_\\_| \\_|_| \\_| |_| |_____|
  ==========================================================
   ULTIMATE AI AGENT
   Powered by OpenRouter
   Running on Termux
  ==========================================================
"""

DEFAULT_SETTINGS = {
    "workspace": "~/storage/downloads",
    "max_permission_level": 3,
    "confirm_sensitive": True,
    "extra_allowed_paths": [],
}


def load_settings():
    settings_file = PROJECT_ROOT / "config" / "settings.json"
    if settings_file.exists():
        try:
            data = json.loads(settings_file.read_text())
            merged = dict(DEFAULT_SETTINGS)
            merged.update(data)
            return merged
        except Exception:
            pass
    return dict(DEFAULT_SETTINGS)


def ensure_dirs():
    for d in ("config", "data", "logs", "backups", "reports"):
        (PROJECT_ROOT / d).mkdir(parents=True, exist_ok=True)


def resolve_workspace(settings):
    ws = Path(settings["workspace"]).expanduser()
    if not ws.exists():
        fallback = PROJECT_ROOT / "workspace"
        print(f"  [!] Workspace '{ws}' does not exist (storage permission not granted?).")
        print(f"      Falling back to: {fallback}")
        print("      Run 'termux-setup-storage' in Termux, then restart, to use Downloads.")
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback
    return ws


def first_run_setup(llm):
    """Welcome + API key setup + validation + model selection."""
    print(BANNER)
    try:
        return _first_run_setup(llm)
    except (EOFError, KeyboardInterrupt):
        print("\n  Setup interrupted. Starting in OFFLINE mode. Use /apikey later to connect.")


def _first_run_setup(llm):
    if not llm.key_exists():
        print("  Welcome! This agent uses the OpenRouter API as its AI provider.")
        print("  You need a free API key from https://openrouter.ai/keys\n")
        while True:
            import getpass
            key = getpass.getpass("  Enter your OpenRouter API key (hidden): ").strip()
            if not key:
                print("  No key entered. The agent will start in OFFLINE mode (tools work, AI chat disabled).")
                return
            llm.save_key(key)
            print("  Key saved securely (file permission 600). Validating...")
            try:
                info = llm.validate_key()
                print(f"  Connected! Key label: {info['label']} | usage so far: {info['usage']}")
                break
            except LLMError as exc:
                print(f"  [!] {exc}")
                llm.clear_key()
                retry = input("  Try another key? [Y/n]: ").strip().lower()
                if retry in ("n", "no"):
                    print("  Starting in OFFLINE mode. Use /apikey later to connect.")
                    return
    else:
        try:
            info = llm.validate_key()
            print(f"  OpenRouter connected (key: {info['label']})")
        except LLMError as exc:
            print(f"  [!] Saved API key problem: {exc}")
            print("      Starting anyway - use /apikey to fix. Tools still work offline.")
            return

    saved_model = llm.load_saved_model()
    if saved_model:
        llm.model = saved_model
        print(f"  Model: {saved_model} (change anytime with /model)")
    else:
        print("\n  Now select a model. Fetching the list from OpenRouter...")
        try:
            models = llm.list_models()
            free = [m for m in models if m["free"]]
            if free:
                print(f"  {len(free)} free models available. Top options:")
                for i, m in enumerate(free[:10], 1):
                    print(f"   {i:2}. {m['id']}")
                choice = input("\n  Pick a number (or Enter for the first one): ").strip()
                idx = int(choice) - 1 if choice.isdigit() and 0 < int(choice) <= min(10, len(free)) else 0
                llm.set_model(free[idx]["id"])
            else:
                llm.set_model(models[0]["id"])
            print(f"  Model selected: {llm.model}")
        except LLMError as exc:
            print(f"  [!] Could not fetch models: {exc}")
            print("      Set one later with /model (e.g. openai/gpt-4o-mini or meta-llama/llama-3.1-8b-instruct:free)")


def build_agent():
    ensure_dirs()
    settings = load_settings()
    workspace = resolve_workspace(settings)

    sec = SecurityManager(workspace, settings, log_file=PROJECT_ROOT / "logs" / "security.log")
    llm = OpenRouterClient(PROJECT_ROOT / "config", log_fn=lambda *_: None)
    memory = MemoryManager(PROJECT_ROOT / "data", redact_fn=sec.redact)
    fm = FileManager(sec, backup_dir=PROJECT_ROOT / "backups")
    term = TerminalExecutor(sec, workdir=workspace)
    coding = CodingEngine(fm, sec, term, memory)
    debugger = Debugger(coding, term, sec, llm=llm)
    crypto = CryptoToolkit(sec)
    blockchain = BlockchainToolkit(sec, file_manager=fm)
    sec_analyzer = SecurityAnalyzer(sec, fm, term)
    planner = Planner(None)
    agent = Agent(llm, memory, sec, fm, term, coding, debugger, crypto,
                  blockchain, sec_analyzer, planner, settings)
    planner.agent = agent
    return agent


def main():
    agent = build_agent()
    first_run_setup(agent.llm)

    print(BANNER)
    agent.cmd_status("")
    print("  Type /help for commands, or just talk to the agent (Hindi/English). /exit to quit.\n")

    while agent.running:
        try:
            line = input("agent> ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n  State saved. Goodbye!")
            break
        if not line:
            continue
        if line.startswith("/"):
            agent.handle_command(line)
        else:
            try:
                agent.chat(line)
            except LLMError as exc:
                print(f"\n  [AI ERROR - {exc.kind}] {exc}")
                if exc.kind == "network":
                    print("  Tip: check your internet connection, then try again.")
            except PermissionDenied as exc:
                print(f"\n  [PERMISSION] {exc}")
            except KeyboardInterrupt:
                print("\n  (cancelled)")
        print()


if __name__ == "__main__":
    main()
