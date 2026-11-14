#!/usr/bin/env python3
"""ULTIMATE AI AGENT - entry point. Welcome screen, first-run setup, interactive REPL."""

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from core.providers import ProviderManager, ProviderError, PROVIDER_PRESETS
from core.memory import MemoryManager
from core.security import SecurityManager
from core.agent import Agent
from core.planner import Planner
from tools.file_manager import FileManager
from tools.terminal import TerminalExecutor
from tools.registry import ToolRegistry
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
   Powered by OpenRouter and other providers
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
    """Welcome + provider/key setup + validation + model selection."""
    print("  Welcome! This agent talks to AI providers through a pluggable layer.")
    print("  Providers: " + ", ".join(PROVIDER_PRESETS.keys()) + "\n")

    if not llm.names():
        print("  No providers configured yet. Quick setup:\n")
        for i, (name, preset) in enumerate(PROVIDER_PRESETS.items(), 1):
            print(f"   {i:2}. {name:<10} - {preset['note']}")
        choice = input("\n  Pick a provider number (or Enter for openrouter): ").strip()
        names = list(PROVIDER_PRESETS.keys())
        name = names[int(choice) - 1] if choice.isdigit() and 0 < int(choice) <= len(names) \
            else (choice if choice in PROVIDER_PRESETS else "openrouter")
        preset = PROVIDER_PRESETS[name]
        api_key = None
        if preset["kind"] != "ollama":
            import getpass
            api_key = getpass.getpass(f"  Enter API key for '{name}' (hidden): ").strip()
        try:
            llm.add_provider(name, preset["kind"], base_url=preset["base_url"], api_key=api_key)
            llm.set_active(name)
        except (ValueError, ProviderError) as exc:
            print(f"  [!] {exc}\n  Starting in OFFLINE mode. Use /provider add later.")
            return
    elif not llm.key_exists():
        import getpass
        active = llm.active_name()
        key = getpass.getpass(f"  Enter API key for provider '{active}' (hidden): ").strip()
        if key:
            llm.save_key(key)
        else:
            print("  No key entered. Starting in OFFLINE mode (tools work, AI chat disabled).")
            return

    print("  Validating connection...")
    try:
        info = llm.validate_key()
        print(f"  Connected! {info['detail']}")
    except ProviderError as exc:
        print(f"  [!] {exc}")
        print("      Starting anyway - use /provider test or /apikey to fix. Tools still work offline.")
        return

    saved_model = llm.load_saved_model()
    if saved_model:
        print(f"  Model: {saved_model} (change anytime with /model)")
        return
    print("\n  Now select a model. Fetching the list...")
    try:
        models = llm.list_models()
        if not models:
            print("  [!] No models returned. Set one manually with /model <model-id>")
            return
        free = [m for m in models if m.get("free")]
        pool = free or models
        print(f"  {len(models)} models available ({len(free)} free). Top options:")
        for i, m in enumerate(pool[:10], 1):
            ctx = f"ctx {m['context']}" if m.get("context") else ""
            print(f"   {i:2}. {m['id']}  {ctx}")
        choice = input("\n  Pick a number (or Enter for the first one): ").strip()
        idx = int(choice) - 1 if choice.isdigit() and 0 < int(choice) <= min(10, len(pool)) else 0
        llm.set_model(pool[idx]["id"])
        print(f"  Model selected: {llm.model}")
    except ProviderError as exc:
        print(f"  [!] Could not fetch models: {exc}")
        print("      Set one later with /model <model-id>")


def build_agent():
    ensure_dirs()
    settings = load_settings()
    workspace = resolve_workspace(settings)

    sec = SecurityManager(workspace, settings, log_file=PROJECT_ROOT / "logs" / "security.log")
    llm = ProviderManager(PROJECT_ROOT / "config", log_fn=sec.log)
    memory = MemoryManager(PROJECT_ROOT / "data", redact_fn=sec.redact)
    fm = FileManager(sec, backup_dir=PROJECT_ROOT / "backups")
    term = TerminalExecutor(sec, workdir=workspace)
    coding = CodingEngine(fm, sec, term, memory)
    debugger = Debugger(coding, term, sec, llm=llm)
    crypto = CryptoToolkit(sec)
    blockchain = BlockchainToolkit(sec, file_manager=fm)
    sec_analyzer = SecurityAnalyzer(sec, fm, term)
    planner = Planner(None)
    registry = ToolRegistry(sec, fm, term, crypto)
    agent = Agent(llm, memory, sec, fm, term, coding, debugger, crypto,
                  blockchain, sec_analyzer, planner, settings, tools=registry)
    planner.agent = agent
    return agent


def main():
    agent = build_agent()
    try:
        first_run_setup(agent.llm)
    except (EOFError, KeyboardInterrupt):
        print("\n  Setup interrupted. Starting in OFFLINE mode. Use /provider add later.")

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
            except ProviderError as exc:
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
