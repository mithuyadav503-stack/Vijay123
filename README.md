# ULTIMATE AI AGENT

A fully functional, modular, tool-using AI coding and cybersecurity assistant that runs
inside **Android Termux**, powered by the **OpenRouter API**.

> Hindi aur English dono me baat kar sakte hain. Errors simple Hindi me samjhayi jaati hain.

---

## Features

- **Multi-provider AI brain** — pluggable providers: OpenRouter, OpenAI, Groq, Together,
  Mistral, Gemini (native), any OpenAI-compatible server, and local Ollama/llama.cpp.
  Automatic fallback chain (429/5xx/timeout → next provider, exponential backoff),
  SSE streaming, token + cost accounting. Keys validated against auth-required endpoints.
- **Tool registry** — 18 schema'd tools (files, grep, shell, python_eval, sqlite, diff,
  hexdump, download...) with timeouts, structured results, and permission enforcement.
- **Planning loop** — PLAN → ACT → OBSERVE → REFLECT with persistent plan state (`/plan`)
  and long-horizon task tracking (`/task add|done|list`).
- **Audit log** — every shell command and file write with timestamp + exit code (`/audit`).
- **`/doctor`** — one-shot environment verification (deps, network, workspace, provider).
- **ECDSA lab** — educational secp256k1: sign/verify, RFC 6979, nonce-reuse key recovery
  demonstrated on self-generated toy keys.
- **Defensive wallet audit** — detects Bitcoin Core/Electrum/Blockchain.com/MetaMask/
  MultiBit/Armory wallet files, reports encryption status and weak KDF parameters.
  Local-only; never extracts or transmits key material.
- **AI conversation** — secure API-key entry (hidden input), real validation,
  model browsing/switching, Hindi/English chat, expert-level help
  across Python, JS/TS, C/C++, Java, Rust, Go, Bash, Linux/Termux, databases, APIs, web,
  automation, cryptography, blockchain/Bitcoin, and defensive security.
- **Autonomous coding engine** — `PLAN → WRITE CODE → REVIEW → EXECUTE → TEST → DEBUG → FIX → VERIFY`
  workflow (`/code`), project scaffolding, backups before every modification, README and
  JSON/Markdown report generation.
- **File manager** — list/read/search/create/rename/copy/move/delete/extract, recursive
  scanning, secret-file protection (`.env`, `id_rsa`, `*.pem`, wallets are never read or logged).
- **Terminal executor** — validated shell commands with a dangerous-command blocklist
  (`rm -rf /`, `mkfs`, fork bombs, pipe-to-shell, privilege escalation, etc.), timeouts,
  and redacted logging.
- **Debugger** — parses tracebacks, classifies ~18 error types, explains in simple Hindi,
  offers safe repairs (dependency install at level 4 with confirmation, LLM patch with preview
  and confirmation), then retests.
- **Cryptography toolkit** — SHA-256/512, SHA-3, BLAKE2, HMAC, AES-256-GCM (PBKDF2),
  RSA-PSS, Ed25519 — all local. Private keys are never sent to the AI or logged.
- **Blockchain toolkit** — Bitcoin address format analysis (base58check + bech32/BIP-173
  checksums, P2PKH/P2SH/P2WPKH/P2TR), raw transaction parsing (version/inputs/outputs/
  witnesses/locktime), local wallet-file security audit.
- **Security analyzer** — AST-based static analysis (eval/exec, pickle, shell=True,
  hardcoded secrets, weak hashes, SQL injection, TLS verification disabled, insecure
  randomness, world-writable chmod...), dependency CVE checks via `pip-audit`,
  OWASP Top-10 review.
- **Persistent memory** — facts, instructions, decisions, errors, pending/completed tasks,
  conversation history; inspect/search/edit/export/clear commands.
- **Permission system** — 5 levels, from read-only to destructive ops requiring explicit
  confirmation. Workspace is restricted to `~/storage/downloads` by default.

## Installation (Termux)

```bash
pkg update -y && pkg install -y python git
termux-setup-storage          # allow the permission dialog
git clone <THIS_REPO> ~/storage/downloads/ULTIMATE_AI_AGENT
cd ~/storage/downloads/ULTIMATE_AI_AGENT
bash setup.sh
```

`setup.sh` installs dependencies (`requests`, `cryptography`), verifies that every module
compiles, and runs the offline self-test suite (80 checks, no API key needed).

## Running

```bash
cd ~/storage/downloads/ULTIMATE_AI_AGENT
bash run.sh
```

First start: enter your OpenRouter API key (get one at https://openrouter.ai/keys — free
keys available). The key is validated with a real request, stored obfuscated in
`config/credentials.json` with `600` permissions, and never printed or logged.

## Commands

| Command | Description |
|---|---|
| `/help` | Command list |
| `/model` | Browse and switch OpenRouter models |
| `/apikey` | Change the API key |
| `/status` | API/model/workspace/memory status |
| `/files [path]` | List workspace files |
| `/scan [path]` | Recursive scan with secret-file flagging |
| `/code <task>` | Autonomous coding workflow |
| `/debug <file.py>` | Run, diagnose (Hindi), repair, retest |
| `/run <file.py>` | Execute a Python script (level 3) |
| `/create <name>` | Create a project folder |
| `/projects` | Current project + history |
| `/memory` | `show` `search` `add` `edit` `delete` `export` `clear` |
| `/history` | Recent conversation |
| `/settings` | Permission level, allowed paths, workspace |
| `/clear` | Clear screen |
| `/exit` | Save and quit |

Natural language also triggers tools, e.g. `hash sha256: hello`,
`analyze btc address: bc1q...`, `audit the file app.py`, `create project myapp`.

## Permission levels

| Level | Capability |
|---|---|
| 1 | Read-only operations |
| 2 | Create/edit files in the workspace |
| 3 | Execute scripts and validated commands |
| 4 | Install packages, change configuration (confirmed) |
| 5 | Destructive operations (explicit confirmation required) |

## Project structure

```
ULTIMATE_AI_AGENT/
├── main.py              Entry point, welcome screen, REPL
├── setup.sh             Termux setup (deps, syntax check, self-tests)
├── run.sh               Launcher
├── requirements.txt
├── README.md
├── config/
│   ├── settings.json    Workspace, permission level
│   └── credentials.json API key (obfuscated, chmod 600)
├── core/
│   ├── agent.py         Command routing, intent detection, LLM context
│   ├── providers.py     Multi-provider layer (OpenRouter/OpenAI/Gemini/Ollama + fallback)
│   ├── memory.py        Persistent memory + history
│   ├── planner.py       PLAN→VERIFY workflow engine
│   └── security.py      Permission levels, path sandbox, command blocklist, redaction
├── tools/
│   ├── file_manager.py  Sandboxed file operations
│   ├── terminal.py      Validated shell execution
│   ├── coding.py        Projects, editing, running, reports
│   ├── debugger.py      Traceback diagnosis (Hindi) + auto-repair
│   ├── crypto.py        Hashes, HMAC, AES, RSA, Ed25519
│   ├── blockchain.py    BTC address/tx analysis, defensive wallet format audit
│   ├── ecdsa_lab.py     Educational secp256k1 (RFC6979, nonce-reuse demo)
│   ├── registry.py      Tool registry (schemas, dispatch, timeouts)
│   └── security_audit.py Static analysis, pip-audit, OWASP review
├── tests/selftest.py    80 offline self-tests (incl. mock OpenRouter server)
├── data/                memory.json, history.jsonl
├── logs/                security.log (secrets redacted)
├── backups/             Automatic file backups
└── reports/             Generated JSON/Markdown reports
```

## Security model

- API key: entered hidden, validated, stored obfuscated with `600` permissions, never
  logged or included in any LLM request body.
- Private keys / seed phrases: never transmitted anywhere; generation output is shown once
  with a warning; secret-like files are never read during scans or greps.
- All logs and LLM-visible content pass through a redaction layer (API keys, hex blobs,
  seed phrases, `password=...` patterns).
- Dangerous shell commands are blocked by pattern; non-whitelisted commands require
  interactive confirmation; deletions require level 5 + confirmation.
- This tool is for **authorized, defensive, and educational** use only. It refuses to
  implement unauthorized access, credential theft, ransomware, or stealth malware.

## Tests

```bash
python tests/selftest.py
```

Covers security rules, memory, file operations, backups, terminal validation, coding
engine, debugger classification, crypto known-answer vectors (SHA-256, HMAC), AES/RSA/
Ed25519 roundtrips, Bitcoin base58check/bech32 known vectors, raw-tx parsing, static
analysis detection, planner, and the OpenRouter client against a local mock server.
