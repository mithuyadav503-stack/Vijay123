# CHANGELOG

## v2.0.0 — Operator upgrade

### Fixed
- **Self-test is now fully transactional**: every test runs create → assert → rename → cleanup
  inside try/finally. A failure can no longer leave half-built state or crash the run
  (fixes the `FileNotFoundError .../proj/renamed_copy.py` crash).
- **Banner prints exactly once** (was printed in both setup and the main loop).
- **Key validation now uses an auth-required endpoint** — OpenRouter keys are verified
  against `/auth/key`, not the public `/models` route (an empty key previously showed
  "connected").
- **`/status` rewritten**: shows provider, key state, model, workspace, permission level,
  registered tool count, memory counters, per-session token/cost/fallback accounting.
- **Dead `cryptography` checks removed** from the security analyzer's AST walk; the
  library is now genuinely used by the crypto toolkit and verified by `/doctor`.
- **Model repetition across turns fixed**: per-turn context trimming (per-message cap +
  total char budget) keeps history compact.
- `run_python`/`run_tests` now use the running interpreter (`sys.executable`) instead of
  a hardcoded `python` binary.
- Misleading "Command not found" error when the working directory was missing is now
  reported accurately.

### Added
- **Provider layer** (`core/providers.py`): `Provider` base class with `list_models()`,
  `chat(messages, tools, stream)`, `usage()`. Adapters for OpenRouter, OpenAI, Groq,
  Together, Mistral, Gemini (native API), generic OpenAI-compatible (custom base_url),
  and local Ollama / llama.cpp server. `config/providers.json` (chmod 600), interactive
  `/provider add|use|test|list|remove`, numbered model picker, hot-swap `/model`,
  automatic fallback chain on 429/5xx/timeout with exponential backoff, SSE streaming,
  token + cost accounting per turn. No model or provider name is hardcoded anywhere.
- **Tool registry** (`tools/registry.py`): 18 built-in tools with JSON schemas, required-arg
  validation, timeouts, structured results, and permission-level enforcement:
  read_file, write_file, append_file, list_dir, glob, grep, file_stat, hash, hexdump,
  base64_encode/decode, run_shell, python_eval, edit_file, diff, download, extract_archive,
  sqlite_query.
- **Audit log** (`logs/audit.log`): every shell command, file write, and python_eval with
  timestamp + exit code. View with `/audit`.
- **Planning loop** (`core/planner.py`): PLAN → ACT → OBSERVE → REFLECT with persistent
  plan state (`data/plan.json`), `/plan` to inspect, self-critique verdict after each run.
- **Task tracking**: `/task add|done|list` mapped to persistent memory.
- **`/doctor`**: verifies Python, dependencies, workspace writability, provider, model,
  network reachability, Termux PREFIX.
- **Defensive wallet format detection** (`BlockchainToolkit.detect_wallet_format`):
  identifies Bitcoin Core (Berkeley DB), Electrum, Blockchain.com, MetaMask/Trust keystore,
  MultiBit, Armory files; reports encryption status, weak KDF parameters, and file
  permission problems. Local-only; never decrypts or extracts anything.
- **ECDSA lab** (`tools/ecdsa_lab.py`): pure-Python secp256k1 with keygen, ECDSA sign/verify,
  RFC 6979 deterministic nonces, and the nonce-reuse private-key recovery demonstration on
  self-generated toy keys — showing exactly why repeated nonces destroy keys.

### Test results
105 offline checks passing (no API key or network needed), including a mock
OpenRouter-compatible server exercising key validation, model listing, chat, retry, and
the full fallback chain.
