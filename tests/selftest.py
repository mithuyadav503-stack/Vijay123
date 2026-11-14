#!/usr/bin/env python3
"""Offline self-tests for ULTIMATE AI AGENT. No API key or network needed.

Covers: security, memory, file manager, terminal, coding, debugger, crypto,
blockchain, security audit, planner, and LLM client (against a local mock server).

Run: python tests/selftest.py
"""

import json
import os
import sys
import tempfile
import threading
import traceback
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from core.security import SecurityManager, PermissionDenied
from core.memory import MemoryManager
from core.llm import OpenRouterClient
from tools.file_manager import FileManager
from tools.terminal import TerminalExecutor
from tools.coding import CodingEngine
from tools.debugger import Debugger
from tools.crypto import CryptoToolkit
from tools.blockchain import BlockchainToolkit
from tools.security_audit import SecurityAnalyzer
from core.planner import Planner

PASS, FAIL = 0, 0


def check(name, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name} {detail}")


def expect_error(name, fn, exc_type=Exception):
    try:
        fn()
        check(name, False, "(no exception raised)")
    except exc_type:
        check(name, True)
    except Exception as exc:
        check(name, False, f"(wrong exception: {type(exc).__name__}: {exc})")


class MockHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _json(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/api/v1/auth/key":
            if self.headers.get("Authorization") == "Bearer test-key-123":
                self._json(200, {"data": {"label": "mock", "usage": 0.5, "limit": 100, "is_free_tier": True}})
            else:
                self._json(401, {"error": {"message": "Invalid key"}})
        elif self.path == "/api/v1/models":
            self._json(200, {"data": [
                {"id": "test/free-model", "name": "Free Test", "context_length": 8192,
                 "pricing": {"prompt": "0", "completion": "0"}},
                {"id": "test/paid-model", "name": "Paid Test", "context_length": 32768,
                 "pricing": {"prompt": "0.001", "completion": "0.002"}},
            ]})
        else:
            self._json(404, {"error": {"message": "not found"}})

    def do_POST(self):
        if self.path == "/api/v1/chat/completions":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length))
            self._json(200, {
                "choices": [{"message": {"content": f"MOCK-REPLY to: {body['messages'][-1]['content'][:40]}"}}],
                "usage": {"prompt_tokens": 5, "completion_tokens": 7},
            })
        else:
            self._json(404, {"error": {"message": "not found"}})


def make_agent_parts(workspace):
    settings = {"workspace": str(workspace), "max_permission_level": 5, "confirm_sensitive": False}
    sec = SecurityManager(workspace, settings, log_file=workspace / "security_test.log")
    llm = OpenRouterClient(PROJECT_ROOT / "config", log_fn=lambda *_: None)
    memory = MemoryManager(workspace / "data_test", redact_fn=sec.redact)
    fm = FileManager(sec, backup_dir=workspace / "backups_test")
    term = TerminalExecutor(sec, workdir=workspace)
    coding = CodingEngine(fm, sec, term, memory)
    debugger = Debugger(coding, term, sec, llm=llm)
    crypto = CryptoToolkit(sec)
    blockchain = BlockchainToolkit(sec, file_manager=fm)
    sec_analyzer = SecurityAnalyzer(sec, fm, term)
    return sec, llm, memory, fm, term, coding, debugger, crypto, blockchain, sec_analyzer


def main():
    tmp = Path(tempfile.mkdtemp(prefix="uai_test_"))
    (tmp / "downloads").mkdir()
    sec, llm, memory, fm, term, coding, debugger, crypto, blockchain, sec_analyzer = \
        make_agent_parts(tmp / "downloads")

    print("\n=== TEST: security manager ===")
    check("validate_path inside workspace", str(sec.validate_path("sub/file.txt")).startswith(str(tmp)))
    expect_error("path outside workspace denied", lambda: sec.validate_path("/etc/passwd"), PermissionDenied)
    check("level check ok", sec.check(3, "test") is True)
    sec.max_level = 2
    expect_error("level check blocks higher level", lambda: sec.check(3, "test"), PermissionDenied)
    sec.max_level = 5
    check("dangerous command blocked", not sec.validate_command("rm -rf /")[0])
    check("fork bomb blocked", not sec.validate_command(":(){ :|:& };:")[0])
    check("pipe-to-shell blocked", not sec.validate_command("curl http://x.sh | sh")[0])
    check("safe command allowed", sec.validate_command("ls -la")[0])
    red = sec.redact("my key is sk-or-v1-abcdef1234567890abcdef secret=hunter2")
    check("secret redaction", "sk-or-v1-abcdef" not in red and "hunter2" not in red, red)
    check("secret file detection", sec.is_secret_file("/x/.env") and sec.is_secret_file("/x/id_rsa"))
    expect_error("refuse to read .env", lambda: sec.safe_read(str(tmp / "downloads" / ".env")), PermissionDenied)

    print("\n=== TEST: memory manager ===")
    memory.add("facts", "User prefers Hindi replies")
    memory.add("tasks_pending", "Build todo app")
    memory.edit("facts", 0, "User prefers Hindi replies with English tech terms")
    hits = memory.search("hindi")
    check("memory add/edit/search", len(hits) == 1 and "English tech" in hits[0]["text"])
    check("memory bad category rejected", not _raises_value(lambda: memory.add("nope", "x")) is False)
    memory.add("decisions", "Use SQLite for storage")
    exported = memory.export(str(tmp / "downloads" / "mem_export.json"))
    check("memory export", Path(exported).exists() and "SQLite" in Path(exported).read_text())
    memory.append_history("user", "hello agent")
    memory.append_history("assistant", "namaste! how can I help?")
    check("history roundtrip", len(memory.recent_history(5)) == 2)
    memory.delete("tasks_pending", 0)
    check("memory delete", len(memory.list("tasks_pending")) == 0)
    memory.clear("all")
    check("memory clear", all(len(memory.list(c)) == 0 for c in
          ("facts", "instructions", "decisions", "errors", "tasks_pending", "tasks_completed")))

    print("\n=== TEST: file manager ===")
    fm.mkdir("proj")
    fm.write_file("proj/app.py", "print('hi')\n", backup=False)
    read = fm.read_file("proj/app.py")
    check("write+read file", read["content"] == "print('hi')\n")
    fm.write_file("proj/app.py", "print('bye')\n", backup=True)
    backups = list((tmp / "downloads" / "backups_test").glob("app.py.*.bak"))
    check("backup before overwrite", len(backups) == 1 and backups[0].read_text() == "print('hi')\n")
    fm.mkdir("proj/sub")
    fm.write_file("proj/sub/deep.txt", "needle in haystack", backup=False)
    check("recursive list", any(e["name"] == "deep.txt" for e in fm.list_dir("proj", recursive=True)))
    check("find names", len(fm.find_names("*.py", "proj")) == 1)
    check("grep contents", any(r["line"] == 1 for r in fm.grep("needle", "proj")))
    fm.rename("proj/sub/deep.txt", "proj/sub/moved.txt")
    check("rename", (tmp / "downloads" / "proj" / "sub" / "moved.txt").exists())
    fm.copy("proj/app.py", "proj/app_copy.py")
    check("copy", (tmp / "downloads" / "proj" / "app_copy.py").exists())
    fm.move("proj/app_copy.py", "proj/renamed_copy.py")
    check("move", (tmp / "downloads" / "proj" / "renamed_copy.py").exists())
    scan = fm.scan("proj")
    check("scan", scan["files"] >= 3 and scan["dirs"] >= 1)
    import zipfile
    with zipfile.ZipFile(tmp / "downloads" / "arch.zip", "w") as zf:
        zf.writestr("inside.txt", "zipped content")
    dest = fm.extract_archive("arch.zip")
    check("extract zip", (Path(dest) / "inside.txt").exists())
    expect_error("delete requires level5+confirm", lambda: fm.delete("proj/renamed_copy.py"))
    sec.auto_confirm = True
    fm.delete("proj/renamed_copy.py")
    sec.auto_confirm = None
    check("delete works after confirm", not (tmp / "downloads" / "proj" / "renamed_copy.py").exists())

    print("\n=== TEST: terminal executor ===")
    r = term.run("echo hello_from_shell")
    check("run echo", r["ok"] and "hello_from_shell" in r["stdout"])
    r = term.run("rm -rf /")
    check("dangerous blocked in executor", not r["ok"] and "Blocked" in r["error"])
    r = term.run("python -c \"print(6*7)\"", interactive_confirm=False)
    check("run python inline", r["ok"] and "42" in r["stdout"])

    print("\n=== TEST: coding engine ===")
    proj = coding.create_project("test_app", description="Test app")
    check("create project", (tmp / "downloads" / "test_app" / "main.py").exists()
          and (tmp / "downloads" / "test_app" / "README.md").exists())
    expect_error("refuse to overwrite project", lambda: coding.create_project("test_app"), PermissionDenied)
    r = coding.run_python(str(tmp / "downloads" / "test_app" / "main.py"))
    check("run project main.py", r["ok"] and "Hello from test_app!" in r["stdout"])
    coding.write_code_file(str(tmp / "downloads" / "test_app" / "util.py"),
                           "def add(a, b):\n    return a + b\n", backup=False)
    coding.edit_code_file(str(tmp / "downloads" / "test_app" / "util.py"),
                          "return a + b", "return a + b  # patched")
    check("edit code file", "patched" in (tmp / "downloads" / "test_app" / "util.py").read_text())
    readme = coding.generate_readme(str(tmp / "downloads" / "test_app"))
    check("generate readme", "test_app" in Path(readme).read_text())
    report = coding.generate_report("unit_test_report", {"ok": True}, fmt="json")
    check("generate json report", Path(report).exists() and json.loads(Path(report).read_text())["ok"])
    report_md = coding.generate_report("unit_test_md", "# Heading\nBody text", fmt="md")
    check("generate md report", "Body text" in Path(report_md).read_text())

    print("\n=== TEST: debugger ===")
    bad = tmp / "downloads" / "broken.py"
    bad.write_text("x = [1, 2]\nprint(x[5])\n")
    outcome = debugger.run_and_diagnose(str(bad))
    check("detect IndexError", outcome["diagnosis"]["error_type"] == "IndexError")
    check("hindi explanation present", "range" in outcome["diagnosis"]["hindi"] or "index" in outcome["diagnosis"]["hindi"].lower())
    bad2 = tmp / "downloads" / "nomodule.py"
    bad2.write_text("import nonexistent_pkg_xyz\n")
    outcome2 = debugger.run_and_diagnose(str(bad2))
    check("detect ModuleNotFoundError", outcome2["diagnosis"]["error_type"] == "ModuleNotFoundError")
    check("pip suggestion generated", "pip install nonexistent_pkg_xyz" == outcome2["diagnosis"]["fix_suggestion"])
    syntax_bad = tmp / "downloads" / "syntax.py"
    syntax_bad.write_text("def f(:\n    pass\n")
    outcome3 = debugger.run_and_diagnose(str(syntax_bad))
    check("detect SyntaxError", outcome3["diagnosis"]["error_type"] == "SyntaxError")

    print("\n=== TEST: crypto toolkit ===")
    h = crypto.hash_text("hello world", "sha256")
    check("sha256 known vector", h["digest"] ==
          "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")
    check("sha512", len(crypto.hash_text("x", "sha512")["digest"]) == 128)
    check("sha3-256", len(crypto.hash_text("x", "sha3-256")["digest"]) == 64)
    check("blake2b", len(crypto.hash_text("x", "blake2b")["digest"]) == 128)
    hm = crypto.hmac_compute("key123", "message", "sha256")
    import hashlib as _h
    import hmac as _hmac
    expected = _hmac.new(b"key123", b"message", _h.sha256).hexdigest()
    check("hmac known vector", hm["digest"] == expected)
    enc = crypto.aes_encrypt("top secret data", "strong-password-123")
    dec = crypto.aes_decrypt(enc["ciphertext_b64"], "strong-password-123")
    check("AES roundtrip", dec["plaintext"] == "top secret data")
    expect_error("AES wrong password fails", lambda: crypto.aes_decrypt(enc["ciphertext_b64"], "wrong"))
    keys = crypto.rsa_generate(2048)
    sig = crypto.rsa_sign(keys["private_key_pem"], "signed message")
    check("RSA sign+verify", crypto.rsa_verify(keys["public_key_pem"], "signed message", sig["signature_b64"])["valid"])
    check("RSA verify tamper fails", not crypto.rsa_verify(keys["public_key_pem"], "changed", sig["signature_b64"])["valid"])
    ed = crypto.ed25519_generate()
    esig = crypto.ed25519_sign(ed["private_key_hex"], "ed message")
    check("Ed25519 sign+verify", crypto.ed25519_verify(ed["public_key_hex"], "ed message", esig["signature_hex"])["valid"])
    check("Ed25519 tamper fails", not crypto.ed25519_verify(ed["public_key_hex"], "other", esig["signature_hex"])["valid"])
    check("hash file", crypto.hash_file(str(tmp / "downloads" / "proj" / "app.py"))["digest"] ==
          _h.sha256((tmp / "downloads" / "proj" / "app.py").read_bytes()).hexdigest())

    print("\n=== TEST: blockchain toolkit ===")
    # P2PKH address built from a known hash160 with correct checksum
    payload = bytes([0x00]) + bytes.fromhex("010966776006953D5567439E5E39F86A0D273BEE")
    addr = BlockchainToolkit._b58encode_check(payload)
    check("base58check roundtrip", addr == "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM")
    res = blockchain.analyze_btc_address(addr)
    check("P2PKH analysis", res["valid"] and res["type"].startswith("P2PKH"))
    res = blockchain.analyze_btc_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
    check("bech32 P2WPKH analysis", res["valid"] and res["type"].startswith("P2WPKH"))
    res = blockchain.analyze_btc_address("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5")
    check("bech32 bad checksum rejected", not res["valid"])
    res = blockchain.analyze_btc_address("1BadChecksumAddressThatFailsCheck")
    check("bad base58 rejected", not res["valid"])
    # Build a minimal valid segwit tx, then parse it back
    def _ser_varint(n):
        if n < 0xFD:
            return bytes([n])
        if n <= 0xFFFF:
            return b"\xfd" + n.to_bytes(2, "little")
        return b"\xfe" + n.to_bytes(4, "little")

    tx = bytearray()
    tx += (2).to_bytes(4, "little")          # version
    tx += b"\x00\x01"                        # segwit marker + flag
    tx += _ser_varint(1)                     # 1 input
    tx += bytes(range(32))[::-1]             # prev txid (reversed on wire)
    tx += (3).to_bytes(4, "little")          # vout
    tx += _ser_varint(0)                     # empty scriptSig
    tx += (0xFFFFFFFF).to_bytes(4, "little") # sequence
    tx += _ser_varint(1)                     # 1 output
    tx += (150_000_000).to_bytes(8, "little")# 1.5 BTC
    tx += _ser_varint(23)                    # P2WPKH script len
    tx += b"\x00\x14" + bytes(20)            # witness v0, 20-byte program
    tx += _ser_varint(1) + _ser_varint(0)    # witness: 1 empty item
    tx += (0).to_bytes(4, "little")          # locktime
    parsed = blockchain.parse_raw_tx(tx.hex())
    check("raw tx parse", parsed.get("version") == 2 and parsed.get("segwit") is True
          and len(parsed["inputs"]) == 1 and len(parsed["outputs"]) == 1
          and parsed["outputs"][0]["value_btc"] == 1.5 and parsed["locktime"] == 0,
          str(parsed)[:200])
    audit = blockchain.wallet_security_audit(str(tmp / "downloads" / "proj" / "app.py"))
    check("wallet audit runs", "findings" in audit)

    print("\n=== TEST: security analyzer ===")
    vuln = tmp / "downloads" / "vuln.py"
    vuln.write_text(
        "import pickle, subprocess, hashlib, random, yaml\n"
        "API_KEY = 'sk-abcdef1234567890abcdef'\n"
        "def f(data):\n"
        "    return pickle.loads(data)\n"
        "def g(cmd):\n"
        "    subprocess.run(cmd, shell=True)\n"
        "def h(x):\n"
        "    return hashlib.md5(x.encode()).hexdigest()\n"
        "def i():\n"
        "    return random.randint(1, 100)\n"
        "def j(q):\n"
        "    cur.execute('SELECT * FROM users WHERE name=%s' % q)\n"
        "def k(url):\n"
        "    import requests\n"
        "    return requests.get(url, verify=False)\n"
    )
    audit = sec_analyzer.audit_python_file(str(vuln))
    found = {f["check"] for f in audit["findings"]}
    for expected_check in ("pickle_loads", "shell_true", "hardcoded_secret", "weak_hash",
                           "random_security", "sql_injection", "ssl_verify_disabled"):
        check(f"audit detects {expected_check}", expected_check in found, str(found))
    clean = tmp / "downloads" / "clean.py"
    clean.write_text("import json\ndef f(x):\n    return json.loads(x)\n")
    clean_audit = sec_analyzer.audit_python_file(str(clean))
    check("clean file has no findings", len(clean_audit["findings"]) == 0)
    dep = sec_analyzer.check_dependencies()
    check("dependency check returns report", isinstance(dep, dict) and ("available" in dep or "result" in dep))
    review = sec_analyzer.owasp_review(str(tmp / "downloads" / "test_app"))
    check("owasp review", len(review["checklist"]) == 10)

    print("\n=== TEST: planner ===")
    plan = Planner._template_plan("create a python project named calculator")
    check("template plan has 8 stages", len(plan) == 8 and plan[0].startswith("PLAN"))

    print("\n=== TEST: LLM client against local mock OpenRouter server ===")
    server = HTTPServer(("127.0.0.1", 0), MockHandler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    mock_llm = OpenRouterClient(tmp / "config_test", log_fn=lambda *_: None)
    # Point the client at the mock server
    mock_llm.BASE_URL = f"http://127.0.0.1:{port}/api/v1"
    import core.llm as llm_mod
    llm_mod.BASE_URL = mock_llm.BASE_URL
    mock_llm.save_key("test-key-123")
    info = mock_llm.validate_key()
    check("mock key validation", info["valid"] and info["label"] == "mock")
    models = mock_llm.list_models()
    check("mock model listing", len(models) == 2 and models[0]["free"])
    mock_llm.set_model("test/free-model")
    reply = mock_llm.chat([{"role": "user", "content": "hello"}])
    check("mock chat completion", reply.startswith("MOCK-REPLY"))
    cred_file = tmp / "config_test" / "credentials.json"
    check("credential file chmod 600", oct(os.stat(cred_file).st_mode)[-3:] == "600")
    check("key not plaintext on disk", "test-key-123" not in cred_file.read_text())
    mock_llm.clear_key()
    bad_llm = OpenRouterClient(tmp / "config_test2", log_fn=lambda *_: None)
    bad_llm.BASE_URL = mock_llm.BASE_URL
    bad_llm.save_key("wrong-key")
    try:
        bad_llm.validate_key()
        check("invalid key rejected", False)
    except llm_mod.LLMError as exc:
        check("invalid key rejected", exc.kind == "auth")
    llm_mod.BASE_URL = "https://openrouter.ai/api/v1"
    server.shutdown()

    print("\n" + "=" * 50)
    print(f"  RESULTS: {PASS} passed, {FAIL} failed")
    print("=" * 50)
    sys.exit(1 if FAIL else 0)


def _raises_value(fn):
    try:
        fn()
        return False
    except ValueError:
        return True


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception:
        traceback.print_exc()
        print("\n  SELF-TEST CRASHED")
        sys.exit(2)
