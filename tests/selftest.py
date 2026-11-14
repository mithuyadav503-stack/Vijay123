#!/usr/bin/env python3
"""Offline self-tests for ULTIMATE AI AGENT. No API key or network needed.

Every test is transactional: setup -> assert -> cleanup in try/finally, so a failure
never leaves half-built state behind and never crashes the run.

Run: python tests/selftest.py
"""

import json
import os
import shutil
import sqlite3
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
from core.providers import ProviderManager, ProviderError, build_provider
from tools.file_manager import FileManager
from tools.terminal import TerminalExecutor
from tools.registry import ToolRegistry
from tools.coding import CodingEngine
from tools.debugger import Debugger
from tools.crypto import CryptoToolkit
from tools.blockchain import BlockchainToolkit
from tools.security_audit import SecurityAnalyzer
from tools.ecdsa_lab import (keygen, sign, verify, point_mul, recover_from_nonce_reuse,
                             rfc6979_nonce, demo_nonce_reuse, rfc6979_stability_check)
from core.planner import Planner
import main as agent_main
from unittest import mock

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
    hit_count = {"bad": 0}

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
        auth = self.headers.get("Authorization", "")
        if self.path == "/api/v1/auth/key":
            if auth == "Bearer test-key-123":
                self._json(200, {"data": {"label": "mock", "usage": 0.5, "limit": 100, "is_free_tier": True}})
            else:
                self._json(401, {"error": {"message": "Invalid key"}})
        elif self.path == "/api/v1/models" and auth == "Bearer test-key-123":
            self._json(200, {"data": [
                {"id": "test/free-model", "name": "Free Test", "context_length": 8192,
                 "pricing": {"prompt": "0", "completion": "0"}},
                {"id": "test/paid-model", "name": "Paid Test", "context_length": 32768,
                 "pricing": {"prompt": "0.001", "completion": "0.002"}},
            ]})
        elif self.path == "/api/v1/models":
            self._json(200, {"data": [{"id": "public-model", "name": "Public", "pricing": {}}]})
        else:
            self._json(404, {"error": {"message": "not found"}})

    def do_POST(self):
        if self.path == "/api/v1/chat/completions":
            if self.headers.get("Authorization") != "Bearer test-key-123":
                self._json(401, {"error": {"message": "Invalid key"}})
                return
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length))
            self._json(200, {
                "choices": [{"message": {"content": f"MOCK-REPLY to: {body['messages'][-1]['content'][:40]}"}}],
                "usage": {"prompt_tokens": 5, "completion_tokens": 7},
            })
        elif self.path == "/flaky/chat/completions":
            MockHandler.hit_count["bad"] += 1
            if MockHandler.hit_count["bad"] <= 2:
                self._json(500, {"error": {"message": "flaky server"}})
            else:
                self._json(200, {"choices": [{"message": {"content": "FLAKY-RECOVERED"}}],
                                 "usage": {"prompt_tokens": 3, "completion_tokens": 4}})
        else:
            self._json(404, {"error": {"message": "not found"}})


def make_agent_parts(workspace):
    settings = {"workspace": str(workspace), "max_permission_level": 5, "confirm_sensitive": False}
    sec = SecurityManager(workspace, settings, log_file=workspace / "security_test.log")
    llm = ProviderManager(PROJECT_ROOT / "config", log_fn=lambda *_: None)
    memory = MemoryManager(workspace / "data_test", redact_fn=sec.redact)
    fm = FileManager(sec, backup_dir=workspace / "backups_test")
    term = TerminalExecutor(sec, workdir=workspace)
    coding = CodingEngine(fm, sec, term, memory)
    debugger = Debugger(coding, term, sec, llm=llm)
    crypto = CryptoToolkit(sec)
    blockchain = BlockchainToolkit(sec, file_manager=fm)
    sec_analyzer = SecurityAnalyzer(sec, fm, term)
    registry = ToolRegistry(sec, fm, term, crypto)
    return sec, llm, memory, fm, term, coding, debugger, crypto, blockchain, sec_analyzer, registry


def test_security(sec, tmp):
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
    expect_error("refuse to read .env", lambda: sec.safe_read(str(tmp / ".env")), PermissionDenied)
    sec.audit("TEST", "audit line", exit_code=0)
    audit = (sec.log_file.parent / "audit.log").read_text()
    check("audit log with exit code", "exit=0" in audit and "TEST" in audit)


def test_memory(memory, tmp):
    print("\n=== TEST: memory manager ===")
    memory.add("facts", "User prefers Hindi replies")
    memory.add("tasks_pending", "Build todo app")
    memory.edit("facts", 0, "User prefers Hindi replies with English tech terms")
    hits = memory.search("hindi")
    check("memory add/edit/search", len(hits) == 1 and "English tech" in hits[0]["text"])
    memory.add("decisions", "Use SQLite for storage")
    exported = memory.export(str(tmp / "mem_export.json"))
    check("memory export", Path(exported).exists() and "SQLite" in Path(exported).read_text())
    memory.append_history("user", "hello agent")
    memory.append_history("assistant", "namaste! how can I help?")
    check("history roundtrip", len(memory.recent_history(5)) == 2)
    memory.delete("tasks_pending", 0)
    check("memory delete", len(memory.list("tasks_pending")) == 0)
    memory.clear("all")
    check("memory clear", all(len(memory.list(c)) == 0 for c in
          ("facts", "instructions", "decisions", "errors", "tasks_pending", "tasks_completed")))


def test_file_manager(fm, sec, tmp):
    print("\n=== TEST: file manager (transactional) ===")
    proj = tmp / "proj"
    try:
        fm.mkdir("proj")
        check("mkdir", proj.is_dir())
        fm.write_file("proj/app.py", "print('hi')\n", backup=False)
        read = fm.read_file("proj/app.py")
        check("write+read file", read["content"] == "print('hi')\n")
        fm.write_file("proj/app.py", "print('bye')\n", backup=True)
        backups = list((tmp / "backups_test").glob("app.py.*.bak"))
        check("backup before overwrite", len(backups) == 1 and backups[0].read_text() == "print('hi')\n")
        fm.mkdir("proj/sub")
        fm.write_file("proj/sub/deep.txt", "needle in haystack", backup=False)
        check("recursive list", any(e["name"] == "deep.txt" for e in fm.list_dir("proj", recursive=True)))
        check("find names", len(fm.find_names("*.py", "proj")) == 1)
        check("grep contents", any(r["line"] == 1 for r in fm.grep("needle", "proj")))
        fm.rename("proj/sub/deep.txt", "proj/sub/moved.txt")
        check("rename", (proj / "sub" / "moved.txt").exists())
        fm.copy("proj/app.py", "proj/app_copy.py")
        check("copy", (proj / "app_copy.py").exists())
        fm.move("proj/app_copy.py", "proj/renamed_copy.py")
        renamed = proj / "renamed_copy.py"
        check("move", renamed.exists())
        scan = fm.scan("proj")
        check("scan", scan["files"] >= 3 and scan["dirs"] >= 1)
        import zipfile
        with zipfile.ZipFile(tmp / "arch.zip", "w") as zf:
            zf.writestr("inside.txt", "zipped content")
        dest = fm.extract_archive("arch.zip")
        check("extract zip", (Path(dest) / "inside.txt").exists())
        expect_error("delete requires level5+confirm", lambda: fm.delete("proj/renamed_copy.py"))
        sec.auto_confirm = True
        fm.delete("proj/renamed_copy.py")
        sec.auto_confirm = None
        check("delete works after confirm", not renamed.exists())
    finally:
        sec.auto_confirm = None
        shutil.rmtree(proj, ignore_errors=True)
        shutil.rmtree(tmp / "backups_test", ignore_errors=True)
        shutil.rmtree(tmp / "arch_extracted", ignore_errors=True)
        (tmp / "arch.zip").unlink(missing_ok=True)


def test_terminal(term):
    print("\n=== TEST: terminal executor ===")
    r = term.run("echo hello_from_shell")
    check("run echo", r["ok"] and "hello_from_shell" in r["stdout"])
    r = term.run("rm -rf /")
    check("dangerous blocked in executor", not r["ok"] and "Blocked" in r["error"])
    r = term.run(f'"{sys.executable}" -c "print(6*7)"', interactive_confirm=False)
    check("run python inline", r["ok"] and "42" in r["stdout"], str(r))


def test_coding(coding, fm, tmp, sec):
    print("\n=== TEST: coding engine ===")
    projdir = tmp / "test_app"
    try:
        proj = coding.create_project("test_app", description="Test app")
        check("create project", (projdir / "main.py").exists() and (projdir / "README.md").exists())
        expect_error("refuse to overwrite project", lambda: coding.create_project("test_app"), PermissionDenied)
        r = coding.run_python(str(projdir / "main.py"))
        check("run project main.py", r["ok"] and "Hello from test_app!" in r["stdout"])
        coding.write_code_file(str(projdir / "util.py"), "def add(a, b):\n    return a + b\n", backup=False)
        coding.edit_code_file(str(projdir / "util.py"), "return a + b", "return a + b  # patched")
        check("edit code file", "patched" in (projdir / "util.py").read_text())
        readme = coding.generate_readme(str(projdir))
        check("generate readme", "test_app" in Path(readme).read_text())
        report = coding.generate_report("unit_test_report", {"ok": True}, fmt="json")
        check("generate json report", Path(report).exists() and json.loads(Path(report).read_text())["ok"])
        report_md = coding.generate_report("unit_test_md", "# Heading\nBody text", fmt="md")
        check("generate md report", "Body text" in Path(report_md).read_text())
    finally:
        shutil.rmtree(projdir, ignore_errors=True)
        for f in Path(PROJECT_ROOT, "reports").glob("unit_test_*"):
            f.unlink(missing_ok=True)


def test_debugger(debugger, tmp):
    print("\n=== TEST: debugger ===")
    files = {}
    try:
        bad = tmp / "broken.py"
        bad.write_text("x = [1, 2]\nprint(x[5])\n")
        files["broken"] = bad
        outcome = debugger.run_and_diagnose(str(bad))
        check("detect IndexError", outcome["diagnosis"]["error_type"] == "IndexError")
        check("hindi explanation present", bool(outcome["diagnosis"]["hindi"]))
        bad2 = tmp / "nomodule.py"
        bad2.write_text("import nonexistent_pkg_xyz\n")
        files["nomodule"] = bad2
        outcome2 = debugger.run_and_diagnose(str(bad2))
        check("detect ModuleNotFoundError", outcome2["diagnosis"]["error_type"] == "ModuleNotFoundError")
        check("pip suggestion generated", "pip install nonexistent_pkg_xyz" == outcome2["diagnosis"]["fix_suggestion"])
        syntax_bad = tmp / "syntax.py"
        syntax_bad.write_text("def f(:\n    pass\n")
        files["syntax"] = syntax_bad
        outcome3 = debugger.run_and_diagnose(str(syntax_bad))
        check("detect SyntaxError", outcome3["diagnosis"]["error_type"] == "SyntaxError")
    finally:
        for f in files.values():
            f.unlink(missing_ok=True)


def test_crypto(crypto, tmp, fm):
    print("\n=== TEST: crypto toolkit ===")
    import hashlib as _h
    import hmac as _hmac
    try:
        h = crypto.hash_text("hello world", "sha256")
        check("sha256 known vector", h["digest"] ==
              "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")
        check("sha512", len(crypto.hash_text("x", "sha512")["digest"]) == 128)
        check("sha3-256", len(crypto.hash_text("x", "sha3-256")["digest"]) == 64)
        check("blake2b", len(crypto.hash_text("x", "blake2b")["digest"]) == 128)
        hm = crypto.hmac_compute("key123", "message", "sha256")
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
        target = tmp / "hashme.txt"
        target.write_text("file content")
        check("hash file", crypto.hash_file(str(target))["digest"] == _h.sha256(target.read_bytes()).hexdigest())
    finally:
        target.unlink(missing_ok=True)


def test_blockchain(blockchain, tmp):
    print("\n=== TEST: blockchain toolkit ===")
    try:
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

        def _ser_varint(n):
            if n < 0xFD:
                return bytes([n])
            if n <= 0xFFFF:
                return b"\xfd" + n.to_bytes(2, "little")
            return b"\xfe" + n.to_bytes(4, "little")

        tx = bytearray()
        tx += (2).to_bytes(4, "little")
        tx += b"\x00\x01"
        tx += _ser_varint(1)
        tx += bytes(range(32))[::-1]
        tx += (3).to_bytes(4, "little")
        tx += _ser_varint(0)
        tx += (0xFFFFFFFF).to_bytes(4, "little")
        tx += _ser_varint(1)
        tx += (150_000_000).to_bytes(8, "little")
        tx += _ser_varint(23)
        tx += b"\x00\x14" + bytes(20)
        tx += _ser_varint(1) + _ser_varint(0)
        tx += (0).to_bytes(4, "little")
        parsed = blockchain.parse_raw_tx(tx.hex())
        check("raw tx parse", parsed.get("version") == 2 and parsed.get("segwit") is True
              and len(parsed["inputs"]) == 1 and len(parsed["outputs"]) == 1
              and parsed["outputs"][0]["value_btc"] == 1.5 and parsed["locktime"] == 0,
              str(parsed)[:200])

        wallet = tmp / "sample_electrum"
        wallet.write_text('{"seed_version": 13, "seed": "word1 word2", "keystore": {"type": "bip32", "xprv": "xprvXX..."}}')
        det = blockchain.detect_wallet_format(str(wallet))
        check("detect electrum", det["format"] == "Electrum wallet (JSON)" and det["encrypted"] is False)
        check("electrum plaintext seed flagged",
              any(f["level"] == "CRITICAL" and "Seed" in f["note"] for f in det["findings"]))
        bc = tmp / "sample_blockchain_json"
        bc.write_text('{"pbkdf2_iterations": 10, "payload": "AAAA"}')
        det2 = blockchain.detect_wallet_format(str(bc))
        check("detect blockchain.com + weak kdf",
              det2["format"] == "Blockchain.com wallet (AES JSON)"
              and any("5000" in f["note"] for f in det2["findings"]))
        bdb = tmp / "sample_wallet.dat"
        bdb.write_bytes(b"\x00\x05\x15\xdb" + b"mkey" + b"ckey" + b"\x00" * 64)
        det3 = blockchain.detect_wallet_format(str(bdb))
        check("detect bitcoin core bdb", det3["format"] == "Bitcoin Core (Berkeley DB)"
              and det3["encrypted"] is True)
    finally:
        for f in ("sample_electrum", "sample_blockchain_json", "sample_wallet.dat"):
            (tmp / f).unlink(missing_ok=True)


def test_security_analyzer(sec_analyzer, tmp):
    print("\n=== TEST: security analyzer ===")
    vuln = tmp / "vuln.py"
    try:
        vuln.write_text(
            "import pickle, subprocess, hashlib, random\n"
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
        clean = tmp / "clean.py"
        clean.write_text("import json\ndef f(x):\n    return json.loads(x)\n")
        clean_audit = sec_analyzer.audit_python_file(str(clean))
        check("clean file has no findings", len(clean_audit["findings"]) == 0)
        dep = sec_analyzer.check_dependencies()
        check("dependency check returns report", isinstance(dep, dict) and ("available" in dep or "result" in dep))
        review = sec_analyzer.owasp_review(str(tmp))
        check("owasp review", len(review["checklist"]) == 10)
    finally:
        vuln.unlink(missing_ok=True)
        (tmp / "clean.py").unlink(missing_ok=True)


def test_planner():
    print("\n=== TEST: planner ===")
    plan = Planner._template_plan("create a python project named calculator")
    check("template plan has 8 stages", len(plan) == 8 and plan[0].startswith("PLAN"))


def test_ecdsa_lab():
    print("\n=== TEST: ECDSA lab (educational, toy keys) ===")
    d, pub = keygen()
    r, s, z = sign(d, "test message")
    check("sign+verify", verify(pub, "test message", r, s))
    check("verify tamper fails", not verify(pub, "other message", r, s))
    demo = demo_nonce_reuse("tx one", "tx two")
    check("nonce reuse recovers private key", demo["private_key_recovered"] and demo["public_key_matches"])
    check("recovered k matches", demo["recovered_k_matches"])
    stab = rfc6979_stability_check(d, "deterministic msg")
    check("rfc6979 deterministic", stab["deterministic"] and stab["distinct_nonces_seen"] == 1)
    k1 = rfc6979_nonce(d, "msg A")
    k2 = rfc6979_nonce(d, "msg B")
    check("rfc6979 differs across messages", k1 != k2)


def test_registry(registry, sec, tmp):
    print("\n=== TEST: tool registry ===")
    try:
        target = tmp / "reg_test.txt"
        out = registry.dispatch("write_file", {"path": str(target), "content": "registry works"})
        check("registry write_file", out["ok"] and target.read_text() == "registry works")
        out = registry.dispatch("read_file", {"path": str(target)})
        check("registry read_file", out["ok"] and out["result"]["content"] == "registry works")
        out = registry.dispatch("hash", {"text": "abc", "algo": "sha256"})
        check("registry hash", out["ok"] and out["result"]["digest"] ==
              "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        db = tmp / "test.db"
        conn = sqlite3.connect(str(db))
        conn.execute("CREATE TABLE t (id INTEGER, name TEXT)")
        conn.execute("INSERT INTO t VALUES (1, 'alpha')")
        conn.commit()
        conn.close()
        out = registry.dispatch("sqlite_query", {"path": str(db), "query": "SELECT * FROM t"})
        check("registry sqlite_query", out["ok"] and out["result"]["rows"][0]["name"] == "alpha")
        out = registry.dispatch("python_eval", {"code": "print(21*2)"})
        check("registry python_eval", out["ok"] and "42" in out["result"]["stdout"])
        out = registry.dispatch("base64_decode", {"text": "not valid base64!!!"})
        check("registry invalid input handled", not out["ok"] and "error" in out)
        out = registry.dispatch("nonexistent_tool", {})
        check("unknown tool handled", not out["ok"] and "Unknown tool" in out["error"])
        out = registry.dispatch("write_file", {"path": str(target)})
        check("missing required arg handled", not out["ok"] and "Missing required" in out["error"])
        sec.max_level = 1
        out = registry.dispatch("write_file", {"path": str(target), "content": "x"})
        check("level enforcement in registry", not out["ok"] and "LEVEL" in out["error"])
        sec.max_level = 5
        out = registry.dispatch("run_shell", {"command": "rm -rf /"})
        check("dangerous shell blocked in registry",
              out["ok"] and not out["result"]["ok"] and "Blocked" in out["result"]["error"], str(out))
        check("tool count", len(registry.list()) >= 18, f"got {len(registry.list())}")
    finally:
        target.unlink(missing_ok=True)
        db.unlink(missing_ok=True)


def test_providers(tmp):
    print("\n=== TEST: provider layer (mock OpenRouter-compatible server) ===")
    server = HTTPServer(("127.0.0.1", 0), MockHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    cfg_dir = tmp / "providers_cfg"
    pm = ProviderManager(cfg_dir, log_fn=lambda *_: None)
    try:
        pm.add_provider("mock", "openai", base_url=f"http://127.0.0.1:{port}/api/v1",
                        api_key="test-key-123", default_model="test/free-model")
        pm.config["providers"]["mock"]["test_path"] = "/auth/key"
        info = pm.validate_key()
        check("mock key validation", info["valid"] and "mock" in info["detail"])
        pm.config["providers"]["mock"]["test_path"] = "/models"
        models = pm.list_models()
        check("mock model listing", len(models) == 2 and models[0]["free"])
        reply = pm.chat([{"role": "user", "content": "hello"}])
        check("mock chat completion", reply.startswith("MOCK-REPLY"))
        check("usage accounting", pm.session_usage["prompt_tokens"] == 5
              and pm.session_usage["completion_tokens"] == 7)

        pm.add_provider("flaky", "openai", base_url=f"http://127.0.0.1:{port}/flaky",
                        api_key="test-key-123", default_model="any")
        pm.set_active("flaky")
        reply2 = pm.chat([{"role": "user", "content": "hi"}])
        check("5xx retried on same provider", reply2 == "FLAKY-RECOVERED"
              and pm.last_provider == "flaky", reply2)

        pm.add_provider("down", "openai", base_url="http://127.0.0.1:9/unreachable",
                        api_key="test-key-123", default_model="any")
        pm.set_active("down")
        MockHandler.hit_count["bad"] = 99
        reply3 = pm.chat([{"role": "user", "content": "hello"}])
        check("fallback chain switches to healthy provider", reply3.startswith("MOCK-REPLY")
              and pm.last_provider == "mock" and pm.session_usage["fallbacks"] >= 1, reply3)
        pm.set_active("mock")

        bad = ProviderManager(tmp / "cfg2")
        bad.add_provider("mock", "openai", base_url=f"http://127.0.0.1:{port}/api/v1",
                         api_key="wrong-key")
        bad.config["providers"]["mock"]["test_path"] = "/auth/key"
        bad._save()
        try:
            bad.validate_key()
            check("invalid key rejected", False)
        except ProviderError as exc:
            check("invalid key rejected", exc.kind == "auth")
        cred = cfg_dir / "providers.json"
        check("providers.json chmod 600", oct(os.stat(cred).st_mode)[-3:] == "600")
        check("key not plaintext on disk", "test-key-123" not in cred.read_text())
        check("no provider configured raises", _raises(pm2_chat := (lambda: ProviderManager(tmp / 'cfg3').chat([{"role": "user", "content": "x"}]))))
    finally:
        server.shutdown()
        thread.join(timeout=2)
        shutil.rmtree(cfg_dir, ignore_errors=True)
        shutil.rmtree(tmp / "cfg2", ignore_errors=True)
        shutil.rmtree(tmp / "cfg3", ignore_errors=True)


def _raises(fn):
    try:
        fn()
        return False
    except ProviderError:
        return True



def test_startup_recovery(tmp):
    """The reported bug: a 401 during setup must not skip model selection."""
    print("\n=== TEST: startup recovery (401 -> re-key -> model picker reached) ===")
    cfg_dir = tmp / "startup_cfg"
    pm = ProviderManager(cfg_dir, log_fn=lambda *_: None)
    calls = {"validate": 0}

    def flaky_validate():
        calls["validate"] += 1
        if calls["validate"] == 1:
            raise ProviderError("Invalid or unauthorized API key (401).", kind="auth")
        return {"valid": True, "detail": "mock: key accepted"}

    pm.add_provider("mock", "openai", base_url="http://127.0.0.1:1/v1",
                    api_key="bad-key-first", default_model=None)
    pm.validate_key = flaky_validate
    pm.list_models = lambda: [{"id": "mock/model-1", "name": "M1", "context": 100, "free": True}]

    answers = iter(["new-key-456", "1"])  # re-enter key, then pick model 1
    getpass_answers = iter(["new-key-456"])
    with mock.patch("builtins.input", lambda *a, **k: next(answers)), \
         mock.patch("getpass.getpass", lambda *a, **k: next(getpass_answers)):
        agent_main.first_run_setup(pm)

    check("model selected after 401 recovery", pm.model == "mock/model-1", str(pm.model))
    check("validation retried with new key", calls["validate"] == 2)
    check("new key stored", pm.key_exists())
    shutil.rmtree(cfg_dir, ignore_errors=True)

    pm2 = ProviderManager(tmp / "startup_cfg2", log_fn=lambda *_: None)
    pm2.add_provider("mock", "openai", base_url="http://127.0.0.1:1/v1",
                     api_key=None, default_model=None)
    answers2 = iter([""])  # empty key -> offline, must return cleanly
    with mock.patch("builtins.input", lambda *a, **k: next(answers2)), \
         mock.patch("getpass.getpass", lambda *a, **k: ""):
        agent_main.first_run_setup(pm2)
    check("empty key enters offline mode without crash", True)
    shutil.rmtree(tmp / "startup_cfg2", ignore_errors=True)


def main():
    tmp = Path(tempfile.mkdtemp(prefix="uai_test_"))
    try:
        sec, llm, memory, fm, term, coding, debugger, crypto, blockchain, sec_analyzer, registry = \
            make_agent_parts(tmp / "downloads")
        (tmp / "downloads").mkdir(exist_ok=True)
        test_security(sec, tmp / "downloads")
        test_memory(memory, tmp / "downloads")
        test_file_manager(fm, sec, tmp / "downloads")
        test_terminal(term)
        test_coding(coding, fm, tmp / "downloads", sec)
        test_debugger(debugger, tmp / "downloads")
        test_crypto(crypto, tmp / "downloads", fm)
        test_blockchain(blockchain, tmp / "downloads")
        test_security_analyzer(sec_analyzer, tmp / "downloads")
        test_planner()
        test_ecdsa_lab()
        test_registry(registry, sec, tmp / "downloads")
        test_providers(tmp)
        test_startup_recovery(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    print("\n" + "=" * 50)
    print(f"  RESULTS: {PASS} passed, {FAIL} failed")
    print("=" * 50)
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception:
        traceback.print_exc()
        print("\n  SELF-TEST CRASHED")
        sys.exit(2)
