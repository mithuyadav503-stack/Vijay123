"""Security analyzer: static code analysis, dependency checks, OWASP-style configuration review.

Defensive only: this tool audits code you own and runs only in your local environment.
"""

import ast
import json
import re
import shutil
import subprocess
from pathlib import Path


class SecurityAnalyzer:
    def __init__(self, security, file_manager, terminal):
        self.sec = security
        self.fm = file_manager
        self.term = terminal

    # ---------------- static analysis (AST-based) ----------------
    CHECKS = [
        ("eval", "CRITICAL", "Use of eval() can execute arbitrary code. Remove it or use ast.literal_eval."),
        ("exec", "CRITICAL", "Use of exec() can execute arbitrary code."),
        ("pickle_loads", "HIGH", "pickle.loads() on untrusted data enables remote code execution. Use JSON instead."),
        ("yaml_load_unsafe", "HIGH", "yaml.load() without Loader=SafeLoader allows arbitrary object injection."),
        ("shell_true", "HIGH", "subprocess with shell=True enables command injection. Use a list of args."),
        ("hardcoded_secret", "CRITICAL", "Possible hardcoded API key/password/token in source code."),
        ("weak_hash", "MEDIUM", "MD5/SHA1 are cryptographically broken for security purposes. Use SHA-256+ or BLAKE2."),
        ("random_security", "HIGH", "random module is not cryptographically secure. Use the secrets module."),
        ("sql_injection", "HIGH", "SQL query built with string formatting. Use parameterized queries."),
        ("ssl_verify_disabled", "CRITICAL", "verify=False disables TLS certificate validation (MITM risk)."),
        ("tempfile_insecure", "MEDIUM", "mktemp() is race-prone. Use NamedTemporaryFile or mkstemp."),
        ("chmod_world_writable", "MEDIUM", "chmod 0o777 makes a file world-writable."),
        ("debug_true", "LOW", "Flask debug=True exposes the interactive debugger in production."),
    ]

    def audit_python_file(self, path):
        """Run AST-based security checks against one Python file."""
        p = self.sec.safe_read(path)
        source = p.read_text(encoding="utf-8", errors="ignore")
        findings = []
        try:
            tree = ast.parse(source)
        except SyntaxError as exc:
            return {"file": str(p), "error": f"Cannot parse: {exc}"}

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fn = node.func
                name = getattr(fn, "id", None) or getattr(fn, "attr", None)
                if name == "eval":
                    findings.append(self._finding("eval", node.lineno, "eval()"))
                elif name == "exec":
                    findings.append(self._finding("exec", node.lineno, "exec()"))
                elif name == "loads" and isinstance(fn, ast.Attribute) and getattr(fn.value, "id", "") == "pickle":
                    findings.append(self._finding("pickle_loads", node.lineno, "pickle.loads"))
                elif name == "load" and isinstance(fn, ast.Attribute) and getattr(fn.value, "id", "") == "yaml":
                    kwargs = {kw.arg for kw in node.keywords if kw.arg}
                    if "Loader" not in kwargs:
                        findings.append(self._finding("yaml_load_unsafe", node.lineno, "yaml.load without SafeLoader"))
                elif name == "run" and isinstance(fn, ast.Attribute) and getattr(fn.value, "id", "") == "subprocess":
                    for kw in node.keywords:
                        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                            findings.append(self._finding("shell_true", node.lineno, "subprocess shell=True"))
                elif name in ("md5", "sha1"):
                    findings.append(self._finding("weak_hash", node.lineno, f"hashlib.{name}"))
                elif name in ("mktemp",):
                    findings.append(self._finding("tempfile_insecure", node.lineno, "tempfile.mktemp"))
            elif isinstance(node, ast.Constant):
                if isinstance(node.value, str) and re.search(
                        r"(?i)(sk-or-v1-[A-Za-z0-9\-_]{16,}|sk-[A-Za-z0-9]{16,}|(password|secret|api_?key)\s*=\s*['\"][^'\"]{8,})", node.value):
                    findings.append(self._finding("hardcoded_secret", getattr(node, "lineno", 0), "hardcoded secret string"))
            elif isinstance(node, (ast.Attribute, ast.Name)):
                nm = getattr(node, "attr", None) or getattr(node, "id", None)
                if nm == "verify":
                    pass
            if isinstance(node, ast.keyword) and node.arg == "verify":
                if isinstance(node.value, ast.Constant) and node.value.value is False:
                    findings.append(self._finding("ssl_verify_disabled", getattr(node, "lineno", 0), "verify=False"))
            if isinstance(node, ast.Call):
                fn = node.func
                if getattr(fn, "attr", None) == "random" or getattr(getattr(fn, "value", None), "id", "") == "random":
                    if getattr(fn, "attr", None) in ("random", "randint", "choice"):
                        findings.append(self._finding("random_security", node.lineno, f"random.{fn.attr}"))
                if getattr(fn, "attr", None) == "chmod":
                    for arg in node.args:
                        if isinstance(arg, ast.Constant) and arg.value == 0o777:
                            findings.append(self._finding("chmod_world_writable", node.lineno, "chmod 0o777"))
            if isinstance(node, ast.BoolOp):
                pass
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
                if isinstance(node.left, ast.Constant) and isinstance(node.left.value, str) and "select" in node.left.value.lower():
                    findings.append(self._finding("sql_injection", node.lineno, "SQL via %-format"))
            if isinstance(node, ast.JoinedStr):
                for v in node.values:
                    if isinstance(v, ast.Constant) and isinstance(v.value, str) and "select" in v.value.lower():
                        findings.append(self._finding("sql_injection", node.lineno, "SQL via f-string"))
            if isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name) and t.id == "debug" and isinstance(node.value, ast.Constant) and node.value.value is True:
                        findings.append(self._finding("debug_true", node.lineno, "debug = True"))

        # deduplicate
        seen = set()
        unique = []
        for f in findings:
            key = (f["check"], f["line"])
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return {
            "file": str(p),
            "findings": unique,
            "summary": self._summarize(unique),
        }

    @staticmethod
    def _finding(check, line, detail):
        for name, severity, advice in SecurityAnalyzer.CHECKS:
            if name == check:
                return {"check": name, "severity": severity, "line": line, "detail": detail, "advice": advice}
        return {"check": check, "severity": "INFO", "line": line, "detail": detail, "advice": ""}

    @staticmethod
    def _summarize(findings):
        counts = {}
        for f in findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        return counts

    def audit_project(self, project_dir):
        """Audit every Python file in a project directory."""
        pdir = self.sec.validate_path(project_dir)
        results = []
        for f in sorted(pdir.rglob("*.py")):
            if "site-packages" in str(f):
                continue
            results.append(self.audit_python_file(f))
        total = {}
        for r in results:
            for sev, n in r.get("summary", {}).items():
                total[sev] = total.get(sev, 0) + n
        return {"project": str(pdir), "files_audited": len(results), "results": results, "totals": total}

    # ---------------- dependency vulnerability check ----------------
    def check_dependencies(self, project_dir=None):
        """Check installed packages for known CVEs via pip-audit if available."""
        if shutil.which("pip-audit") is None:
            return {
                "available": False,
                "note": "pip-audit is not installed. Install it for real CVE checks: pip install pip-audit",
                "manual": "Review your packages at https://osv.dev and https://pypi.org/project/pip-audit/",
            }
        cmd = "pip-audit"
        if project_dir:
            req = Path(project_dir) / "requirements.txt"
            if req.exists():
                cmd = f"pip-audit -r {req}"
        result = self.term.run(cmd, timeout=300, interactive_confirm=False)
        return {"available": True, "result": result}

    # ---------------- OWASP-style config review ----------------
    OWASP_CHECKLIST = [
        ("A01 Broken Access Control", "Check every endpoint restricts resources to authorized users only."),
        ("A02 Cryptographic Failures", "Data in transit uses TLS; passwords use bcrypt/argon2; no MD5/SHA1."),
        ("A03 Injection", "All SQL/OS/LDAP queries use parameterized or validated inputs."),
        ("A04 Insecure Design", "Threat model documented; rate limiting on sensitive operations."),
        ("A05 Security Misconfiguration", "Debug mode off; default credentials changed; verbose errors disabled."),
        ("A06 Vulnerable Components", "Dependencies pinned and scanned (pip-audit / osv.dev)."),
        ("A07 Auth Failures", "MFA supported; login rate-limited; session tokens expire."),
        ("A08 Data Integrity Failures", "Updates signed; deserialization of untrusted data avoided."),
        ("A09 Logging Failures", "Auth events logged; logs contain no secrets (this agent redacts them)."),
        ("A10 SSRF", "Outbound URL fetching restricted to allow-listed hosts."),
    ]

    def owasp_review(self, project_dir=None):
        """Produce an OWASP Top-10 review checklist; static findings are attached when a project is given."""
        review = {
            "scope": str(project_dir) if project_dir else "configuration-only",
            "checklist": [{"item": item, "guidance": guidance} for item, guidance in self.OWASP_CHECKLIST],
        }
        if project_dir:
            audit = self.audit_project(project_dir)
            review["static_analysis_totals"] = audit["totals"]
            review["static_findings"] = [
                f for r in audit["results"] for f in r.get("findings", [])
            ][:50]
        return review
