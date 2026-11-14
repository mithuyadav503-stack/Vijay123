"""OpenRouter LLM client: secure key storage, validation, model listing, chat completions."""

import base64
import json
import os
import stat
import time
from pathlib import Path

import requests

BASE_URL = "https://openrouter.ai/api/v1"
TIMEOUT = 90


class LLMError(Exception):
    def __init__(self, message, kind="api", status=None):
        super().__init__(message)
        self.kind = kind          # auth | network | rate_limit | api
        self.status = status


class OpenRouterClient:
    def __init__(self, config_dir, log_fn=print):
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.cred_file = self.config_dir / "credentials.json"
        self.settings_file = self.config_dir / "settings.json"
        self.model = None
        self.last_usage = None
        self._log = log_fn

    # ---------------- API key management ----------------
    def save_key(self, api_key):
        """Store the key obfuscated (base64) in a 0600 file. Never logged, never hardcoded."""
        payload = json.dumps({"api_key": base64.b64encode(api_key.encode()).decode()}).encode()
        with open(self.cred_file, "wb") as fh:
            fh.write(payload)
        os.chmod(self.cred_file, stat.S_IRUSR | stat.S_IWUSR)  # 600
        try:
            os.chmod(self.config_dir, stat.S_IRWXU)  # 700
        except OSError:
            pass

    def load_key(self):
        if not self.cred_file.exists():
            return None
        try:
            data = json.loads(self.cred_file.read_text())
            return base64.b64decode(data["api_key"]).decode()
        except Exception:
            return None

    def key_exists(self):
        return self.load_key() is not None

    def clear_key(self):
        if self.cred_file.exists():
            self.cred_file.unlink()

    # ---------------- HTTP helpers ----------------
    def _headers(self):
        key = self.load_key()
        if not key:
            raise LLMError("No API key configured. Use /apikey to set one.", kind="auth")
        return {
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
            "HTTP-Referer": "https://localhost/ultimate-ai-agent",
            "X-Title": "ULTIMATE AI AGENT (Termux)",
        }

    def _request(self, method, path, json_body=None, retries=2):
        url = f"{BASE_URL}{path}"
        last_exc = None
        for attempt in range(retries + 1):
            try:
                resp = requests.request(
                    method, url, headers=self._headers(),
                    json=json_body, timeout=TIMEOUT,
                )
                if resp.status_code == 401:
                    raise LLMError("Invalid or expired API key (401). Use /apikey to set a new one.", kind="auth", status=401)
                if resp.status_code == 402:
                    raise LLMError("Insufficient OpenRouter credits (402). Top up at openrouter.ai/credits.", kind="api", status=402)
                if resp.status_code == 429:
                    if attempt < retries:
                        time.sleep(3 * (attempt + 1))
                        continue
                    raise LLMError("Rate limited by OpenRouter (429). Wait a moment and retry.", kind="rate_limit", status=429)
                if resp.status_code >= 500 and attempt < retries:
                    time.sleep(2 * (attempt + 1))
                    continue
                if resp.status_code >= 400:
                    detail = ""
                    try:
                        detail = resp.json().get("error", {}).get("message", "")
                    except Exception:
                        detail = resp.text[:200]
                    raise LLMError(f"OpenRouter API error {resp.status_code}: {detail}", kind="api", status=resp.status_code)
                return resp
            except LLMError:
                raise
            except requests.exceptions.ConnectionError as exc:
                last_exc = exc
                if attempt < retries:
                    time.sleep(2 * (attempt + 1))
                    continue
                raise LLMError(
                    "Network failure: cannot reach openrouter.ai. Check your internet connection.",
                    kind="network",
                ) from exc
            except requests.exceptions.Timeout as exc:
                last_exc = exc
                if attempt < retries:
                    continue
                raise LLMError("Request to OpenRouter timed out. Try again.", kind="network") from exc
        raise LLMError(f"Request failed: {last_exc}", kind="network")

    # ---------------- validated operations ----------------
    def validate_key(self):
        """Validate the stored key with a real request to /auth/key."""
        resp = self._request("GET", "/auth/key")
        data = resp.json().get("data", {})
        return {
            "valid": True,
            "label": data.get("label", "key"),
            "usage": data.get("usage", 0),
            "limit": data.get("limit"),
            "is_free_tier": data.get("is_free_tier", False),
        }

    def list_models(self):
        resp = self._request("GET", "/models")
        models = resp.json().get("data", [])
        result = []
        for m in models:
            pricing = m.get("pricing", {})
            result.append({
                "id": m.get("id"),
                "name": m.get("name", m.get("id")),
                "context": m.get("context_length"),
                "free": pricing.get("prompt") == "0" and pricing.get("completion") == "0",
            })
        return result

    def set_model(self, model_id):
        self.model = model_id
        if self.settings_file.exists():
            try:
                settings = json.loads(self.settings_file.read_text())
            except Exception:
                settings = {}
        else:
            settings = {}
        settings["model"] = model_id
        self.settings_file.write_text(json.dumps(settings, indent=2))
        os.chmod(self.settings_file, stat.S_IRUSR | stat.S_IWUSR)

    def load_saved_model(self):
        if self.settings_file.exists():
            try:
                return json.loads(self.settings_file.read_text()).get("model")
            except Exception:
                return None
        return None

    def chat(self, messages, model=None, temperature=0.4, max_tokens=2048):
        """Send a chat completion request. Returns assistant text content."""
        use_model = model or self.model
        if not use_model:
            raise LLMError("No model selected. Use /model to choose one.", kind="auth")
        body = {
            "model": use_model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        resp = self._request("POST", "/chat/completions", json_body=body)
        data = resp.json()
        self.last_usage = data.get("usage")
        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as exc:
            raise LLMError(f"Unexpected API response shape: {json.dumps(data)[:300]}", kind="api") from exc
        if content is None:
            content = ""
        return content
