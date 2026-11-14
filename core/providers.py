"""Provider layer: pluggable LLM backends with fallback chain, backoff, usage accounting.

Supported kinds:
- openai-compatible: OpenRouter, OpenAI, Groq, Together, Mistral, llama.cpp server, any generic
- gemini: Google native API
- ollama: local server on 127.0.0.1 (no key needed)

Config lives in config/providers.json (chmod 600). API keys are stored base64-obfuscated,
never logged, never hardcoded.
"""

import base64
import json
import os
import stat
import time
from pathlib import Path

import requests

TIMEOUT = 90


class ProviderError(Exception):
    def __init__(self, message, kind="api", status=None):
        super().__init__(message)
        self.kind = kind  # auth | network | rate_limit | api
        self.status = status


PROVIDER_PRESETS = {
    "openrouter": {"kind": "openai", "base_url": "https://openrouter.ai/api/v1",
                   "test_path": "/auth/key", "note": "openrouter.ai keys (sk-or-...)"},
    "openai": {"kind": "openai", "base_url": "https://api.openai.com/v1",
               "test_path": "/models", "note": "platform.openai.com keys (sk-...)"},
    "groq": {"kind": "openai", "base_url": "https://api.groq.com/openai/v1",
             "test_path": "/models", "note": "console.groq.com keys (free tier)"},
    "together": {"kind": "openai", "base_url": "https://api.together.xyz/v1",
                 "test_path": "/models", "note": "api.together.xyz keys"},
    "mistral": {"kind": "openai", "base_url": "https://api.mistral.ai/v1",
                "test_path": "/models", "note": "console.mistral.ai keys (free tier)"},
    "gemini": {"kind": "gemini", "base_url": "https://generativelanguage.googleapis.com/v1beta",
               "note": "aistudio.google.com keys (free tier)"},
    "ollama": {"kind": "ollama", "base_url": "http://127.0.0.1:11434",
               "note": "local, no key needed (pkg install ollama)"},
    "llamacpp": {"kind": "openai", "base_url": "http://127.0.0.1:8080/v1",
                 "note": "llama.cpp server, no key needed"},
}


class Provider:
    """Base class for all LLM backends."""
    name = "base"

    def list_models(self):
        raise NotImplementedError

    def chat(self, messages, model=None, temperature=0.4, max_tokens=2048, stream=False):
        raise NotImplementedError

    def test(self):
        raise NotImplementedError

    def usage(self):
        return dict(getattr(self, "_usage", {}))


class OpenAICompatProvider(Provider):
    """Works for OpenRouter, OpenAI, Groq, Together, Mistral, llama.cpp, any /v1 server."""

    def __init__(self, name, base_url, api_key=None, extra_headers=None, needs_key=True, test_path="/models"):
        self.name = name
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.needs_key = needs_key
        self.extra_headers = extra_headers or {}
        self.test_path = test_path
        self._usage = {}

    def _headers(self):
        if self.needs_key and not self.api_key:
            raise ProviderError(f"Provider '{self.name}' has no API key. Use /provider add or /apikey.", kind="auth")
        headers = {"Content-Type": "application/json", **self.extra_headers}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def _request(self, method, path, json_body=None, stream=False):
        url = f"{self.base_url}{path}"
        try:
            resp = requests.request(method, url, headers=self._headers(),
                                    json=json_body, timeout=TIMEOUT, stream=stream)
        except requests.exceptions.ConnectionError as exc:
            raise ProviderError(f"Cannot reach {self.base_url} (network down or server offline).", kind="network") from exc
        except requests.exceptions.Timeout as exc:
            raise ProviderError(f"Request to {self.name} timed out.", kind="network") from exc
        if resp.status_code == 401 or resp.status_code == 403:
            raise ProviderError(f"Invalid or unauthorized API key for '{self.name}' ({resp.status_code}).", kind="auth", status=resp.status_code)
        if resp.status_code == 402:
            raise ProviderError(f"'{self.name}': insufficient credits (402).", kind="api", status=402)
        if resp.status_code == 429:
            raise ProviderError(f"'{self.name}' rate limited (429).", kind="rate_limit", status=429)
        if resp.status_code >= 500:
            raise ProviderError(f"'{self.name}' server error ({resp.status_code}).", kind="api", status=resp.status_code)
        if resp.status_code >= 400:
            detail = resp.text[:200]
            try:
                detail = resp.json().get("error", {}).get("message", detail)
            except Exception:
                pass
            raise ProviderError(f"'{self.name}' API error {resp.status_code}: {detail}", kind="api", status=resp.status_code)
        return resp

    def list_models(self):
        resp = self._request("GET", "/models")
        data = resp.json().get("data", [])
        models = []
        for m in data:
            pricing = m.get("pricing", {}) or {}
            models.append({
                "id": m.get("id"),
                "name": m.get("name") or m.get("id"),
                "context": m.get("context_length") or m.get("context_window"),
                "free": pricing.get("prompt") == "0" and pricing.get("completion") == "0",
            })
        return [m for m in models if m["id"]]

    def test(self):
        """Validate the key against an AUTH-REQUIRED endpoint (never a public one)."""
        if self.needs_key and not self.api_key:
            raise ProviderError(f"Provider '{self.name}' has no API key.", kind="auth")
        resp = self._request("GET", self.test_path)
        try:
            n = len(resp.json().get("data", []))
        except Exception:
            n = 0
        return {"valid": True, "detail": f"{self.name}: key accepted ({self.test_path}), {n} models visible"}

    def chat(self, messages, model=None, temperature=0.4, max_tokens=2048, stream=False):
        if not model:
            raise ProviderError(f"No model selected for '{self.name}'. Use /model.", kind="auth")
        body = {"model": model, "messages": messages, "temperature": temperature, "max_tokens": max_tokens}
        if stream:
            return self._chat_stream(messages, model, temperature, max_tokens)
        resp = self._request("POST", "/chat/completions", json_body=body)
        data = resp.json()
        u = data.get("usage") or {}
        self._usage = {"prompt_tokens": u.get("prompt_tokens", 0),
                       "completion_tokens": u.get("completion_tokens", 0)}
        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError) as exc:
            raise ProviderError(f"Unexpected response shape from '{self.name}'.", kind="api") from exc
        return content or ""

    def _chat_stream(self, messages, model, temperature, max_tokens):
        """Stream SSE chunks; print tokens live; return full text."""
        body = {"model": model, "messages": messages, "temperature": temperature,
                "max_tokens": max_tokens, "stream": True}
        resp = self._request("POST", "/chat/completions", json_body=body, stream=True)
        collected = []
        try:
            for raw in resp.iter_lines(decode_unicode=True):
                if not raw or not raw.startswith("data: "):
                    continue
                payload = raw[6:]
                if payload.strip() == "[DONE]":
                    break
                try:
                    chunk = json.loads(payload)
                    delta = chunk["choices"][0].get("delta", {}).get("content") or ""
                except (json.JSONDecodeError, KeyError, IndexError):
                    continue
                if delta:
                    collected.append(delta)
                    print(delta, end="", flush=True)
        finally:
            resp.close()
        print()
        text = "".join(collected)
        self._usage = {"prompt_tokens": 0, "completion_tokens": 0, "streamed": True}
        if not text:
            raise ProviderError(f"'{self.name}' stream ended with no content.", kind="api")
        return text


class GeminiProvider(Provider):
    """Google Gemini native API (generativelanguage.googleapis.com)."""

    def __init__(self, name, base_url, api_key=None):
        self.name = name
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self._usage = {}

    def _key(self):
        if not self.api_key:
            raise ProviderError(f"Provider '{self.name}' has no API key.", kind="auth")
        return self.api_key

    def list_models(self):
        try:
            resp = requests.get(f"{self.base_url}/models", params={"key": self._key()}, timeout=TIMEOUT)
        except requests.exceptions.RequestException as exc:
            raise ProviderError(f"Cannot reach Gemini API: {exc}", kind="network") from exc
        if resp.status_code in (401, 403):
            raise ProviderError("Invalid Gemini API key.", kind="auth", status=resp.status_code)
        if resp.status_code == 429:
            raise ProviderError("Gemini rate limited (429).", kind="rate_limit", status=429)
        if resp.status_code >= 400:
            raise ProviderError(f"Gemini API error {resp.status_code}: {resp.text[:200]}", kind="api", status=resp.status_code)
        models = []
        for m in resp.json().get("models", []):
            if "generateContent" in m.get("supportedGenerationMethods", []):
                mid = m.get("name", "").removeprefix("models/")
                models.append({"id": mid, "name": m.get("displayName", mid),
                               "context": m.get("inputTokenLimit"), "free": "free" in mid or True})
        return models

    def test(self):
        models = self.list_models()
        return {"valid": True, "detail": f"{self.name}: key accepted, {len(models)} models visible"}

    def chat(self, messages, model=None, temperature=0.4, max_tokens=2048, stream=False):
        if not model:
            raise ProviderError(f"No model selected for '{self.name}'. Use /model.", kind="auth")
        system = "\n".join(m["content"] for m in messages if m["role"] == "system")
        contents = []
        for m in messages:
            if m["role"] not in ("user", "assistant"):
                continue
            role = "user" if m["role"] == "user" else "model"
            contents.append({"role": role, "parts": [{"text": m["content"]}]})
        body = {
            "contents": contents,
            "generationConfig": {"temperature": temperature, "maxOutputTokens": max_tokens},
        }
        if system:
            body["systemInstruction"] = {"parts": [{"text": system}]}
        url = f"{self.base_url}/models/{model}:generateContent"
        try:
            resp = requests.post(url, params={"key": self._key()}, json=body, timeout=TIMEOUT)
        except requests.exceptions.RequestException as exc:
            raise ProviderError(f"Cannot reach Gemini API: {exc}", kind="network") from exc
        if resp.status_code in (401, 403):
            raise ProviderError("Invalid Gemini API key.", kind="auth", status=resp.status_code)
        if resp.status_code == 429:
            raise ProviderError("Gemini rate limited (429).", kind="rate_limit", status=429)
        if resp.status_code >= 400:
            raise ProviderError(f"Gemini API error {resp.status_code}: {resp.text[:200]}", kind="api", status=resp.status_code)
        data = resp.json()
        u = data.get("usageMetadata", {})
        self._usage = {"prompt_tokens": u.get("promptTokenCount", 0),
                       "completion_tokens": u.get("candidatesTokenCount", 0)}
        try:
            parts = data["candidates"][0]["content"]["parts"]
            return "".join(p.get("text", "") for p in parts)
        except (KeyError, IndexError) as exc:
            raise ProviderError("Unexpected Gemini response shape.", kind="api") from exc


class OllamaProvider(Provider):
    """Local Ollama server. No API key, no internet needed."""

    def __init__(self, name, base_url):
        self.name = name
        self.base_url = base_url.rstrip("/")
        self._usage = {}

    def list_models(self):
        try:
            resp = requests.get(f"{self.base_url}/api/tags", timeout=10)
        except requests.exceptions.RequestException as exc:
            raise ProviderError(
                f"Ollama server not reachable at {self.base_url}. Start it with: `ollama serve` (another session) then `ollama pull llama3.2`.",
                kind="network",
            ) from exc
        if resp.status_code >= 400:
            raise ProviderError(f"Ollama error {resp.status_code}.", kind="api", status=resp.status_code)
        return [{"id": m.get("name"), "name": m.get("name"), "context": None, "free": True}
                for m in resp.json().get("models", []) if m.get("name")]

    def test(self):
        models = self.list_models()
        return {"valid": True, "detail": f"{self.name}: server up, {len(models)} models installed"}

    def chat(self, messages, model=None, temperature=0.4, max_tokens=2048, stream=False):
        if not model:
            raise ProviderError(f"No model selected for '{self.name}'. Use /model.", kind="auth")
        body = {"model": model, "messages": messages, "stream": bool(stream),
                "options": {"temperature": temperature, "num_predict": max_tokens}}
        try:
            if stream:
                resp = requests.post(f"{self.base_url}/api/chat", json=body, timeout=TIMEOUT, stream=True)
                collected = []
                for line in resp.iter_lines(decode_unicode=True):
                    if not line:
                        continue
                    try:
                        chunk = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    delta = chunk.get("message", {}).get("content", "")
                    if delta:
                        collected.append(delta)
                        print(delta, end="", flush=True)
                    if chunk.get("done"):
                        u = chunk.get("prompt_eval_count", 0), chunk.get("eval_count", 0)
                        self._usage = {"prompt_tokens": u[0], "completion_tokens": u[1]}
                print()
                return "".join(collected)
            resp = requests.post(f"{self.base_url}/api/chat", json=body, timeout=TIMEOUT)
        except requests.exceptions.RequestException as exc:
            raise ProviderError(f"Ollama server not reachable: {exc}", kind="network") from exc
        if resp.status_code >= 400:
            raise ProviderError(f"Ollama error {resp.status_code}: {resp.text[:200]}", kind="api", status=resp.status_code)
        data = resp.json()
        self._usage = {"prompt_tokens": data.get("prompt_eval_count", 0),
                       "completion_tokens": data.get("eval_count", 0)}
        return data.get("message", {}).get("content", "")


def build_provider(name, cfg):
    kind = cfg.get("kind", "openai")
    key = cfg.get("api_key_b64")
    key = base64.b64decode(key).decode() if key else None
    if kind == "gemini":
        return GeminiProvider(name, cfg["base_url"], api_key=key)
    if kind == "ollama":
        return OllamaProvider(name, cfg["base_url"])
    headers = {}
    if kind == "openrouter":
        headers = {"HTTP-Referer": "https://localhost/ultimate-ai-agent", "X-Title": "ULTIMATE AI AGENT"}
    return OpenAICompatProvider(name, cfg["base_url"], api_key=key, extra_headers=headers,
                                needs_key=kind != "local",
                                test_path=cfg.get("test_path")
                                or PROVIDER_PRESETS.get(name, {}).get("test_path", "/models"))


class ProviderManager:
    """Holds provider configs, active provider, fallback chain, session usage."""

    def __init__(self, config_dir, log_fn=None):
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.config_file = self.config_dir / "providers.json"
        self._log = log_fn or (lambda *_: None)
        self.config = self._load()
        self.last_provider = None
        self.last_usage = {}
        self.session_usage = {"prompt_tokens": 0, "completion_tokens": 0, "requests": 0,
                              "fallbacks": 0, "cost_usd": 0.0}

    # ---------------- config ----------------
    def _load(self):
        if self.config_file.exists():
            try:
                return json.loads(self.config_file.read_text())
            except Exception:
                pass
        return {"active": None, "providers": {}}

    def _save(self):
        self.config_file.write_text(json.dumps(self.config, indent=2))
        os.chmod(self.config_file, stat.S_IRUSR | stat.S_IWUSR)

    # ---------------- provider management ----------------
    def add_provider(self, name, kind, base_url=None, api_key=None, default_model=None):
        if kind not in ("openai", "gemini", "ollama", "openrouter", "local"):
            raise ValueError(f"Unknown provider kind '{kind}'.")
        preset = PROVIDER_PRESETS.get(name, {})
        cfg = {
            "kind": preset.get("kind", kind),
            "base_url": base_url or preset.get("base_url"),
            "default_model": default_model,
            "enabled": True,
        }
        if not cfg["base_url"]:
            raise ValueError(f"No base_url for provider '{name}'. Pass base_url explicitly.")
        if api_key:
            cfg["api_key_b64"] = base64.b64encode(api_key.encode()).decode()
        self.config["providers"][name] = cfg
        if not self.config.get("active"):
            self.config["active"] = name
        self._save()
        self._log("PROVIDER-ADD", name)

    def remove_provider(self, name):
        if name in self.config["providers"]:
            del self.config["providers"][name]
            if self.config.get("active") == name:
                self.config["active"] = next(iter(self.config["providers"]), None)
            self._save()

    def set_active(self, name):
        if name not in self.config["providers"]:
            raise ValueError(f"Provider '{name}' not configured. Use /provider add.")
        self.config["active"] = name
        self._save()

    def names(self):
        return list(self.config["providers"].keys())

    def active_name(self):
        return self.config.get("active")

    def _construct(self, name):
        return build_provider(name, self.config["providers"][name])

    # ---------------- compatibility interface (agent/main use this) ----------------
    @property
    def model(self):
        active = self.config.get("active")
        if not active:
            return None
        return self.config["providers"][active].get("default_model")

    def key_exists(self):
        active = self.config.get("active")
        if not active:
            return False
        cfg = self.config["providers"][active]
        if cfg.get("kind") == "ollama":
            return True
        return bool(cfg.get("api_key_b64"))

    def save_key(self, api_key):
        active = self.config.get("active")
        if not active:
            raise ProviderError("No active provider. Use /provider add first.", kind="auth")
        self.config["providers"][active]["api_key_b64"] = base64.b64encode(api_key.encode()).decode()
        self._save()

    def clear_key(self):
        active = self.config.get("active")
        if active:
            self.config["providers"][active].pop("api_key_b64", None)
            self._save()

    def load_saved_model(self):
        return self.model

    def set_model(self, model_id):
        active = self.config.get("active")
        if not active:
            raise ProviderError("No active provider.", kind="auth")
        self.config["providers"][active]["default_model"] = model_id
        self._save()

    def validate_key(self):
        return self.active().test()

    def active(self):
        name = self.config.get("active")
        if not name:
            raise ProviderError("No provider configured. Use /provider add.", kind="auth")
        return self._construct(name)

    # ---------------- chat with fallback chain ----------------
    def chat(self, messages, model=None, temperature=0.4, max_tokens=2048, stream=False):
        chain = [self.config["active"]] if self.config.get("active") else []
        chain += [n for n in self.config["providers"]
                  if n != self.config.get("active") and self.config["providers"][n].get("enabled", True)]
        if not chain:
            raise ProviderError("No provider configured. Use /provider add.", kind="auth")

        last_exc = None
        for pname in chain:
            provider = self._construct(pname)
            for attempt in range(3):
                try:
                    text = provider.chat(messages, model=model or self.config["providers"][pname].get("default_model"),
                                         temperature=temperature, max_tokens=max_tokens, stream=stream)
                    self.last_provider = pname
                    self.last_usage = provider.usage()
                    self.session_usage["requests"] += 1
                    self.session_usage["prompt_tokens"] += self.last_usage.get("prompt_tokens", 0)
                    self.session_usage["completion_tokens"] += self.last_usage.get("completion_tokens", 0)
                    self.session_usage["cost_usd"] += self._estimate_cost(pname, self.last_usage)
                    if pname != chain[0]:
                        self.session_usage["fallbacks"] += 1
                    return text
                except ProviderError as exc:
                    last_exc = exc
                    if exc.kind == "auth":
                        self._log("PROVIDER-SKIP", f"{pname}: {exc}")
                        break
                    if exc.kind in ("rate_limit", "network") or (exc.status and exc.status >= 500):
                        wait = 2 ** attempt
                        self._log("PROVIDER-RETRY", f"{pname}: {exc} (retry in {wait}s)")
                        time.sleep(wait)
                        continue
                    raise
            self._log("PROVIDER-FALLBACK", f"{pname} failed, trying next")
        raise last_exc or ProviderError("All providers failed.", kind="network")

    def _estimate_cost(self, pname, usage):
        pricing = self.config["providers"].get(pname, {}).get("pricing_per_mtok")
        if not pricing:
            return 0.0
        pt = usage.get("prompt_tokens", 0)
        ct = usage.get("completion_tokens", 0)
        return (pt * pricing.get("prompt", 0) + ct * pricing.get("completion", 0)) / 1_000_000

    def list_models(self):
        return self.active().list_models()

    # ---------------- status ----------------
    def status(self):
        return {
            "active": self.config.get("active"),
            "providers": {n: {"kind": c.get("kind"), "has_key": bool(c.get("api_key_b64")) or c.get("kind") == "ollama",
                              "model": c.get("default_model"), "base_url": c.get("base_url")}
                          for n, c in self.config["providers"].items()},
            "session_usage": self.session_usage,
        }
