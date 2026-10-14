"""Single LLM abstraction. Every agent calls llm.complete(); no agent imports a provider SDK.

Providers (PROVIDER env var):
  openai_compatible  OpenAI-compatible API (default; works with Groq, Together, local Ollama)
  gemini             Google Gen AI SDK
  anthropic          Anthropic SDK

Rate limiting: a global sliding-window cap at LLM_RPM requests per minute (default 25)
prevents bursting against free-tier rate limits during the benchmark.

Retries: 429 and 503 both get exponential backoff (1s, 2s, 4s) up to 3 attempts total.
"""

from __future__ import annotations

import logging
import os
import re
import threading
import time
from typing import Optional

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

log = logging.getLogger("llm")

# ---------------------------------------------------------------------------
# Environment config (resolved once at import time)
# ---------------------------------------------------------------------------

PROVIDER: str = os.getenv("PROVIDER", "openai_compatible")
LLM_API_KEY: str = os.getenv("LLM_API_KEY", "").strip() or os.getenv("ANTHROPIC_API_KEY", "").strip()
MODEL: str = os.getenv("MODEL", "openai/gpt-oss-120b").strip()
BASE_URL: str = os.getenv("BASE_URL", "https://api.groq.com/openai/v1").strip()
LLM_RPM: int = max(1, int(os.getenv("LLM_RPM", "25") or "25"))

# ---------------------------------------------------------------------------
# Global rate limiter (sliding window)
# ---------------------------------------------------------------------------

_rpm_lock = threading.Lock()
_call_times: list[float] = []


def _rate_limit() -> None:
    """Block until sending another request is within the LLM_RPM budget."""
    while True:
        with _rpm_lock:
            now = time.monotonic()
            cutoff = now - 60.0
            # drop timestamps older than 1 minute
            while _call_times and _call_times[0] < cutoff:
                _call_times.pop(0)
            if len(_call_times) < LLM_RPM:
                _call_times.append(now)
                return
            wait_until = _call_times[0] + 60.0
        wait = max(0.0, wait_until - time.monotonic())
        log.info("Rate limit: %d/%d RPM used; sleeping %.1fs", len(_call_times), LLM_RPM, wait)
        time.sleep(wait + 0.05)


# ---------------------------------------------------------------------------
# JSON-fence stripping
# ---------------------------------------------------------------------------

_FENCE_RE = re.compile(r"^```(?:json)?\s*\n?(.*?)\n?```\s*$", re.DOTALL)


def _strip_fences(text: str) -> str:
    text = text.strip()
    m = _FENCE_RE.match(text)
    return m.group(1).strip() if m else text


# ---------------------------------------------------------------------------
# Status-code extraction (provider-agnostic)
# ---------------------------------------------------------------------------

def _status_code(exc: Exception) -> Optional[int]:
    """Extract HTTP status code from provider exceptions without importing their modules."""
    # Most providers store it in .status_code or .code
    for attr in ("status_code", "code", "http_status"):
        val = getattr(exc, attr, None)
        if isinstance(val, int):
            return val
    # openai wraps it in the message string "Error code: 429 - ..."
    msg = str(exc)
    m = re.search(r"\b(429|503)\b", msg)
    return int(m.group(1)) if m else None


# ---------------------------------------------------------------------------
# Provider implementations
# ---------------------------------------------------------------------------

def _call_openai_compatible(system: str, user: str, json_schema: Optional[dict]) -> str:
    from openai import OpenAI  # lazy import so other providers don't pay for it
    api_key = (
        os.getenv("LLM_API_KEY", "").strip()
        or os.getenv("OPENAI_API_KEY", "").strip()
        or os.getenv("ANTHROPIC_API_KEY", "").strip()
        or LLM_API_KEY
    )
    base_url = os.getenv("BASE_URL", "").strip() or BASE_URL
    model = os.getenv("MODEL", "").strip() or MODEL
    client = OpenAI(api_key=api_key, base_url=base_url)
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]
    kwargs: dict = {"model": model, "messages": messages}
    if json_schema is not None:
        kwargs["response_format"] = {"type": "json_object"}
    resp = client.chat.completions.create(**kwargs)
    return resp.choices[0].message.content or ""


def _call_gemini(system: str, user: str, json_schema: Optional[dict]) -> str:
    from google import genai  # type: ignore[import]
    from google.genai import types as gtypes
    model = MODEL if MODEL and MODEL != "openai/gpt-oss-120b" else "gemini-flash-latest"
    client = genai.Client(api_key=LLM_API_KEY)
    config_kwargs: dict = {}
    if json_schema is not None:
        config_kwargs["response_mime_type"] = "application/json"
    prompt = f"{system}\n\n{user}"
    resp = client.models.generate_content(
        model=model,
        contents=prompt,
        config=gtypes.GenerateContentConfig(**config_kwargs) if config_kwargs else None,
    )
    return resp.text or ""


def _call_anthropic(system: str, user: str, json_schema: Optional[dict]) -> str:
    import anthropic  # type: ignore[import]
    model = MODEL if MODEL and MODEL != "openai/gpt-oss-120b" else "claude-sonnet-5-5"
    client = anthropic.Anthropic(api_key=LLM_API_KEY)
    extra: dict = {}
    if json_schema is not None:
        extra["betas"] = ["json-object-2024-09-12"]
    msg = client.messages.create(
        model=model,
        max_tokens=4096,
        system=system,
        messages=[{"role": "user", "content": user}],
        **extra,
    )
    return msg.content[0].text if msg.content else ""


_PROVIDERS: dict[str, object] = {
    "openai_compatible": _call_openai_compatible,
    "gemini": _call_gemini,
    "anthropic": _call_anthropic,
}

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def complete(system: str, user: str, json_schema: Optional[dict] = None) -> str:
    """Call the configured LLM. Blocks for rate limiting; retries on 429/503."""
    _rate_limit()
    fn = _PROVIDERS.get(PROVIDER)
    if fn is None:
        raise ValueError(f"Unknown PROVIDER={PROVIDER!r}. Choose: {list(_PROVIDERS)}")
    max_attempts = 3
    for attempt in range(max_attempts):
        try:
            result = fn(system, user, json_schema)  # type: ignore[operator]
            return _strip_fences(result)
        except Exception as exc:
            code = _status_code(exc)
            if code in (429, 503) and attempt < max_attempts - 1:
                wait = 2 ** attempt
                log.warning(
                    "LLM returned %s; retrying in %ds (attempt %d/%d)",
                    code, wait, attempt + 1, max_attempts,
                )
                time.sleep(wait)
            else:
                raise
    raise RuntimeError("complete() exited retry loop without returning")  # unreachable
