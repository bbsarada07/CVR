"""Runtime settings, read once from the environment (.env is loaded by main.py)."""

import os
from dataclasses import dataclass, field

DEFAULT_MODEL = "openai/gpt-oss-120b"
PLACEHOLDER_KEY = "sk-ant-..."


@dataclass(frozen=True)
class Settings:
    api_key: str
    model: str
    port: int
    allowed_domains: tuple[str, ...]
    provider: str = "openai_compatible"
    base_url: str = "https://api.groq.com/openai/v1"
    llm_rpm: int = 25

    @property
    def has_api_key(self) -> bool:
        key = self.api_key.strip()
        return bool(key) and key != PLACEHOLDER_KEY


def load_settings() -> Settings:
    raw_domains = os.getenv("ALLOWED_DOMAINS", "")
    domains = tuple(d.strip().lower() for d in raw_domains.split(",") if d.strip())
    try:
        port = int(os.getenv("PORT", "8000"))
    except ValueError:
        port = 8000
    try:
        llm_rpm = int(os.getenv("LLM_RPM", "25"))
    except ValueError:
        llm_rpm = 25
    # Support both new LLM_API_KEY and legacy ANTHROPIC_API_KEY
    api_key = os.getenv("LLM_API_KEY", "").strip() or os.getenv("ANTHROPIC_API_KEY", "").strip()
    return Settings(
        api_key=api_key,
        model=os.getenv("MODEL", "").strip() or DEFAULT_MODEL,
        port=port,
        allowed_domains=domains,
        provider=os.getenv("PROVIDER", "openai_compatible").strip(),
        base_url=os.getenv("BASE_URL", "https://api.groq.com/openai/v1").strip(),
        llm_rpm=llm_rpm,
    )
