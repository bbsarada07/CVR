import anthropic
import httpx
import pytest
from fastapi.testclient import TestClient

import main
from main import LLMStatus, describe_llm_error

MODEL = "claude-sonnet-5-5"
REQUEST = httpx.Request("POST", "https://api.anthropic.com/v1/messages")

HEALTHZ_REQUIRED_KEYS = {"status", "provider", "model", "base_url", "llm_reachable", "uptime_s"}


def status_error(cls, code, message):
    response = httpx.Response(code, request=REQUEST, json={"error": {"message": message}})
    return cls(message, response=response, body=None)


@pytest.fixture
def env(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test")
    monkeypatch.setenv("MODEL", MODEL)
    monkeypatch.setenv("ALLOWED_DOMAINS", "company.com, Trusted-Vendor.com")
    return monkeypatch


def make_client(monkeypatch, status=None, exc=None):
    async def fake_probe(settings):
        if exc:
            raise exc
        return status

    monkeypatch.setattr(main, "probe_llm", fake_probe)
    return TestClient(main.app)


def test_healthz_ok_when_llm_reachable(env):
    with make_client(env, LLMStatus(True)) as client:
        body = client.get("/healthz").json()
        page = client.get("/").text
    assert body["status"] == "ok"
    assert body["model"] == MODEL
    assert body["llm_reachable"] is True
    assert isinstance(body["uptime_s"], float)
    assert HEALTHZ_REQUIRED_KEYS <= set(body)
    assert 'class="banner"' not in page


def test_degraded_mode_serves_ui_with_banner(env):
    status = LLMStatus(False, "bad_model", "Model 'nope' was not found (404).")
    with make_client(env, status) as client:
        body = client.get("/healthz").json()
        page = client.get("/")
    assert body["status"] == "degraded"
    assert body["llm_reachable"] is False
    assert page.status_code == 200
    assert 'class="banner"' in page.text
    assert "bad_model" in page.text


def test_boot_survives_probe_crash(env):
    with make_client(env, exc=RuntimeError("boom")) as client:
        assert client.get("/healthz").json()["llm_reachable"] is False
        assert "Startup check crashed" in client.get("/").text


@pytest.mark.parametrize("key", ["", "   ", "sk-ant-..."])
def test_missing_or_placeholder_key_skips_network(env, key):
    env.setenv("ANTHROPIC_API_KEY", key)
    env.setenv("LLM_API_KEY", key)  # also clear the new unified key

    def no_network(*args, **kwargs):
        raise AssertionError("must not build a client without a key")

    env.setattr(anthropic, "AsyncAnthropic", no_network)
    with TestClient(main.app) as client:
        assert client.get("/healthz").json()["llm_reachable"] is False
        assert "missing_key" in client.get("/").text


def test_banner_escapes_error_text(env):
    status = LLMStatus(False, "api_error", "<script>alert(1)</script>")
    with make_client(env, status) as client:
        page = client.get("/").text
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page


def test_allowed_domains_parsed(env):
    with make_client(env, LLMStatus(True)):
        assert main.app.state.settings.allowed_domains == ("company.com", "trusted-vendor.com")


@pytest.mark.parametrize(
    "exc, problem",
    [
        (status_error(anthropic.AuthenticationError, 401, "invalid x-api-key"), "bad_key"),
        (status_error(anthropic.PermissionDeniedError, 403, "forbidden"), "key_forbidden"),
        (status_error(anthropic.NotFoundError, 404, "model: claude-nope"), "bad_model"),
        (status_error(anthropic.BadRequestError, 400, "invalid model name"), "bad_model"),
        (status_error(anthropic.BadRequestError, 400, "max_tokens too large"), "bad_request"),
        (status_error(anthropic.RateLimitError, 429, "slow down"), "rate_limited"),
        (status_error(anthropic.InternalServerError, 500, "oops"), "api_error"),
        (anthropic.APITimeoutError(request=REQUEST), "no_network"),
        (anthropic.APIConnectionError(request=REQUEST), "no_network"),
        (ValueError("weird"), "unexpected"),
    ],
)
def test_describe_llm_error(exc, problem):
    status = describe_llm_error(exc, MODEL)
    assert status.reachable is False
    assert status.problem == problem
    assert status.detail
