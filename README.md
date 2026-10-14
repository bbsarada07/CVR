# SENTINEL

FastAPI email security agent with a provenance-enforcement policy engine. Supports Groq (default), Anthropic, and Gemini. No ORM, database, auth library, task queue, or agent framework.

## Setup

Requires Python 3.10+.

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env            # then add the real key   (Windows: copy .env.example .env)
pytest -q
uvicorn main:app --reload --port 8000
```

Open http://localhost:8000

## Configuration (`.env`)

| Variable | Default | Purpose |
|---|---|---|
| `PROVIDER` | `openai_compatible` | `openai_compatible` \| `gemini` \| `anthropic` |
| `LLM_API_KEY` | none | API key (falls back to `ANTHROPIC_API_KEY`). |
| `MODEL` | `openai/gpt-oss-120b` | Model ID. |
| `BASE_URL` | `https://api.groq.com/openai/v1` | Base URL for `openai_compatible` providers. |
| `LLM_RPM` | `25` | Max LLM requests per minute (global rate limiter). |
| `PORT` | `8000` | Port for `uvicorn --port`. |
| `ALLOWED_DOMAINS` | `northwindtraders.com,contoso-supply.com` | Comma-separated list of trusted domains. |

## Startup check and health

On boot the app checks that `LLM_API_KEY` (or `ANTHROPIC_API_KEY`) is set and makes one minimal model call (10 s timeout, no retries). If it fails, the log names the cause and the server keeps running, with a red banner at the top of the UI:

| Problem | Meaning |
|---|---|
| `missing_key` | `LLM_API_KEY` / `ANTHROPIC_API_KEY` is unset or placeholder. |
| `bad_key` | The API rejected the key (401). |
| `key_forbidden` | The key cannot use this model (403). |
| `bad_model` | The `MODEL` string is wrong (404 / 400 mentioning the model). |
| `no_network` | Connection failed or timed out. |
| `rate_limited` / `api_error` / `unexpected` | Other failures. The log has the details. |

Restart the server after fixing `.env`. The check only runs at boot.

`GET /healthz` returns:

```json
{"status": "ok", "provider": "openai_compatible", "model": "openai/gpt-oss-120b",
 "base_url": "https://api.groq.com/openai/v1", "llm_reachable": true, "uptime_s": 12.3}
```

`status` is `"degraded"` when `llm_reachable` is false.

## Tests

`pytest -q`. The tests replace all model calls with stubs, so they need neither network access nor an API key.

## Known limitations

- **Strict consequential failures are intentional.** An action at `TIER-CONSEQUENTIAL` that cannot trace all its arguments to trusted sources is blocked, not degraded. This is the correct fail-closed behaviour; the human operator resolves it out-of-band.

- **Residual risk: attacker can choose among trusted values.** If the attacker's desired value happens to appear in the user or system registry (e.g. the payment destination is a known contact), P-03/P-07 and human confirmation are the remaining controls.

- **IBAN over-match is intentional and tight.** The `_IBAN_RE` pattern can match non-IBAN strings with similar structure. It is marked `LOW` confidence when triggered by value alone (no financial key name), so the human reviewer has context. The verdict stays `BLOCK` either way.

- **Bare-domain check can block file references whose extension is also a TLD** (e.g. `invoice.zip`, `main.py` in message bodies). This fails closed, which is the correct behaviour; a reviewer can approve the action explicitly.
