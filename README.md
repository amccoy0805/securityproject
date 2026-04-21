# Aegis AI Gateway

> **Antivirus for AI usage in the enterprise.**
> A self-hosted security and compliance layer that mediates every AI call your
> employees and applications make — to OpenAI, Anthropic, Azure OpenAI, internal
> models, and any OpenAI-compatible endpoint.

Aegis is the SaaS that businesses purchase so their workforce can use AI tools
(ChatGPT, Claude, Cursor, OpenCLaw, internal copilots) **without** leaking PII,
PHI, secrets, IP, or violating GDPR / HIPAA / PCI / SOC 2.

It is designed to be the **mandatory gateway** through which all AI traffic
flows, providing a single audit trail, a single policy regime, and a single
identity model regardless of upstream provider or downstream tool.

---

## What it does

| Pillar | What Aegis enforces |
| --- | --- |
| **Data classification** | Detects PII, PHI, PCI, secrets, credentials, internal tokens in every prompt and every response. |
| **Policy as code** | Composable compliance profiles (`baseline`, `gdpr`, `hipaa`, `pci`, `secrets-only`) plus tenant-specific overrides — severity-based `allow / redact / block`. |
| **Mediated access** | All AI traffic flows through one proxy. Per-tenant API keys; per-tenant upstream credentials so end users never see raw OpenAI/Anthropic keys. |
| **Tamper-evident audit** | Append-only event log of who asked what, which model answered, what was redacted, latency, sizes — built for SIEM ingest. |
| **Anomaly signal** | Sliding-window block-rate tracking to surface compromised users or runaway integrations. |
| **Provider-agnostic** | OpenAI, Anthropic, Azure OpenAI, vLLM, Ollama, internal endpoints — one SDK, one policy. |
| **Endpoint agent** | Lightweight local proxy for laptops/CI so developer tools (Cursor, OpenCLaw, raw `curl`) hit the gateway by changing only `OPENAI_BASE_URL`. |

See [`docs/architecture.md`](docs/architecture.md) for the design rationale and
[`docs/compliance.md`](docs/compliance.md) for how Aegis maps to GDPR/HIPAA/PCI.

---

## Quickstart

```bash
git clone <this-repo>
cd securityproject
cp .env.example .env
# edit .env — at minimum set AEGIS_SECRET_KEY and AEGIS_BOOTSTRAP_ADMIN_PASSWORD

python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

uvicorn aegis.main:app --host 0.0.0.0 --port 8080 --reload
```

Open `http://localhost:8080/`, sign in with the bootstrap admin credentials,
and:

1. Add an upstream provider credential (your real OpenAI / Anthropic key).
2. Generate an Aegis API key (`aeg_live_…`). **Save it** — you'll only see it once.
3. Optionally tighten the tenant's compliance profile (`gdpr`, `hipaa`, …).
4. Use the **Playground** to try sample prompts and see decisions live.

### Drop-in OpenAI usage

```python
from openai import OpenAI

client = OpenAI(
    base_url="https://aegis.your-company.com/v1",
    api_key="aeg_live_xxxxxxxx.xxxxxxxxxxxxxxxxxxxxxxxx",
)
client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Hello"}],
)
```

### Anthropic usage (drop-in)

```python
import anthropic
client = anthropic.Anthropic(
    base_url="https://aegis.your-company.com",  # native /v1/messages route
    api_key="aeg_live_…",
)
```

### Endpoint agent (laptops / CI)

```bash
python agent/aegis_agent.py --gateway https://aegis.example.com --api-key aeg_live_… --port 11434
export OPENAI_BASE_URL=http://127.0.0.1:11434/v1
export OPENAI_API_KEY=anything   # ignored by the agent; gateway uses the real key
```

---

## Run with Docker

```bash
docker compose up --build
```

The gateway listens on `:8080`. Persistent state lives in `./data` and audit
logs in `./logs`.

---

## Tests

```bash
pip install -r requirements-dev.txt
pytest -q
```

---

## Repository layout

```
aegis/                  # FastAPI gateway service (the SaaS)
  policy/               # Detection, redaction, compliance profiles, decisioning
  providers/            # OpenAI / Anthropic adapters + registry
  routes/               # /v1/* proxy + /admin/api/* + /admin/* UI
  templates/            # Server-rendered admin console
sdk/aegis_client/       # Python SDK
agent/aegis_agent.py    # Local endpoint agent
tests/                  # Unit + integration tests
docs/                   # Architecture, security, compliance, ops
```

---

## Roadmap

The current implementation is a complete, runnable MVP. See
[`docs/roadmap.md`](docs/roadmap.md) for the path to:

- Postgres + KMS-encrypted credential storage
- Streaming response support (SSE)
- ML-based detection (Microsoft Presidio, internal classifiers)
- SAML / OIDC SSO + SCIM provisioning
- Per-user / per-group quotas and budgets
- Tamper-evident WORM audit storage
- SOC 2 Type II evidence pack
