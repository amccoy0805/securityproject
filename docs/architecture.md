# Aegis Architecture

## Why a gateway, not a library?

The original brief was: *"You cannot rely on generic hooks for all tools.
Instead, you need to enforce a controlled interface layer."*

Aegis follows that principle literally. Every AI interaction — whether it's a
SaaS chatbot, an internal copilot, a developer using Cursor, or a backend
service calling Anthropic — is forced through a single mediation point:

```
┌────────────────────────┐         ┌──────────────────────────┐         ┌─────────────────┐
│ App / IDE / CLI / CI   │ ──────▶ │ Aegis Gateway (this repo)│ ──────▶ │ OpenAI/Anthropic│
│                        │         │                          │         │ /vLLM/Azure/... │
│  optional: endpoint    │         │  - authn (aeg_… keys)    │         └─────────────────┘
│  agent on laptop       │         │  - tenant resolve        │
└────────────────────────┘         │  - policy evaluation     │
                                   │  - redaction (in/out)    │
                                   │  - audit log (append)    │
                                   │  - anomaly tracking      │
                                   └──────────────────────────┘
```

This is the only architecture that gives a defensible answer to:

- *"Can you prove no PHI ever left our network?"* — yes, the audit log is the
  ground truth and it is the *only* path traffic could have taken.
- *"What models are we paying for?"* — the gateway sees every request.
- *"Can a developer hit ChatGPT with a customer's credit card number?"* — no,
  the regex + Luhn-validated PCI detector blocks it before the upstream call.

## Components

### `aegis/policy/`

Pure-Python, no I/O. The decisioning core.

- `detectors.py` — pluggable detectors that scan text and emit `Finding`s with
  spans, severities, categories, and tags. Easy to extend with ML-based
  detectors (Presidio, internal classifiers) without touching the engine.
- `profiles.py` — built-in compliance profiles (`gdpr`, `hipaa`, `pci`, …).
  Profiles compose with **strictest-wins** semantics so combining `gdpr+hipaa`
  always tightens, never loosens.
- `engine.py` — `evaluate_inbound` (per-request) and `apply_outbound`
  (per-response) primitives plus `effective_spec()` to merge profiles +
  tenant overrides into one `PolicySpec`.

### `aegis/providers/`

Adapter interface (`base.py`) and per-provider implementations (`openai.py`,
`anthropic.py`). An adapter knows how to:

1. Extract plain text from a request body so the policy engine can scan it.
2. Rewrite the body with the redacted text after a `REDACT` decision.
3. Forward to the upstream API with the tenant's real key.
4. Pull the assistant text out of the response so it can be re-scanned.

Adding a new provider is a matter of writing one adapter class and registering
it.

### `aegis/routes/proxy.py`

The single AI proxy router. It is OpenAI-compatible at `/v1/chat/completions`,
`/v1/embeddings`, `/v1/responses`, and Anthropic-compatible at `/v1/messages`,
so existing customer code can be re-pointed by changing only the base URL and
API key.

The flow per request:

1. Authenticate Aegis API key → resolve tenant.
2. Resolve effective `PolicySpec` (compliance profiles + tenant policies).
3. Adapter extracts text + model.
4. `evaluate_inbound` → `ALLOW` / `REDACT` / `BLOCK`.
5. If allowed/redacted, forward to upstream.
6. `apply_outbound` re-scans the response and redacts if needed.
7. Append `AuditEvent` row + update anomaly tracker.
8. Return upstream body **plus an `aegis` envelope** describing the decision
   so SDK callers can act on it.

### `aegis/routes/admin_api.py` + `admin_ui.py`

Tenant admin REST API (used by the bundled console and any custom dashboards)
and a server-rendered admin console with:

- Overview / API key management
- Provider credential storage (per tenant — never exposed in API responses)
- Audit log browser with per-event detail
- Policy playground (dry-run text against the live policy)

### `aegis/models.py`

SQLAlchemy schema:

- `tenants`, `users`, `api_keys` — multi-tenant identity.
- `provider_credentials` — upstream API keys, per tenant.
- `policies` — tenant-specific policy overrides on top of compliance profiles.
- `audit_events` — append-only event log. In production, replicate to an
  immutable WORM store (S3 Object Lock, AWS QLDB, immudb).

### `agent/aegis_agent.py`

A standalone local proxy users run on laptops or CI workers. It exposes the
same OpenAI-compatible surface on `127.0.0.1:11434` and forwards everything
through the corporate Aegis gateway. This is the deployment story for tools
that read `OPENAI_BASE_URL` (Cursor, ContinueDev, openai-cli, etc.) without
requiring app code changes.

### `sdk/aegis_client/`

Thin synchronous SDK exposing `chat`, `messages`, `check`, `my_policy`. For
most enterprise apps the right move is still pointing the **official**
provider SDK at the gateway and using an `aeg_…` key — that needs zero new
dependencies.

## Trust boundaries

```
trusted ──────────────────────────────────────────────────────── untrusted
        │                                                       │
        │  Aegis DB (tenants, policies, creds, audit)           │
        │  Aegis process (decisioning, audit writes)            │
        │   ↑                                                   │
        │   │ TLS, mutual auth in front (recommended)           │
        │   │                                                   │
        │  Customer apps                                        │
        │  Endpoint agent on developer laptop                   │
        │                                                       │
        ──────────────────── network egress ─────────────────────
                                                                │
                                              OpenAI / Anthropic / vLLM
```

- Aegis only forwards bodies *after* policy evaluation. The redacted body is
  what hits the upstream — original text never leaves the gateway when the
  decision is `REDACT`.
- Upstream API keys never leave the gateway. Customers get `aeg_…` keys,
  which the gateway translates to the real upstream credentials.
- Audit excerpts can be disabled per profile (HIPAA/GDPR/PCI default to `off`)
  so regulated payloads never sit at rest in the audit table.
