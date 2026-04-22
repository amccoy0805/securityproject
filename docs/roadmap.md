# Roadmap

This MVP is intentionally small but complete: it can be deployed today and
will enforce real policy on real AI traffic. The items below describe the
direction for hardening it into the SaaS you'd sell to regulated enterprises.

## Done in the most recent revision

- ✅ **Tool-arg JSON-Schema validation** (`aegis/safety/schema_validate.py`):
  registered tool schemas are stored, and every model-emitted call has its
  args validated against `parameters` / `input_schema`. Malformed or
  schema-violating calls are stripped from the response with a structured
  reason.
- ✅ **Cost reconciliation** (`aegis/pricing.py::cost_from_usage`): the
  proxy reads upstream `usage` (OpenAI prompt/completion or Anthropic
  input/output tokens) and uses the reconciled USD figure for budget
  commits and the audit log; pre-flight checks still use the conservative
  estimate. Both numbers + the cost source land in the response envelope
  (`aegis.usage.{estimated_cost_usd, reconciled_cost_usd, cost_source, tokens}`).
- ✅ **LLM-judge detector slot** (`aegis/policy/llm_judge.py`): opt-in,
  bounded (input/output char budget, timeout), tenant-overridable model.
  A positive verdict above threshold becomes a HIGH-severity injection
  finding; a judge crash is a soft-fail recorded in the envelope.
- ✅ **Distributed budget + loop store** (`aegis/safety/redis_backend.py`):
  set `AEGIS_REDIS_URL` to share state across replicas; falls back to the
  in-memory implementation automatically.
- ✅ **Streaming SSE responses** (`aegis/policy/streaming.py`): the gateway
  forwards SSE end-to-end with an incremental output redactor whose sliding
  buffer catches secrets that straddle chunk boundaries. Reconciled cost,
  audit, agent risk update, and budget commit all happen on stream-end.

## Still on the explicit roadmap

- **ML-based detectors** plugged in alongside the regex detectors:
  - [Microsoft Presidio](https://github.com/microsoft/presidio) for
    multilingual PII.
  - In-house classifier for industry-specific PHI / IP terms.
  (The LLM-judge slot is the bridge until these land.)
- **Streaming for Anthropic `/v1/messages`** — today we stream OpenAI-shaped
  SSE; Anthropic's `event:` / nested-block format needs its own adapter.
- **SSO**: SAML + OIDC for the admin console, SCIM for user provisioning.
- **Postgres migrations** via Alembic.
- **KMS-wrapped envelope encryption** for the tool-credential vault and
  upstream provider credentials (AWS KMS / GCP KMS / HashiCorp Vault). The
  `aegis/safety/vault.py` interface is intentionally narrow so this swap
  is one file.

## Mid-term

- **Tamper-evident audit storage** — write `audit_events` to an immutable
  store (S3 Object Lock / QLDB / immudb) in addition to Postgres.
- **Anthropic / OpenAI tool-use schema awareness** — scan tool arguments and
  tool results, not just the freeform text.
- **File and embedding scans** — Aegis already proxies `/v1/embeddings`;
  extend with file upload + chunked scanning so RAG ingestion goes through
  the same controls.
- **Policy testing UI** — golden-set replay so security teams can verify
  policy changes before rolling them out.
- **DLP integrations** — forward findings to Symantec / Forcepoint / etc. for
  unified incident handling.

## Long-term

- **Per-org private model routing** — declarative routing so a `hipaa` tenant
  automatically lands on Azure OpenAI in their own subscription.
- **Just-in-time access** — temporary unlock of high-severity categories with
  an approval workflow and a time-bound reason recorded in the audit log.
- **SOC 2 Type II evidence pack** — automated control coverage reports.
- **Fine-grained user attribution** via SSO claims so audit shows
  `alice@acme.com` rather than `aeg_…` API keys.
- **Egress proof** — opt-in mTLS / IP allow-list per provider, with
  certificate pinning, so customers can prove that no other endpoint can
  reach their AI providers.
