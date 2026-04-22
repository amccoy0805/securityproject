# Roadmap

This MVP is intentionally small but complete: it can be deployed today and
will enforce real policy on real AI traffic. The items below describe the
direction for hardening it into the SaaS you'd sell to regulated enterprises.

## Near-term

- **Streaming responses (SSE)** for `/v1/chat/completions` so latency parity
  with raw OpenAI is preserved. Outbound redaction becomes a streaming
  scanner.
- **ML-based detectors** plugged in alongside the regex detectors:
  - [Microsoft Presidio](https://github.com/microsoft/presidio) for
    multilingual PII.
  - LLM-judge classifier for prompt-injection signals that regex can't catch
    (paraphrased "ignore" instructions, multi-language jailbreaks).
  - In-house classifier for industry-specific PHI / IP terms.
- **Tool-call allow-list**: when a request uses OpenAI/Anthropic tool calls,
  enforce a tenant-defined whitelist of permitted tool names + argument
  schemas. Blocks an injected page from telling the agent to call
  `delete_files()`.
- **Distributed budget store**: swap the in-memory `BudgetEnforcer` for Redis
  so multi-replica deployments share counters in real time.
- **Cost reconciliation**: post-process upstream `usage` fields to replace
  estimates with billing-grade actuals before they hit budgets.
- **SSO**: SAML + OIDC for the admin console, SCIM for user provisioning.
- **Postgres migrations** via Alembic.
- **KMS-wrapped provider credentials** (AWS KMS / GCP KMS / HashiCorp Vault).

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
