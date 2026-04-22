# Spec audit — Aegis vs. "trust layer for agentic AI"

This is an honest, line-by-line audit of Aegis against the
"McAfee for AI" trust-layer spec, with the gaps closed in this
revision flagged ✅ NEW. Read this with [`agent-safety.md`](agent-safety.md)
for the deep dive on each layer and [`compliance.md`](compliance.md) for
GDPR/HIPAA/PCI mapping.

## Capability matrix

| # | Spec capability | Status | Where it lives |
|---|---|---|---|
| 1 | **Agent discovery & inventory** | ✅ NEW | `aegis/safety/agents.py` (auto-discovers from `X-Aegis-Agent` header or `(api_key, model)` tuple); `models.Agent`; admin `GET/PATCH /admin/api/agents`. The aegis envelope on every response carries the agent id/name/kind/autonomy. |
| 2 | **Risk scoring** | ✅ NEW | `compute_risk` + `fold_observation` produce a transparent 0–100 score with named factors (`autonomy`, `data`, `injection`, `tool_breadth`, `financial`, `destructive`, `external_input`). Per-agent score updates after every request. |
| 3 | **Prompt-injection defense** | ✅ | `aegis/policy/injection.py` — instruction-override / role-hijack / exfil / hidden Unicode / data-URIs / malicious scripts / shorteners / IDN-and-typo lookalike (`is_lookalike`). The `<aegis:untrusted>` channel auto-elevates everything inside scraped content to HIGH. Runs inbound and outbound. |
| 4 | **Sensitive data detection** | ✅ | `aegis/policy/detectors.py` — PII / PHI / PCI (Luhn) / SSN (validated) / IBAN / AWS / GitHub / OpenAI / Slack tokens / JWTs / private keys / MRNs / DOBs. Inbound + outbound. |
| 5 | **Policy engine (rules)** | ✅ NEW | `aegis/policy/rules.py` — human-readable rule kinds: `never_send_money`, `require_approval_for`, `never_share`, `block_weekends`, `business_hours_only`, `no_external_input_for_destructive`. Rules compose strictest-wins; consumer profile ships sensible defaults. |
| 6 | **Action approval workflow (HITL)** | ✅ NEW | `aegis/safety/approvals.py` + `models.PendingApproval`. Sensitive tool calls (without `X-Aegis-Approve-Action: 1`) generate a ticket; admin queue at `GET/POST /admin/api/approvals`; agent re-submits with `X-Aegis-Approval-Ticket: <id>`; tickets are single-use, time-boxed, and tool-bound. |
| 7 | **Sandboxed execution** | ⚠️ partial | Aegis is a policy point, not a runtime. We mark tools `sandbox_required` (per tool config or via tenant `require_sandbox_class`) and **refuse to relay** the call until the orchestrator marks the args with `_sandbox: true`. Pair with your existing sandbox runtime; we provide the *enforcement* hook. |
| 8 | **OAuth & credential vaulting** | ✅ NEW | `aegis/safety/vault.py` + `models.ToolCredential`. Per-tenant secrets stored as authenticated, nonce-fresh ciphertext (Fernet-style HMAC-SHA-256 stream cipher, keyed off `AEGIS_VAULT_KEY`); per-credential `scopes`, `expires_at`, `rotation_period_days`, `last_used_at`, instant `revoke`. Production should swap `encrypt`/`decrypt` for KMS envelope encryption — the interface is one file. |
| 9 | **Audit logs** | ✅ NEW (hash chain) | `aegis/audit.py`: every row carries `prev_hash` + `this_hash` over a canonical payload. `verify_chain()` re-walks the log; admin `GET /admin/api/audit/verify`. Combine with WORM replication for full tamper-resistance. |
| 10 | **Memory protection** | ✅ NEW | `ActionClass.MEMORY_WRITE` + memory keyword set (`remember`, `store_memory`, `memorize`, …). Memory writes are in `require_approval_for` by default — a poisoned model can't silently persist a memory without a human checkpoint. |
| 11 | **Exfiltration prevention** | ✅ | Outbound markdown-image-exfil and shortener detectors; URL safety on tool args blocks SSRF; tool-arg scanner pulls URLs out of nested dicts; **lookalike-domain** detection (homoglyph + Levenshtein) catches spoofed brand exfil. |
| 12 | **Brand & fraud protection** | ✅ NEW | `models.ProtectedDomain` + admin `GET/POST/DELETE /admin/api/protected-domains`. The URL-safety inspector blocks any tool argument whose host is a homoglyph/typo lookalike of a protected brand (e.g. `g00gle.com`, `goog1e.com`, `аpple.com`). |

## B2C: safe-by-default for individuals

The new `consumer` compliance profile is preconfigured for an everyday user:

- Severity → action mapping is `low → redact, medium → redact, high → block` (anything sensitive is at minimum redacted).
- Audit excerpts are **not** stored (privacy by default).
- The bundled rule pack is auto-applied if the tenant has no custom rules:
  - `Never send money` (blocks any `financial` tool call).
  - `Require approval for email sends` (write/send_email/send_message/send_sms).
  - `No destructive actions from scraped content` (untrusted + destructive = block).
  - `Never share secrets / PCI / PHI` (blocks responses that would leak those).
- Every response includes a plain-English **`aegis.verdict`**:
  - `level`: `ok | warning | blocked | error`
  - `headline`: e.g. *"We removed sensitive details before sending this to the AI."*
  - `severity` and a short `details` list of detector names.

A consumer-facing app (browser ext / desktop / mobile) only needs to render this object — no understanding of prompt injection or model internals required.

## B2B: governed agent operations

For enterprise installs, the same control plane gives the security team:

- **Centralised inventory** of every agent (auto-discovered from gateway traffic, no manual onboarding).
- **Per-agent risk score** with named factors so reviewers can act on it.
- **Tool registry + schema-hash** for supply-chain protection.
- **OAuth / credential vault** with scope minimisation, rotation reminders, instant revoke.
- **Async approval queue** for sensitive actions (HITL even when humans are on a different schedule than the agent).
- **Tamper-evident audit chain** for compliance evidence.
- **CIDR allowlist + first-seen-IP pin** on API keys for credential-theft resistance.
- **Compliance profiles** that map to GDPR / HIPAA / PCI / SOC 2.

SAML / OIDC SSO and SCIM provisioning are tracked in `docs/roadmap.md`.

## Differentiators delivered today

> *"The winning product would not just detect threats; it would make agents
> usable by ordinary people without requiring them to understand prompt
> injection or model internals."*

Concretely, this revision puts those user-visible primitives in the box:

- **Plain-English verdicts** in every response.
- **Default rules** that protect the everyday user (no money, no destructive scrapes, no secret sharing) without configuration.
- **One-click async approval** — when something risky is queued, the user sees a single ticket with a summary, not a stack trace.
- **Lookalike protection** — a request to `g00gle.com` looks identical to one to `google.com` to a human; Aegis catches it.

## What's still out of scope (deliberately)

- Aegis is a **gateway**, not a sandbox runtime, browser, or email client.
  Our job is to be the policy point and audit ground-truth.
- Aegis does not maintain its own LLM. All inference is delegated to whatever
  upstream the tenant configures.
- "Brand fraud detection" today is lookalike + domain-deny; ML-based
  account-takeover signals are upstream concerns we'd integrate with via
  the same audit JSON.

## What's on the explicit roadmap

See `docs/roadmap.md`. Highlights:

- Tool-call arg validation against the registered JSON Schema (we hash today).
- Streaming SSE responses + streaming output redaction.
- Distributed budgets/loops via Redis.
- SAML / OIDC SSO + SCIM provisioning for B2B.
- KMS-backed envelope encryption for the vault and provider credentials.
- ML-based detector slot for paraphrased / multi-language injection.
