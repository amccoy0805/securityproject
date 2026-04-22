# Compliance mapping

> Aegis does not certify your business as compliant. It implements technical
> controls that materially help you meet GDPR, HIPAA, PCI-DSS, and SOC 2
> requirements *as they apply to AI usage*. Combine with your existing
> governance program.

## Compliance profiles shipped out of the box

| Profile | Enabled categories | Severity → action | Audit excerpts | Notes |
| --- | --- | --- | --- | --- |
| `baseline` | pii, secret, pci, phi, financial, network | low→allow, med→redact, high→block | stored | Sensible defaults for general use. |
| `gdpr` | pii, secret, financial, network | low→redact, med→redact, high→block | **not stored** | Personal data minimisation by default. |
| `hipaa` | phi, pii, secret | low→redact, med→**block**, high→**block** | **not stored** | Treats PHI/medium+ as block-or-better. |
| `pci` | pci, secret, pii | low→allow, med→redact, high→block | **not stored** | PAN/CVV never reach upstream models. |
| `secrets-only` | secret | low→allow, med→block, high→block | stored | Light profile for developer tools. |

Profiles compose with **strictest-wins** semantics. `gdpr,hipaa` is stricter
than either alone.

## GDPR (EU)

| Article / principle | How Aegis helps |
| --- | --- |
| Art. 5(1)(c) — data minimisation | `gdpr` profile redacts personal data before forwarding to AI providers. |
| Art. 25 — data protection by design | Policy is enforced *before* the call, not after; redaction is the default for personal data. |
| Art. 30 — records of processing | Append-only `audit_events` provides the audit log; categories are recorded so DPO reports can answer "what types of data have we processed via AI". |
| Art. 32 — security of processing | Bcrypt for secrets, KMS-able provider credentials, TLS, role-based access. |
| Art. 33–34 — breach notification | Audit trail enables forensic reconstruction of what data, if any, was disclosed to which third party. |
| International transfers | `model_allow` lets you restrict tenants to in-EU endpoints (Azure OpenAI EU, on-prem vLLM). |

## HIPAA (US healthcare)

| Safeguard | Control |
| --- | --- |
| Access control (§164.312(a)(1)) | Per-tenant API keys + admin/security/member roles. |
| Audit controls (§164.312(b)) | `AuditEvent` rows for every PHI-containing interaction. |
| Integrity (§164.312(c)(1)) | Append-only by convention; recommend WORM replication. |
| Person/entity authentication (§164.312(d)) | Bcrypt-hashed credentials; revocable API keys. |
| Transmission security (§164.312(e)(1)) | TLS in front of the gateway; redaction of PHI before transmission to upstream. |
| Minimum necessary | `hipaa` profile blocks PHI; only redacted text reaches AI providers. |

> **Note**: A BAA with your AI provider is still required if PHI is permitted
> to reach them. Most enterprise customers run `hipaa` to *prevent* PHI from
> reaching external providers entirely, restricting it to BAA-covered private
> deployments via `model_allow`.

## PCI-DSS

| Requirement | Control |
| --- | --- |
| 3.2 — do not store sensitive auth data | `pci` profile blocks PANs (Luhn-validated) before any storage or forwarding. |
| 3.4 — render PAN unreadable | Outbound redaction replaces PAN with `[REDACTED:PCI]` if a model returns one. |
| 8 — strong access control | API key per integration, per-user admin accounts, role separation. |
| 10 — logging and monitoring | `AuditEvent` provides per-interaction logs with timestamps, actor, decision. |

## SOC 2 (Trust Services Criteria)

| TSC | How Aegis helps |
| --- | --- |
| CC6 (logical access) | Role-based admin, revocable API keys, bcrypt password hashing. |
| CC7 (system operations) | Health endpoint, structured logs, anomaly tracking. |
| CC8 (change management) | Policies are versioned in the DB with `created_at` / `updated_at`; profile composition is deterministic and auditable. |
| C1 (confidentiality) | Redaction of secrets/PII; per-tenant credential isolation. |
| P (privacy) | GDPR/HIPAA profiles, configurable retention via `store_request_excerpts`. |

## Customising

You can build your own profile by adding an entry to
`aegis/policy/profiles.py`. Categories, severity actions, and model lists are
all data — no code changes are required to ship a tenant-specific profile in
the `policies` table.
