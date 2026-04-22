# Agent safety: injection, loops, budgets, tools, actions, and identity

This document is the comprehensive reference for the agent-safety controls
Aegis ships. It maps directly to the everyday-user risk model (loss of
control, data leakage, unintended actions) and covers six layers — every one
runs on every request and writes a row to the audit log.

This document covers the controls Aegis ships specifically for **autonomous
agents** (OpenCLaw / OpenDevin / LangChain / custom orchestrators) and
**RAG / browsing assistants** that consume scraped content.

These are layered on top of the data-leak controls in
[`compliance.md`](compliance.md): all four layers run on every request.

## 1. Indirect prompt-injection from scraped pages

The risk: an attacker plants instructions inside a webpage. When your agent
fetches that page and feeds it back to the LLM, the model treats those
instructions as authoritative and may leak data, call tools, or act
maliciously on the user's behalf.

What Aegis detects (every prompt and every response):

| Detector | What it catches |
| --- | --- |
| `instruction_override` | "ignore previous/all instructions", "disregard…", "from now on you are…", "act as DAN/jailbroken", "enable developer mode" |
| `role_hijack` | Forged system tags: `<\|system\|>`, `[system]`, `<<SYS>>`, `### system prompt`, `system:`, etc. |
| `tool_or_secret_request` | "reveal/print the system prompt", "show me your hidden instructions", "what were your original rules" |
| `credential_harvest` | "send/email/post the API key/password/token to …" |
| `markdown_image_exfil` | `![](https://attacker/?leak=…)` — renderers GET the URL, exfiltrating context |
| `markdown_link_query_exfil` | `[click](https://x/page?ref=…)` — same trick via clickable links |
| `data_uri_payload` | `data:` URIs that smuggle base64 / JS payloads |
| `html_script_block`, `hidden_html_comment_instruction` | Malicious `<script>` and HTML comments hiding instructions |
| `invisible_zero_width`, `invisible_tagged_unicode` | Zero-width / Unicode tag stego (`U+E0000–U+E007F`); these are *stripped* from the forwarded text and recorded as findings |
| `url_shortener` | bit.ly / t.co / etc. — low-severity heads-up |

### How to mark scraped content as untrusted

When your agent passes scraped/retrieved text to the LLM, wrap it in a
`<aegis:untrusted>…</aegis:untrusted>` block (or send the whole request with
the header `X-Aegis-Untrusted: 1`). Inside an untrusted region, **every
injection finding is elevated to HIGH severity** and the `baseline` profile
will block the request.

The Python SDK has helpers so you don't need to remember:

```python
from aegis_client import AegisClient, quote_scraped

scraped = fetch_html("https://random-site.example/article")
prompt = (
    "Summarise this article:\n\n"
    + quote_scraped("https://random-site.example/article", scraped)
)

client = AegisClient("https://aegis.example.com", "aeg_live_…")
client.chat(model="gpt-4o-mini", messages=[{"role": "user", "content": prompt}])
```

If your agent forgets the wrapper, the detectors still run — they just won't
auto-elevate, and you'll see the findings in the audit log so a security
admin can tighten the per-tenant policy.

## 2. Runaway loops

The risk: a buggy agent loop sends the same prompt 50 times in a minute. The
upstream provider happily charges for all 50.

Aegis ships a per-(tenant, API key) loop detector with a default of
**8 identical prompts within 120 seconds**. Whitespace is normalised and the
model name is part of the digest, so trivial differences still cluster.

When the threshold is hit:

```http
HTTP/1.1 429 Too Many Requests
Content-Type: application/json

{
  "error": {
    "type": "runaway_loop_blocked",
    "message": "This API key has sent the same request 8 times in the last 120s — possible runaway loop.",
    "request_id": "…",
    "override": "To proceed anyway, retry with header `X-Aegis-Override-Loop: 1`. The override is recorded in the audit log alongside the original block.",
    "snapshot": { "repeat_count": 8, "digest": "abc123..." }
  }
}
```

Both the block **and** any subsequent override are written to the audit log,
so a security admin can spot a developer who is routinely silencing the
canary.

You can tune `loop_threshold` and `loop_window_seconds` per tenant via a
`policies` row spec.

## 3. Budgets — the OpenCLaw scenario

The risk you described: a customer builds an OpenCLaw bot, forgets a
guardrail, and runs up real money before they notice.

Aegis enforces sliding-window budgets per API key **and** per tenant on:

- **request count** (e.g. 120 / minute / key)
- **input characters** (token-budget proxy)
- **output characters**
- **estimated USD** (using the per-model price table in `aegis/pricing.py`)

Defaults (always on, even if the customer hasn't configured anything):

| Scope | Window | Limit |
| --- | --- | --- |
| Per key | 1 minute | 120 requests |
| Per key | 5 minutes | $25 estimated |
| Per key | 1 hour | 2,000 requests / $100 |
| Per tenant | 5 minutes | $100 |
| Per tenant | 24 hours | $2,500 |

When a request *would* push any window over its cap, Aegis returns:

```json
{
  "error": {
    "type": "budget_exceeded",
    "message": "Budget exceeded: key/5min/$: $25.40/25.00 estimated",
    "override": "To proceed anyway, retry with header `X-Aegis-Override-Budget: 1` …",
    "snapshot": { "key:key/5min/$": { "cost_usd": 25.4, "limit_usd": 25.0, … } }
  }
}
```

Tighter or looser per-tenant budgets can be set with a policy row:

```json
{
  "name": "tight-budget",
  "spec": {
    "budgets": {
      "enabled": true,
      "require_explicit_override": true,
      "per_key": [
        { "seconds": 60,  "max_requests": 30 },
        { "seconds": 300, "max_usd": 5.0 }
      ],
      "per_tenant": [
        { "seconds": 86400, "max_usd": 500.0 }
      ]
    }
  }
}
```

Per-model price overrides (e.g. for negotiated enterprise pricing or internal
models) live alongside it:

```json
"model_prices": {
  "gpt-4o-mini": { "input": 0.03, "output": 0.12 },
  "internal-llm": { "input": 0.0,  "output": 0.0 }
}
```

The estimate is intentionally pessimistic so budgets bite a little earlier
than the upstream invoice.

## 4. Dashboard signal

`GET /v1/policy/me` (auth: `aeg_…` API key) returns:

- effective compiled policy spec
- decision histogram for the current window (the existing anomaly tracker)
- usage roll-ups for the last hour and last 24 hours, per tenant and per key

Wire those into your own ops dashboard, or use the bundled audit UI which
shows decisions, severities, findings, sizes, latency, and the full extra
metadata (including `safety: budget_exceeded` and `safety: loop_detected`
markers) for any blocked request.

## 5. Tool governance: stop the agent doing things it wasn't asked to

The risk: a model is tricked (or just confused) into calling a tool the user
didn't ask for — `delete_account()`, `send_payment()`, `email_to_attacker()`.
Worse: a malicious or compromised plugin teaches the model a brand-new tool
that the customer never approved, so the model "knows" how to call it.

Aegis closes both holes with a **tenant-scoped tool registry** and a
**model-emitted tool-call inspector**.

### The registry (admin-controlled allowlist)

Every tool the customer wants the model to be able to use must be
registered:

```bash
curl -X POST https://aegis.example.com/admin/api/tools \
  -H "Content-Type: application/json" -b session.cookie \
  -d '{
    "name": "create_calendar_event",
    "action_class": "write",
    "schema": { "type":"function", "function":{ "name":"create_calendar_event",
                "parameters":{...} } },
    "config": {
      "allow_domains": ["example.com"],
      "monetary_threshold_usd": 0
    }
  }'
```

Registration captures:

- `action_class` — `read | write | destructive | financial | network`.
- `requires_approval` — opt-in even for non-sensitive tools.
- `schema` (optional) — Aegis stores its SHA-256 hash. If the schema the
  customer's app *advertises to the model later* doesn't match (a
  supply-chain plugin mutated it), the request is blocked.
- `config` — per-tool guardrails: domain allow/deny lists for tools that take
  URLs, monetary thresholds, etc.

### What the proxy enforces

**Inbound** (the `tools` array on the request):

- Reject any tool that isn't registered → HTTP 451 `tool_registry_block`.
- Reject any tool whose advertised schema doesn't match the registered
  `schema_hash` → same status with a reason that calls out supply-chain
  mutation explicitly.

**Outbound** (model-emitted `tool_calls` / Anthropic `tool_use`):

- Classify the call (`read / write / destructive / financial / network`)
  using the registered `action_class` or, as a fallback, a transparent
  keyword heuristic (`delete_*` → destructive, `pay_*` → financial,
  `browse_*` → network, etc.).
- Run **URL safety** on the arguments — `extract_urls` walks the args dict;
  every URL is checked for loopback / RFC1918 / cloud-metadata / disallowed
  scheme / domain allow-list / domain deny-list. A SSRF target like
  `http://169.254.169.254/` or `http://10.0.0.5/admin` is blocked even if
  the model thought it was fine.
- For sensitive classes (`destructive` and `financial` by default, plus
  any `requires_approval=true` tool), the call is **stripped from the
  response unless the request carried `X-Aegis-Approve-Action: 1`**. The
  client agent never sees a handle it could invoke.
- For `financial` calls, Aegis reads `amount_usd` / `amount` / `total` /
  `price` / `cost` / `value` from the args. If the value exceeds the
  per-tool or per-tenant threshold, the call is blocked even with the
  default approve toggle off.

In every case the original call, the reason it was blocked, and any
override flags are written to `aegis.tool_governance` in the response
envelope and to the `AuditEvent` row, so a security admin can review every
"the AI tried to do X" event.

### SDK ergonomics

```python
from aegis_client import AegisClient

with AegisClient("https://aegis.example.com", "aeg_live_…") as a:
    # Default — sensitive calls get stripped; user is asked to confirm.
    resp = a.chat(model="gpt-4o-mini", messages=[...], tools=[...])

    # User clicked "yes, proceed" — re-call with explicit approval.
    confirmed = a.chat(model="gpt-4o-mini", messages=[...], tools=[...],
                       approve_action=True)
```

## 6. API key identity: stop credential theft from being useful

The risk: an attacker copies an `aeg_…` key from a developer's `.env` file
and starts using it from their own machine.

Aegis ships two layers of defence at the auth layer:

### CIDR allowlist (per key)

When you create a key, you can pin it to one or more CIDRs:

```bash
curl -X POST https://aegis.example.com/admin/api/keys \
  -H "Content-Type: application/json" -b session.cookie \
  -d '{ "name": "prod-app", "scopes": ["proxy"],
        "allowed_ips": ["10.0.0.0/16", "203.0.113.5"] }'
```

Any request from outside the allowlist returns HTTP 403. There is no
override header for this — if you really need to extend it, do it in the
admin UI / API.

### First-seen-IP pin

For keys that legitimately move (developer laptops, CI runners), set
`pin_first_seen_ip: true`. The very first request locks the key to the /24
(IPv4) or /48 (IPv6) it was used from. Subsequent requests from a different
network return:

```http
HTTP/1.1 403 Forbidden
{
  "detail": "API key is pinned to first-seen network 198.51.100.0/24 but
             request came from 203.0.113.7. Retry with header
             `X-Aegis-Override-IP: 1` (logged) or rotate the key from the
             admin console."
}
```

The override is recorded so a security admin can spot a developer who
keeps silencing the alarm.

### Forensic visibility

Every API key now carries `first_seen_ip` and `last_used_ip`. The admin
console + `/admin/api/keys` endpoint show both. If a stolen key is suspected,
revoking it propagates instantly because revocation is checked on every
request.

## What this does *not* do (yet)

- **Browser sandbox**: Aegis is the gateway, not the headless browser. The
  recommended pattern is to fetch pages in your agent code, then send the
  text via the SDK's `quote_scraped` helper so the gateway sees it as
  untrusted.
- **Token-perfect cost**: estimates use a calibrated chars-per-token ratio;
  for billing-grade accuracy, plug in the upstream `usage` field by adding a
  small adapter post-processing step. The infrastructure is already in
  place — `estimate_cost_usd` is the single point to override.
- **Argument-schema enforcement**: today Aegis hashes the schema for
  supply-chain detection. Server-side validation of model-emitted args
  against the registered JSON Schema is on the roadmap.
