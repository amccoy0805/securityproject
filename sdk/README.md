# aegis-client

Minimal Python SDK for the Aegis AI Gateway. Two patterns:

## 1. Drop-in OpenAI client

```python
from openai import OpenAI

client = OpenAI(
    base_url="https://aegis.your-company.com/v1",
    api_key="aeg_live_xxxxxxxx.xxxxxxxxxxxxxxxxxxxxxxxx",  # issued by Aegis admin console
)

resp = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Hello"}],
)
```

The same trick works for Anthropic — point its base URL at the Aegis gateway and use the
`aeg_…` key. Aegis transparently forwards to your real Anthropic credential, after policy
evaluation.

## 2. Native client (policy + dry runs)

```python
from aegis_client import AegisClient

with AegisClient("https://aegis.your-company.com", "aeg_live_…") as a:
    print(a.my_policy())
    print(a.check("Customer SSN 123-45-6789", model="gpt-4o-mini"))
```
