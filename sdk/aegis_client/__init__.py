"""Aegis client SDK.

Two ways to use Aegis from your apps:

1. **Drop-in OpenAI client**: point the official ``openai`` SDK at the gateway:

       from openai import OpenAI
       client = OpenAI(base_url="https://aegis.example.com/v1", api_key="aeg_live_...")

2. **Native ``AegisClient``** for policy introspection and dry-runs:

       from aegis_client import AegisClient
       c = AegisClient("https://aegis.example.com", "aeg_live_...")
       c.check("Customer SSN 123-45-6789")
"""

from .client import AegisClient, AegisError
from .web import quote_scraped

__all__ = ["AegisClient", "AegisError", "quote_scraped"]
