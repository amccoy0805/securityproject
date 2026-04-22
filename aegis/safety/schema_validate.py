"""JSON Schema validation for tool/function call arguments.

When an admin registers a tool, they may attach the full tool schema
(``RegisteredTool.tool_schema_json``). On every model-emitted tool call we
extract the ``parameters`` JSON Schema, validate the call's actual arguments
against it, and refuse to relay the call if the model produced something the
tool can't actually accept.

Why this matters
----------------

A registered ``schema_hash`` defends against *plugin supply-chain* mutation
(someone changes the schema upstream → the hash mismatches → we block). It
does **not** defend against a model emitting arguments that don't conform to
the schema — which is the single biggest source of "the agent did something
unexpected" in production. This module closes that gap.

Implementation notes
--------------------

- We use Draft 2020-12 (the OpenAI / Anthropic tool-use contract) when
  available; older drafts validate fine too because we treat unknown keywords
  as informational.
- ``jsonschema`` is an optional dep. If it's missing we degrade to "no
  validation, log a warning once per process" so the gateway still boots in
  minimal environments.
- Validation errors are returned as a structured ``SchemaValidationResult``
  for the audit log.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger("aegis.schema")

try:
    from jsonschema import Draft202012Validator
    from jsonschema.exceptions import SchemaError, ValidationError
    _JSONSCHEMA_OK = True
except Exception:  # pragma: no cover  (only hit if dep missing)
    _JSONSCHEMA_OK = False
    Draft202012Validator = None  # type: ignore[assignment]
    ValidationError = SchemaError = Exception  # type: ignore[misc, assignment]
    log.warning(
        "aegis.schema: 'jsonschema' is not installed; tool argument validation is disabled. "
        "Install with `pip install jsonschema` for full coverage."
    )


@dataclass
class SchemaValidationResult:
    ok: bool
    errors: list[str] = field(default_factory=list)
    schema_present: bool = False
    schema_invalid: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "schema_present": self.schema_present,
            "schema_invalid": self.schema_invalid,
            "errors": list(self.errors),
        }


def extract_parameters_schema(tool_schema: dict[str, Any] | None) -> dict[str, Any] | None:
    """Pull the ``parameters`` schema from an OpenAI/Anthropic tool registration.

    Accepts either the full OpenAI shape::

        { "type": "function", "function": { "name": ..., "parameters": {...} } }

    or the Anthropic shape::

        { "name": ..., "input_schema": {...} }
    """
    if not tool_schema or not isinstance(tool_schema, dict):
        return None
    if "function" in tool_schema and isinstance(tool_schema["function"], dict):
        params = tool_schema["function"].get("parameters")
        if isinstance(params, dict):
            return params
    if "input_schema" in tool_schema and isinstance(tool_schema["input_schema"], dict):
        return tool_schema["input_schema"]
    if "parameters" in tool_schema and isinstance(tool_schema["parameters"], dict):
        return tool_schema["parameters"]
    return None


def validate_arguments(
    arguments: Any,
    *,
    tool_schema: dict[str, Any] | None,
) -> SchemaValidationResult:
    """Validate ``arguments`` against the ``parameters`` slice of ``tool_schema``."""
    params = extract_parameters_schema(tool_schema)
    if params is None:
        return SchemaValidationResult(ok=True, schema_present=False)
    if not _JSONSCHEMA_OK:
        return SchemaValidationResult(ok=True, schema_present=True)
    try:
        validator = Draft202012Validator(params)
    except SchemaError as exc:
        return SchemaValidationResult(
            ok=False,
            errors=[f"registered schema is itself invalid: {exc.message}"],
            schema_present=True,
            schema_invalid=True,
        )
    errors: list[str] = []
    try:
        for err in validator.iter_errors(arguments):
            path = "/".join(str(p) for p in err.absolute_path) or "<root>"
            errors.append(f"{path}: {err.message}")
            if len(errors) >= 8:
                errors.append("…(more errors elided)")
                break
    except Exception as exc:
        # jsonschema raises UnknownType / similar at *validation* time when the
        # schema itself is malformed (e.g. unknown ``type: ...``). Treat that
        # as a malformed schema, not a crash.
        return SchemaValidationResult(
            ok=False,
            errors=[f"schema validation aborted: {exc}"],
            schema_present=True,
            schema_invalid=True,
        )
    return SchemaValidationResult(
        ok=not errors, errors=errors, schema_present=True, schema_invalid=False
    )
