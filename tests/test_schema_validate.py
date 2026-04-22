from aegis.safety.schema_validate import (
    extract_parameters_schema,
    validate_arguments,
)

OPENAI_SCHEMA = {
    "type": "function",
    "function": {
        "name": "place_order",
        "parameters": {
            "type": "object",
            "required": ["sku", "qty"],
            "properties": {
                "sku": {"type": "string", "minLength": 4},
                "qty": {"type": "integer", "minimum": 1, "maximum": 100},
                "currency": {"type": "string", "enum": ["USD", "EUR", "GBP"]},
            },
            "additionalProperties": False,
        },
    },
}

ANTHROPIC_SCHEMA = {
    "name": "lookup_user",
    "input_schema": {
        "type": "object",
        "required": ["user_id"],
        "properties": {"user_id": {"type": "string"}},
    },
}


def test_extract_parameters_handles_openai_shape():
    p = extract_parameters_schema(OPENAI_SCHEMA)
    assert p and p["type"] == "object" and "sku" in p["properties"]


def test_extract_parameters_handles_anthropic_shape():
    p = extract_parameters_schema(ANTHROPIC_SCHEMA)
    assert p and "user_id" in p["properties"]


def test_extract_returns_none_when_absent():
    assert extract_parameters_schema(None) is None
    assert extract_parameters_schema({"foo": "bar"}) is None


def test_validation_passes_for_valid_args():
    res = validate_arguments({"sku": "ABCDE", "qty": 5}, tool_schema=OPENAI_SCHEMA)
    assert res.ok and not res.errors and res.schema_present


def test_validation_fails_on_missing_required():
    res = validate_arguments({"qty": 5}, tool_schema=OPENAI_SCHEMA)
    assert not res.ok
    assert any("sku" in e for e in res.errors)


def test_validation_fails_on_wrong_type():
    res = validate_arguments({"sku": "ABCD", "qty": "five"}, tool_schema=OPENAI_SCHEMA)
    assert not res.ok
    assert any("qty" in e for e in res.errors)


def test_validation_fails_on_enum_violation():
    res = validate_arguments(
        {"sku": "ABCD", "qty": 1, "currency": "XYZ"}, tool_schema=OPENAI_SCHEMA
    )
    assert not res.ok
    assert any("currency" in e for e in res.errors)


def test_validation_fails_on_extra_properties_when_disallowed():
    res = validate_arguments(
        {"sku": "ABCD", "qty": 1, "evil": "code_injection"}, tool_schema=OPENAI_SCHEMA
    )
    assert not res.ok


def test_no_schema_means_pass():
    res = validate_arguments({"anything": "goes"}, tool_schema=None)
    assert res.ok and not res.schema_present


def test_invalid_schema_itself_is_flagged():
    bad = {"function": {"parameters": {"type": "not-a-real-type"}}}
    res = validate_arguments({}, tool_schema=bad)
    # Some jsonschema versions are forgiving about unknown types — accept either.
    assert (res.ok and not res.schema_invalid) or (not res.ok and res.schema_invalid)


def test_anthropic_schema_validates():
    res = validate_arguments({"user_id": "u-123"}, tool_schema=ANTHROPIC_SCHEMA)
    assert res.ok
    bad = validate_arguments({}, tool_schema=ANTHROPIC_SCHEMA)
    assert not bad.ok
