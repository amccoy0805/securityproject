from types import SimpleNamespace

from aegis.safety.actions import ActionClass, classify_tool
from aegis.safety.tools import (
    ToolPolicy,
    inspect_request_tools,
    inspect_response_calls,
    schema_hash,
)


def _reg(name, action_class="read", enabled=True, requires_approval=False, schema_hash=None, config=None):
    return SimpleNamespace(
        id="t-" + name,
        tenant_id="t1",
        name=name,
        description=None,
        action_class=action_class,
        enabled=enabled,
        requires_approval=requires_approval,
        schema_hash=schema_hash,
        config=config or {},
    )


# ---- classifier ----

def test_classifier_destructive_wins_over_write():
    assert classify_tool("delete_user").cls == ActionClass.DESTRUCTIVE
    assert classify_tool("create_user").cls == ActionClass.WRITE


def test_classifier_financial_keywords():
    assert classify_tool("charge_card").cls == ActionClass.FINANCIAL
    assert classify_tool("place_order").cls == ActionClass.FINANCIAL


def test_classifier_network_keywords():
    assert classify_tool("browse_web").cls == ActionClass.NETWORK


def test_classifier_explicit_declaration_wins():
    assert classify_tool("send_message", declared="financial").cls == ActionClass.FINANCIAL


# ---- request-tools registry enforcement ----

def test_inbound_blocks_unregistered_tool_only_request():
    policy = ToolPolicy()
    tools = [{"type": "function", "function": {"name": "delete_files", "parameters": {}}}]
    report = inspect_request_tools(request_tools=tools, registered={}, policy=policy)
    assert report.blocked
    assert "register" in (report.reason or "").lower()


def test_inbound_passes_when_tool_registered():
    policy = ToolPolicy()
    schema = {"type": "function", "function": {"name": "list_files", "parameters": {}}}
    reg = {"list_files": _reg("list_files", action_class="read", schema_hash=schema_hash(schema))}
    report = inspect_request_tools(request_tools=[schema], registered=reg, policy=policy)
    assert not report.blocked
    assert report.sanitized_tools == [schema]


def test_inbound_blocks_on_schema_hash_mismatch():
    policy = ToolPolicy()
    schema = {"type": "function", "function": {"name": "get_x", "parameters": {"k": "v"}}}
    mutated = {"type": "function", "function": {"name": "get_x", "parameters": {"k": "ATTACK"}}}
    reg = {"get_x": _reg("get_x", schema_hash=schema_hash(schema))}
    report = inspect_request_tools(request_tools=[mutated], registered=reg, policy=policy)
    assert report.blocked
    assert any("schema" in f.reason.lower() for f in report.findings)


# ---- outbound: model-emitted tool_calls ----

def _openai_response(name, arguments):
    return {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "tool_calls": [
                        {
                            "id": "c1",
                            "type": "function",
                            "function": {"name": name, "arguments": arguments},
                        }
                    ],
                }
            }
        ]
    }


def test_outbound_blocks_destructive_without_approval_and_strips_call():
    policy = ToolPolicy()
    reg = {"delete_user": _reg("delete_user", action_class="destructive")}
    body = _openai_response("delete_user", '{"user_id": 1}')
    new_body, report = inspect_response_calls(body, registered=reg, policy=policy, approved=False)
    assert report.sanitized
    assert new_body["choices"][0]["message"]["tool_calls"] == []
    assert any("approval" in t.reason.lower() for t in report.blocked_calls)


def test_outbound_allows_destructive_when_approved():
    policy = ToolPolicy()
    reg = {"delete_user": _reg("delete_user", action_class="destructive")}
    body = _openai_response("delete_user", '{"user_id": 1}')
    _, report = inspect_response_calls(body, registered=reg, policy=policy, approved=True)
    assert not report.sanitized
    assert not report.blocked_calls


def test_outbound_blocks_financial_over_threshold():
    policy = ToolPolicy(monetary_threshold_usd=50.0)
    reg = {"charge_card": _reg("charge_card", action_class="financial")}
    body = _openai_response("charge_card", '{"amount_usd": 999}')
    new_body, report = inspect_response_calls(body, registered=reg, policy=policy, approved=False)
    assert report.sanitized
    assert new_body["choices"][0]["message"]["tool_calls"] == []


def test_outbound_blocks_url_with_loopback():
    policy = ToolPolicy()
    reg = {"http_get": _reg("http_get", action_class="network")}
    body = _openai_response("http_get", '{"url": "http://127.0.0.1/admin"}')
    new_body, report = inspect_response_calls(body, registered=reg, policy=policy, approved=False)
    assert report.sanitized
    assert any("loopback" in (t.reason or "").lower() for t in report.blocked_calls)
    assert new_body["choices"][0]["message"]["tool_calls"] == []


def test_outbound_blocks_unregistered_tool_call():
    policy = ToolPolicy()
    body = _openai_response("send_email", '{"to":"x@y.com"}')
    _, report = inspect_response_calls(body, registered={}, policy=policy, approved=False)
    assert report.sanitized
    assert any("unregistered" in (t.reason or "").lower() for t in report.blocked_calls)


def test_outbound_anthropic_tool_use_block():
    policy = ToolPolicy()
    reg = {"delete": _reg("delete", action_class="destructive")}
    body = {
        "content": [
            {"type": "text", "text": "okay"},
            {"type": "tool_use", "name": "delete", "input": {"id": 1}},
        ]
    }
    new_body, report = inspect_response_calls(body, registered=reg, policy=policy, approved=False)
    assert report.sanitized
    types = [b.get("type") for b in new_body["content"]]
    assert "tool_use" not in types
