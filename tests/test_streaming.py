"""Streaming SSE redactor tests."""

from __future__ import annotations

from aegis.policy.streaming import (
    StreamingRedactor,
    extract_delta_text,
    parse_openai_sse_chunk,
    rewrite_delta_text,
    serialise_sse_event,
)


def test_redactor_passes_through_clean_text():
    r = StreamingRedactor(safe_tail=8)
    out, _ = r.feed("hello world this is fine ")
    assert "hello" in out
    tail, _ = r.flush()
    assert "fine" in (out + tail)


def test_redactor_redacts_secret_in_one_chunk():
    r = StreamingRedactor(safe_tail=64)
    chunk = "your token: ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  -- end"
    out, _ = r.feed(chunk)
    tail, _ = r.flush()
    final = out + tail
    assert "ghp_" not in final
    assert "[REDACTED:SECRET]" in final


def test_redactor_redacts_secret_split_across_two_chunks():
    """The split is mid-token; the redactor's lookahead must catch it."""
    r = StreamingRedactor(safe_tail=64)
    half_a = "Sure! token: ghp_aaaaaaaaaaaaaaaaaa"
    half_b = "aaaaaaaaaaaaaaaaaaaa more text"
    out_a, _ = r.feed(half_a)
    out_b, _ = r.feed(half_b)
    tail, _ = r.flush()
    full = out_a + out_b + tail
    assert "ghp_" not in full, full
    assert "[REDACTED:SECRET]" in full


def test_redactor_strips_invisible_unicode_immediately():
    r = StreamingRedactor(safe_tail=4)
    out, _ = r.feed("hi\u200bworld\U000E0041!")
    tail, _ = r.flush()
    full = out + tail
    assert "\u200b" not in full and "\U000E0041" not in full


def test_redactor_disabled_passes_chunks_through():
    r = StreamingRedactor(enabled=False, safe_tail=4)
    out, _ = r.feed("ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    tail, _ = r.flush()
    assert "ghp_" in out + tail


def test_extract_and_rewrite_delta_round_trip():
    ev = {"choices": [{"index": 0, "delta": {"role": "assistant", "content": "hello"}}]}
    assert extract_delta_text(ev) == "hello"
    new = rewrite_delta_text(ev, "[REDACTED]")
    assert new["choices"][0]["delta"]["content"] == "[REDACTED]"
    assert ev["choices"][0]["delta"]["content"] == "hello"  # original untouched


def test_parse_openai_sse_chunk_handles_done_marker():
    raw = b"data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\ndata: [DONE]\n\n"
    events = parse_openai_sse_chunk(raw)
    assert len(events) == 1
    assert extract_delta_text(events[0]) == "hi"


def test_serialise_sse_event_terminates_with_blank_line():
    raw = serialise_sse_event({"choices": [{"delta": {"content": "x"}}]})
    assert raw.endswith(b"\n\n")
    assert raw.startswith(b"data: ")
