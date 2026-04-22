import pytest

from aegis.policy.llm_judge import (
    JudgeConfig,
    JudgeVerdict,
    StaticJudge,
    _parse_response,
    verdict_to_finding,
)


def test_parse_response_extracts_clean_json():
    raw = '{"injection": true, "score": 0.95, "reason": "ignore directive"}'
    v = _parse_response(raw)
    assert v.injection and v.score == 0.95 and "ignore" in v.reason


def test_parse_response_extracts_json_inside_prose():
    raw = "Sure, here you go.\n{\"injection\": false, \"score\": 0.1, \"reason\": \"benign\"}\nThanks."
    v = _parse_response(raw)
    assert not v.injection and v.score == 0.1


def test_parse_response_handles_missing_json():
    v = _parse_response("I am sorry I cannot help.")
    assert not v.injection and v.error == "no_json"


def test_parse_response_handles_malformed_json():
    v = _parse_response("{not really json}")
    assert not v.injection and v.error


def test_verdict_to_finding_above_threshold_promotes():
    cfg = JudgeConfig(enabled=True, threshold=0.5)
    v = JudgeVerdict(injection=True, score=0.9, reason="paraphrased ignore")
    f = verdict_to_finding(v, cfg=cfg, span_end=42)
    assert f and f.detector == "llm_judge" and f.severity.value == "high"


def test_verdict_to_finding_below_threshold_returns_none():
    cfg = JudgeConfig(enabled=True, threshold=0.8)
    v = JudgeVerdict(injection=True, score=0.6, reason="weak")
    assert verdict_to_finding(v, cfg=cfg, span_end=42) is None


def test_verdict_to_finding_skipped_or_errored_returns_none():
    cfg = JudgeConfig(enabled=True, threshold=0.5)
    assert verdict_to_finding(JudgeVerdict(False, 0.0, "", skipped=True), cfg=cfg, span_end=10) is None
    assert verdict_to_finding(JudgeVerdict(False, 0.9, "", error="boom"), cfg=cfg, span_end=10) is None


@pytest.mark.asyncio
async def test_static_judge_returns_canned_verdict():
    j = StaticJudge(JudgeVerdict(injection=True, score=0.99, reason="canned"))
    cfg = JudgeConfig(enabled=True)
    v = await j.judge("anything", cfg=cfg)
    assert v.injection and v.score == 0.99


@pytest.mark.asyncio
async def test_static_judge_can_simulate_failure():
    j = StaticJudge(RuntimeError("upstream down"))
    cfg = JudgeConfig(enabled=True)
    with pytest.raises(RuntimeError):
        await j.judge("x", cfg=cfg)


def test_config_from_dict_clamps_minimums():
    cfg = JudgeConfig.from_dict({"enabled": True, "input_char_budget": 1, "output_char_budget": 1, "timeout_s": 0.0})
    assert cfg.input_char_budget >= 64
    assert cfg.output_char_budget >= 16
    assert cfg.timeout_s >= 0.5
