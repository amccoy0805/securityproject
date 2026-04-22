from datetime import datetime

from aegis.policy.rules import (
    CONSUMER_DEFAULT_RULES,
    RuleContext,
    RuleVerdict,
    evaluate_all,
    fold,
    parse_rules,
)


def _ctx(**kw):
    base = {
        "text": "",
        "model": None,
        "action_classes": [],
        "detected_categories": [],
        "untrusted_present": False,
        "now": datetime(2026, 4, 22, 14, 0, 0),  # Wednesday 14:00 UTC
    }
    base.update(kw)
    return RuleContext(**base)


def test_never_send_money_blocks_financial():
    rules = parse_rules([{"kind": "never_send_money", "name": "no money"}])
    res = evaluate_all(rules, _ctx(action_classes=["financial"]))
    assert res and res[0].verdict == RuleVerdict.BLOCK


def test_never_send_money_quiet_on_read():
    rules = parse_rules([{"kind": "never_send_money", "name": "no money"}])
    assert not evaluate_all(rules, _ctx(action_classes=["read"]))


def test_require_approval_for_writes():
    rules = parse_rules([
        {"kind": "require_approval_for", "name": "approve writes",
         "config": {"classes": ["write"]}},
    ])
    res = evaluate_all(rules, _ctx(action_classes=["write"]))
    assert res and res[0].verdict == RuleVerdict.REQUIRE_APPROVAL


def test_no_external_input_for_destructive():
    rules = parse_rules([
        {"kind": "no_external_input_for_destructive", "name": "no scrape destruct"},
    ])
    res = evaluate_all(
        rules, _ctx(action_classes=["destructive"], untrusted_present=True)
    )
    assert res and res[0].verdict == RuleVerdict.BLOCK


def test_block_weekends_only_fires_on_weekend():
    rules = parse_rules([{"kind": "block_weekends", "name": "weekends off"}])
    sat = datetime(2026, 4, 25, 14, 0, 0)  # Saturday
    wed = datetime(2026, 4, 22, 14, 0, 0)
    assert evaluate_all(rules, _ctx(now=sat))
    assert not evaluate_all(rules, _ctx(now=wed))


def test_business_hours_only_blocks_after_hours():
    rules = parse_rules([{"kind": "business_hours_only", "name": "9-5"}])
    morning = datetime(2026, 4, 22, 7, 0, 0)
    afternoon = datetime(2026, 4, 22, 14, 0, 0)
    assert evaluate_all(rules, _ctx(now=morning))
    assert not evaluate_all(rules, _ctx(now=afternoon))


def test_never_share_categories_blocks_secret():
    rules = parse_rules([
        {"kind": "never_share", "name": "no secrets",
         "config": {"categories": ["secret"]}},
    ])
    res = evaluate_all(rules, _ctx(detected_categories=["secret", "pii"]))
    assert res and res[0].verdict == RuleVerdict.BLOCK


def test_fold_strictest_wins():
    rules = parse_rules([
        {"kind": "require_approval_for", "name": "writes need ok",
         "config": {"classes": ["write"]}},
        {"kind": "never_send_money", "name": "no money"},
    ])
    res = evaluate_all(rules, _ctx(action_classes=["write", "financial"]))
    folded = fold(res)
    assert folded.verdict == RuleVerdict.BLOCK


def test_consumer_defaults_parse_cleanly():
    rules = parse_rules(CONSUMER_DEFAULT_RULES)
    assert len(rules) == len(CONSUMER_DEFAULT_RULES)
    # Every consumer default has a matching dispatch entry.
    for r in rules:
        assert r.kind in {
            "never_send_money", "require_approval_for",
            "no_external_input_for_destructive", "never_share",
        }


def test_unknown_rule_kind_is_ignored():
    rules = parse_rules([{"kind": "rm_rf_filesystem", "name": "no"}])
    assert rules == []
