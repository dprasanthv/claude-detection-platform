"""Sigma parser + DuckDB SQL compiler.

Covers the three layers of ``cdp/sigma.py``:

1. ``resolve_table`` — logsource → table mapping invariants.
2. ``parse_rule_file`` / ``load_rules`` — YAML loading + Pydantic validation.
3. ``compile_rule`` — modifier semantics, list expansion, condition grammar.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from cdp.models import SigmaRule
from cdp.sigma import (
    LOGSOURCE_MAP,
    SUPPORTED_MODIFIERS,
    compile_rule,
    load_rules,
    parse_rule_file,
    resolve_table,
    validate_rule,
)

# ---------- resolve_table ----------


@pytest.mark.parametrize(
    ("logsource", "expected"),
    [
        ({"product": "windows", "category": "process_creation"}, "windows_process_creation"),
        ({"product": "Windows", "category": "Process_Creation"}, "windows_process_creation"),
        ({"product": "aws", "service": "cloudtrail"}, "aws_cloudtrail"),
        ({"category": "authentication"}, "authentication"),
        ({"product": "linux", "category": "process_creation"}, None),
        ({"product": "aws", "service": "guardduty"}, None),
        ({}, None),
    ],
)
def test_resolve_table(logsource: dict[str, str], expected: str | None) -> None:
    assert resolve_table(logsource) == expected


def test_logsource_map_only_resolves_to_known_tables() -> None:
    assert {entry[1] for entry in LOGSOURCE_MAP} == {
        "windows_process_creation",
        "aws_cloudtrail",
        "authentication",
    }


def test_supported_modifiers_match_documented_set() -> None:
    """Guard against drift between the parser and ``detections/README.md``."""
    assert frozenset(
        {"contains", "startswith", "endswith", "re", "gt", "gte", "lt", "lte"}
    ) == SUPPORTED_MODIFIERS


# ---------- parse_rule_file / load_rules ----------


SHIPPED_RULE_IDS = {
    "cdp.credential_access.brute_force_admin_login",
    "cdp.credential_access.iam_admin_policy_attached",
    "cdp.execution.powershell_encoded_command",
    "cdp.execution.office_spawns_script_host",
    "cdp.persistence.new_service_install",
    "cdp.exfiltration.s3_large_object_egress",
}


def test_load_all_shipped_rules(detections_dir: Path) -> None:
    rules = load_rules(detections_dir)
    assert {r.id for r in rules} == SHIPPED_RULE_IDS
    # Every rule has a sha256 fingerprint and a recorded source path.
    for r in rules:
        assert r.sha256 is not None and len(r.sha256) == 64
        assert r.source_path is not None and r.source_path.endswith((".yml", ".yaml"))


def test_parse_rule_extracts_mitre_techniques(detections_dir: Path) -> None:
    rule = parse_rule_file(
        detections_dir / "execution" / "powershell_encoded_command.yml"
    )
    assert "T1059.001" in rule.mitre_techniques
    assert rule.level == "high"


def test_parse_rule_missing_condition_raises(tmp_path: Path) -> None:
    p = tmp_path / "bad.yml"
    p.write_text(
        "title: x\nid: x\nlogsource:\n  category: authentication\n"
        "detection:\n  selection:\n    foo: 1\n"
    )
    with pytest.raises(ValueError, match="condition is required"):
        parse_rule_file(p)


def test_parse_rule_non_mapping_yaml_raises(tmp_path: Path) -> None:
    p = tmp_path / "bad.yml"
    p.write_text("- not\n- a\n- mapping\n")
    with pytest.raises(ValueError, match="top-level YAML must be a mapping"):
        parse_rule_file(p)


def test_parse_rule_invalid_severity_rejected(tmp_path: Path) -> None:
    p = tmp_path / "bad.yml"
    p.write_text(
        "title: x\nid: x\nlevel: urgent\n"
        "logsource:\n  category: authentication\n"
        "detection:\n  selection:\n    a: 1\n  condition: selection\n"
    )
    with pytest.raises(ValidationError):
        parse_rule_file(p)


def test_load_rules_recurses_and_dedupes(tmp_path: Path) -> None:
    sub = tmp_path / "nested"
    sub.mkdir()
    (tmp_path / "a.yml").write_text(
        "title: a\nid: a\nlogsource:\n  category: authentication\n"
        "detection:\n  s:\n    x: 1\n  condition: s\n"
    )
    (sub / "b.yaml").write_text(
        "title: b\nid: b\nlogsource:\n  category: authentication\n"
        "detection:\n  s:\n    y: 2\n  condition: s\n"
    )
    rules = load_rules(tmp_path)
    assert {r.id for r in rules} == {"a", "b"}


# ---------- compile_rule helpers ----------


def _make_rule(detection: dict[str, Any], condition: str) -> SigmaRule:
    """Build a minimal :class:`SigmaRule` mapped to the ``authentication`` table."""
    return SigmaRule(
        id="t",
        title="t",
        logsource={"category": "authentication"},
        detection={**detection, "condition": condition},
        condition=condition,
    )


# ---------- compile_rule: per-modifier sql shape ----------


def test_compile_equality_default_modifier() -> None:
    r = _make_rule({"sel": {"username": "admin"}}, "sel")
    c = compile_rule(r)
    assert c.table == "authentication"
    assert 'CAST("username" AS VARCHAR) = ?' in c.where_sql
    assert c.params == ["admin"]


def test_compile_contains_startswith_endswith() -> None:
    r = _make_rule(
        {"sel": {"a|contains": "x", "b|startswith": "y", "c|endswith": "z"}},
        "sel",
    )
    c = compile_rule(r)
    assert c.params == ["%x%", "y%", "%z"]
    assert c.where_sql.count("LIKE ?") == 3


def test_compile_regex_modifier() -> None:
    r = _make_rule({"sel": {"a|re": "^foo.*$"}}, "sel")
    c = compile_rule(r)
    assert "regexp_matches" in c.where_sql
    assert c.params == ["^foo.*$"]


@pytest.mark.parametrize(
    ("modifier", "operator"),
    [("gt", ">"), ("gte", ">="), ("lt", "<"), ("lte", "<=")],
)
def test_compile_numeric_compare_modifiers(modifier: str, operator: str) -> None:
    r = _make_rule({"sel": {f"a|{modifier}": 100}}, "sel")
    c = compile_rule(r)
    assert f" {operator} ?" in c.where_sql
    assert c.params == [100]


def test_compile_list_value_or_expanded() -> None:
    r = _make_rule({"sel": {"a": ["x", "y", "z"]}}, "sel")
    c = compile_rule(r)
    assert c.where_sql.count(" OR ") == 2
    assert c.params == ["x", "y", "z"]


def test_compile_null_value_uses_is_null() -> None:
    r = _make_rule({"sel": {"a": None}}, "sel")
    c = compile_rule(r)
    assert "IS NULL" in c.where_sql
    assert c.params == []


def test_compile_unsupported_modifier_raises() -> None:
    r = _make_rule({"sel": {"a|wat": "x"}}, "sel")
    with pytest.raises(ValueError, match="unsupported modifier"):
        compile_rule(r)


def test_compile_empty_list_value_raises() -> None:
    r = _make_rule({"sel": {"a": []}}, "sel")
    with pytest.raises(ValueError, match="empty list value"):
        compile_rule(r)


# ---------- compile_rule: condition grammar ----------


def test_condition_and_or_not_parens() -> None:
    r = _make_rule(
        {"a": {"x": "1"}, "b": {"y": "2"}, "c": {"z": "3"}},
        "(a or b) and not c",
    )
    c = compile_rule(r)
    assert "OR" in c.where_sql
    assert "AND" in c.where_sql
    assert "NOT" in c.where_sql
    assert c.params == ["1", "2", "3"]


def test_condition_one_of_pattern_glob() -> None:
    r = _make_rule(
        {"sel_a": {"x": "1"}, "sel_b": {"y": "2"}, "other": {"z": "3"}},
        "1 of sel_*",
    )
    c = compile_rule(r)
    # Two selections matched, joined with OR. ``other`` must not be included.
    assert " OR " in c.where_sql
    assert sorted(c.params) == ["1", "2"]
    assert "3" not in c.params


def test_condition_all_of_them_ands_all() -> None:
    r = _make_rule({"a": {"x": "1"}, "b": {"y": "2"}}, "all of them")
    c = compile_rule(r)
    assert " AND " in c.where_sql
    assert sorted(c.params) == ["1", "2"]


def test_condition_unknown_selection_raises() -> None:
    r = _make_rule({"a": {"x": "1"}}, "ghost")
    with pytest.raises(ValueError, match="unknown selection"):
        compile_rule(r)


def test_condition_pattern_no_match_raises() -> None:
    r = _make_rule({"a": {"x": "1"}}, "1 of ghost_*")
    with pytest.raises(ValueError, match="no selections match pattern"):
        compile_rule(r)


def test_condition_trailing_tokens_rejected() -> None:
    r = _make_rule({"a": {"x": "1"}}, "a a")
    with pytest.raises(ValueError, match="trailing tokens"):
        compile_rule(r)


def test_condition_unexpected_character_rejected() -> None:
    r = _make_rule({"a": {"x": "1"}}, "a & b")
    with pytest.raises(ValueError, match="unexpected character"):
        compile_rule(r)


# ---------- compile_rule: structural failures ----------


def test_compile_rule_unmapped_logsource_raises() -> None:
    rule = SigmaRule(
        id="r",
        title="t",
        logsource={"product": "linux", "category": "process_creation"},
        detection={"sel": {"x": "1"}, "condition": "sel"},
        condition="sel",
    )
    with pytest.raises(ValueError, match="does not map"):
        compile_rule(rule)


def test_compile_rule_no_selections_raises() -> None:
    rule = SigmaRule(
        id="r",
        title="t",
        logsource={"category": "authentication"},
        detection={"condition": "sel"},
        condition="sel",
    )
    with pytest.raises(ValueError, match="no selections defined"):
        compile_rule(rule)


def test_compile_rule_table_override(detections_dir: Path) -> None:
    """The ``table`` arg pins resolution regardless of the rule's logsource."""
    rule = parse_rule_file(detections_dir / "credential_access" / "brute_force_login.yml")
    c = compile_rule(rule, table="custom_override")
    assert c.table == "custom_override"


def test_validate_each_shipped_rule(detections_dir: Path) -> None:
    """Every rule shipped with the repo must parse + compile cleanly."""
    for rule in load_rules(detections_dir):
        validate_rule(rule)


def test_compile_shipped_brute_force_rule_shape(detections_dir: Path) -> None:
    rule = parse_rule_file(detections_dir / "credential_access" / "brute_force_login.yml")
    c = compile_rule(rule)
    assert c.table == "authentication"
    # ``selection AND NOT internal_ranges`` ⇒ both fragments + a NOT.
    assert "NOT" in c.where_sql
    assert "admin" in c.params
    assert "failure" in c.params
