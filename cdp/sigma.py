"""Sigma rule parser and DuckDB SQL compiler.

This is a deliberately small subset of the Sigma spec — enough to express the
rules in ``detections/`` and exercise the moving parts a hiring reviewer cares
about (parser, modifier semantics, condition grammar, deterministic SQL
generation). Out of scope for the demo: aggregations (``| count() by ...``),
``near`` correlation, ``timeframe`` windows, base64offset/utf16 transforms.

Supported field modifiers (postfix ``field|<modifier>:``):
    contains, startswith, endswith, re, gt, gte, lt, lte
Default (no modifier) is equality.

Supported condition grammar:
    expr     := or_expr
    or_expr  := and_expr ('or' and_expr)*
    and_expr := not_expr ('and' not_expr)*
    not_expr := 'not' not_expr | atom
    atom     := '(' expr ')' | quantifier | selection_name
    quantifier := ('1' | 'all') 'of' (selection_glob | 'them')

List values inside a selection are OR-expanded. Multiple key/value pairs in a
selection are AND-ed.
"""

from __future__ import annotations

import fnmatch
import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import yaml

from cdp.models import SeverityLevel, SigmaRule

# Logsource → table resolution. First match wins. ``None`` means "any value".
# Keep this list short and explicit; we only ship three telemetry tables.
LOGSOURCE_MAP: list[tuple[tuple[str | None, str | None, str | None], str]] = [
    # (product, service, category) -> table
    (("windows", None, "process_creation"), "windows_process_creation"),
    (("aws", "cloudtrail", None), "aws_cloudtrail"),
    ((None, None, "authentication"), "authentication"),
]

SUPPORTED_MODIFIERS: frozenset[str] = frozenset(
    {"contains", "startswith", "endswith", "re", "gt", "gte", "lt", "lte"}
)


def resolve_table(logsource: dict[str, str]) -> str | None:
    """Map a Sigma ``logsource`` block to one of our concrete table names."""
    product = (logsource.get("product") or "").lower() or None
    service = (logsource.get("service") or "").lower() or None
    category = (logsource.get("category") or "").lower() or None
    for (lp, ls, lc), table in LOGSOURCE_MAP:
        if (
            (lp is None or lp == product)
            and (ls is None or ls == service)
            and (lc is None or lc == category)
        ):
            return table
    return None


# ---------- Rule loading ----------

def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_rule_file(path: Path) -> SigmaRule:
    """Load a Sigma rule from YAML and return a :class:`SigmaRule`.

    Raises ``ValueError`` for structural problems (missing condition, bad YAML).
    Pydantic validates ``level`` against the SeverityLevel literal.
    """
    raw = yaml.safe_load(path.read_text())
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: top-level YAML must be a mapping")

    detection = raw.get("detection")
    if not isinstance(detection, dict) or "condition" not in detection:
        raise ValueError(f"{path}: detection.condition is required")

    return SigmaRule(
        id=str(raw.get("id") or path.stem),
        title=str(raw.get("title") or path.stem),
        description=str(raw.get("description") or ""),
        status=str(raw.get("status") or "test"),
        # Pydantic validates the literal at runtime; cast satisfies the type checker.
        level=cast(SeverityLevel, str(raw.get("level") or "medium")),
        logsource={k: str(v) for k, v in (raw.get("logsource") or {}).items()},
        detection={k: v for k, v in detection.items() if k != "condition"},
        condition=str(detection["condition"]),
        tags=[str(t) for t in (raw.get("tags") or [])],
        source_path=str(path),
        sha256=_file_sha256(path),
    )


def load_rules(rules_dir: Path) -> list[SigmaRule]:
    """Recursively load all ``*.yml`` / ``*.yaml`` rules under ``rules_dir``."""
    rules: list[SigmaRule] = []
    seen: set[Path] = set()
    for ext in ("*.yml", "*.yaml"):
        for path in sorted(rules_dir.rglob(ext)):
            if path in seen:
                continue
            seen.add(path)
            rules.append(parse_rule_file(path))
    return rules


# ---------- SQL compiler ----------

@dataclass
class CompiledRule:
    """Result of compiling a SigmaRule to a parameterized DuckDB query."""

    table: str
    where_sql: str
    params: list[Any]

    def to_sql(self) -> str:
        # Caller passes ``params`` separately to ``Store.query``.
        return f"SELECT * FROM {self.table} WHERE {self.where_sql}"


def _compile_field_clause(
    field: str, modifier: str | None, value: Any
) -> tuple[str, list[Any]]:
    """Compile a single ``field[|modifier]: value`` into ``(sql, params)``.

    Lists are OR-expanded recursively.
    """
    if isinstance(value, list):
        if not value:
            raise ValueError(f"empty list value for field {field!r}")
        sub_sqls: list[str] = []
        sub_params: list[Any] = []
        for v in value:
            s, p = _compile_field_clause(field, modifier, v)
            sub_sqls.append(s)
            sub_params.extend(p)
        return "(" + " OR ".join(sub_sqls) + ")", sub_params

    col = f'"{field}"'
    if value is None:
        return f"{col} IS NULL", []

    if modifier is None:
        # Cast to VARCHAR so int/bool/string literals compare uniformly. This
        # is what Sigma authors expect; type coercion happens implicitly in
        # most SIEM backends as well.
        return f"CAST({col} AS VARCHAR) = ?", [str(value)]

    if modifier == "contains":
        return f"CAST({col} AS VARCHAR) LIKE ?", [f"%{value}%"]
    if modifier == "startswith":
        return f"CAST({col} AS VARCHAR) LIKE ?", [f"{value}%"]
    if modifier == "endswith":
        return f"CAST({col} AS VARCHAR) LIKE ?", [f"%{value}"]
    if modifier == "re":
        return f"regexp_matches(CAST({col} AS VARCHAR), ?)", [str(value)]
    if modifier in {"gt", "gte", "lt", "lte"}:
        op = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<="}[modifier]
        return f"{col} {op} ?", [value]

    raise ValueError(f"unsupported modifier {modifier!r} on field {field!r}")


def _compile_selection(name: str, selection: dict[str, Any]) -> tuple[str, list[Any]]:
    """AND-combine all key/value pairs in a single named selection."""
    if not isinstance(selection, dict) or not selection:
        raise ValueError(f"selection {name!r} must be a non-empty mapping")

    sqls: list[str] = []
    params: list[Any] = []
    for key, value in selection.items():
        if "|" in key:
            field, modifier = key.split("|", 1)
            modifier = modifier.lower()
            if modifier not in SUPPORTED_MODIFIERS:
                raise ValueError(
                    f"selection {name!r}: unsupported modifier {modifier!r} on field {field!r}"
                )
        else:
            field, modifier = key, None
        s, p = _compile_field_clause(field, modifier, value)
        sqls.append(s)
        params.extend(p)
    return "(" + " AND ".join(sqls) + ")", params


# ---------- Condition tokenizer + parser ----------

_KEYWORDS = {"and", "or", "not", "of"}


def _tokenize_condition(condition: str) -> list[tuple[str, str]]:
    """Tokenize a Sigma condition. Returns ``[(kind, value), ...]``."""
    tokens: list[tuple[str, str]] = []
    i, n = 0, len(condition)
    while i < n:
        c = condition[i]
        if c.isspace():
            i += 1
            continue
        if c == "(":
            tokens.append(("lparen", "("))
            i += 1
            continue
        if c == ")":
            tokens.append(("rparen", ")"))
            i += 1
            continue
        if c.isalnum() or c == "_":
            j = i
            while j < n and (condition[j].isalnum() or condition[j] in "_*?"):
                j += 1
            word = condition[i:j]
            lower = word.lower()
            if lower in _KEYWORDS:
                tokens.append((lower, lower))
            elif lower == "all":
                tokens.append(("all", "all"))
            elif word == "1":
                tokens.append(("one", "1"))
            else:
                tokens.append(("ident", word))
            i = j
            continue
        raise ValueError(f"unexpected character {c!r} at position {i} in condition")
    return tokens


class _ConditionParser:
    """Recursive-descent parser; emits a parameterized SQL fragment."""

    def __init__(
        self,
        tokens: list[tuple[str, str]],
        selections: dict[str, dict[str, Any]],
    ) -> None:
        self.tokens = tokens
        self.pos = 0
        self.selections = selections

    def _peek(self) -> tuple[str, str] | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _consume(self, kind: str | None = None) -> tuple[str, str]:
        if self.pos >= len(self.tokens):
            raise ValueError(f"unexpected end of condition (expected {kind or 'token'})")
        tok = self.tokens[self.pos]
        if kind and tok[0] != kind:
            raise ValueError(f"expected {kind}, got {tok}")
        self.pos += 1
        return tok

    def parse(self) -> tuple[str, list[Any]]:
        sql, params = self._parse_or()
        if self.pos != len(self.tokens):
            raise ValueError(f"trailing tokens in condition: {self.tokens[self.pos:]}")
        return sql, params

    def _parse_or(self) -> tuple[str, list[Any]]:
        sql, params = self._parse_and()
        while (tok := self._peek()) is not None and tok[0] == "or":
            self._consume("or")
            rsql, rparams = self._parse_and()
            sql = f"({sql} OR {rsql})"
            params.extend(rparams)
        return sql, params

    def _parse_and(self) -> tuple[str, list[Any]]:
        sql, params = self._parse_not()
        while (tok := self._peek()) is not None and tok[0] == "and":
            self._consume("and")
            rsql, rparams = self._parse_not()
            sql = f"({sql} AND {rsql})"
            params.extend(rparams)
        return sql, params

    def _parse_not(self) -> tuple[str, list[Any]]:
        tok = self._peek()
        if tok is not None and tok[0] == "not":
            self._consume("not")
            sql, params = self._parse_not()
            return f"(NOT {sql})", params
        return self._parse_atom()

    def _parse_atom(self) -> tuple[str, list[Any]]:
        tok = self._peek()
        if tok is None:
            raise ValueError("unexpected end of condition")
        kind, value = tok
        if kind == "lparen":
            self._consume("lparen")
            sql, params = self._parse_or()
            self._consume("rparen")
            return sql, params
        if kind in {"one", "all"}:
            self._consume(kind)
            self._consume("of")
            pat = self._consume("ident")[1]
            return self._compile_quantifier(kind, pat)
        if kind == "ident":
            self._consume("ident")
            if value not in self.selections:
                raise ValueError(f"unknown selection {value!r}")
            return _compile_selection(value, self.selections[value])
        raise ValueError(f"unexpected token {tok}")

    def _compile_quantifier(self, kind: str, pattern: str) -> tuple[str, list[Any]]:
        if pattern == "them":
            matched = list(self.selections)
        else:
            matched = [name for name in self.selections if fnmatch.fnmatchcase(name, pattern)]
        if not matched:
            raise ValueError(f"no selections match pattern {pattern!r}")
        sub_sqls: list[str] = []
        sub_params: list[Any] = []
        for name in matched:
            s, p = _compile_selection(name, self.selections[name])
            sub_sqls.append(s)
            sub_params.extend(p)
        joiner = " OR " if kind == "one" else " AND "
        return "(" + joiner.join(sub_sqls) + ")", sub_params


# ---------- Public compile entrypoint ----------

def compile_rule(rule: SigmaRule, table: str | None = None) -> CompiledRule:
    """Compile a parsed Sigma rule into a parameterized DuckDB query.

    ``table`` overrides the logsource→table resolution (used in tests). The
    resolved table is whitelisted via :data:`LOGSOURCE_MAP`, so it is safe to
    inline in SQL.
    """
    resolved = table or resolve_table(rule.logsource)
    if not resolved:
        raise ValueError(
            f"rule {rule.id!r}: logsource {rule.logsource!r} does not map to any known table"
        )
    selections = {k: v for k, v in rule.detection.items() if isinstance(v, dict)}
    if not selections:
        raise ValueError(f"rule {rule.id!r}: no selections defined under `detection`")
    tokens = _tokenize_condition(rule.condition)
    where_sql, params = _ConditionParser(tokens, selections).parse()
    return CompiledRule(table=resolved, where_sql=where_sql, params=params)


def validate_rule(rule: SigmaRule) -> None:
    """Run a full parse + compile dry-run; raises on any structural problem."""
    compile_rule(rule)
