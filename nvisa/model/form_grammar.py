"""Data-driven, conservative form selectors shared by binary decoders.

The selector only removes a candidate when a rule's complete preconditions
are present.  It never invents a winner: ordinary identify() logic remains
responsible for a remaining tie.  This makes an absent or malformed grammar
artifact fail closed.
"""
from __future__ import annotations

from typing import Any


class GrammarError(ValueError):
    """The generated form-grammar artifact does not satisfy its small schema."""


def validate(data: Any) -> dict:
    if not isinstance(data, dict) or data.get("schema") != 1:
        raise GrammarError("form grammar schema must be 1")
    selectors = data.get("selectors")
    if not isinstance(selectors, list):
        raise GrammarError("form grammar selectors must be a list")
    for rule in selectors:
        if not isinstance(rule, dict) or rule.get("kind") not in {
                "omit-component", "prefer-candidate", "matching-const-vs-extra-soft",
                "optional-component", "role-aware-column", "conditional-column"}:
            raise GrammarError("unsupported form grammar selector")
        if rule["kind"] == "omit-component":
            component = rule.get("component")
            if not isinstance(component, dict) or not isinstance(component.get("tag"), str):
                raise GrammarError("omit-component selector needs component.tag")
            if not isinstance(component.get("equals"), int):
                raise GrammarError("omit-component selector needs integer component.equals")
        elif rule["kind"] == "prefer-candidate":
            if rule.get("prefer") not in {"short", "long"}:
                raise GrammarError("prefer-candidate selector needs prefer")
            conditions = rule.get("conditions")
            if not isinstance(conditions, dict) or not conditions:
                raise GrammarError("prefer-candidate selector needs conditions")
            for side, checks in conditions.items():
                if side not in {"short", "long"} or not isinstance(checks, list) or not checks:
                    raise GrammarError("invalid prefer-candidate condition side")
                for check in checks:
                    if (not isinstance(check, dict) or not isinstance(check.get("tag"), str)
                            or not isinstance(check.get("equals"), int)):
                        raise GrammarError("invalid prefer-candidate condition")
        elif rule["kind"] == "optional-component":
            if not isinstance(rule.get("tags"), list) or not all(
                    isinstance(tag, str) for tag in rule["tags"]):
                raise GrammarError("optional-component selector needs tags")
            if not isinstance(rule.get("invisible_value"), int):
                raise GrammarError("optional-component selector needs invisible_value")
        elif rule["kind"] == "role-aware-column":
            pairs = rule.get("pairs")
            if not isinstance(pairs, list) or not pairs:
                raise GrammarError("role-aware selector needs form pairs")
            for pair in pairs:
                if (not isinstance(pair, dict) or not isinstance(pair.get("short"), str)
                        or not isinstance(pair.get("long"), str)):
                    raise GrammarError("role-aware form pair needs full keys")
            column = rule.get("column")
            if (not isinstance(column, dict) or not isinstance(column.get("slot"), int)
                    or not isinstance(column.get("tag"), str)
                    or column.get("role") not in {"src", "dst", "optional_dst", "optional_src"}):
                raise GrammarError("role-aware selector needs a typed predicate column")
            if column["role"] in {"optional_dst", "optional_src"}:
                vals = column.get("invisible_values")
                if not isinstance(vals, list) or not vals or not all(isinstance(v, int) for v in vals):
                    raise GrammarError("optional role needs invisible_values")
        elif rule["kind"] == "conditional-column":
            prefixes = rule.get("key_prefixes")
            if not isinstance(prefixes, list) or not prefixes or not all(isinstance(x, str) for x in prefixes):
                raise GrammarError("conditional column needs key_prefixes")
            when = rule.get("when")
            if not isinstance(when, dict) or set(when) - {"all", "xor"} or len(when) != 1:
                raise GrammarError("conditional column needs all or xor modifier condition")
            tokens = next(iter(when.values()))
            if not isinstance(tokens, list) or not tokens or not all(isinstance(x, str) for x in tokens):
                raise GrammarError("conditional column needs modifier tokens")
            shape = rule.get("column")
            if not isinstance(shape, dict) or shape.get("kind") not in {"final-predicate", "operand-shape"}:
                raise GrammarError("conditional column needs a supported shape")
            if shape["kind"] == "operand-shape":
                if not isinstance(shape.get("length"), int) or not isinstance(shape.get("drop"), list):
                    raise GrammarError("operand-shape needs length and drop")
            if not isinstance(rule.get("present"), bool):
                raise GrammarError("conditional column needs present")
        else:
            if not isinstance(rule.get("soft_kinds"), list) or not all(
                    isinstance(kind, str) for kind in rule["soft_kinds"]):
                raise GrammarError("matching-const selector needs soft_kinds")
        if rule["kind"] in {"omit-component", "prefer-candidate"}:
            pairs = rule.get("pairs")
            if not isinstance(pairs, list) or not pairs:
                raise GrammarError("form-pair selector needs pairs")
            for pair in pairs:
                if (not isinstance(pair, dict) or not isinstance(pair.get("short"), str)
                        or not isinstance(pair.get("long"), str)):
                    raise GrammarError("form pair needs short and long tokens")
    return data


def _single_token_replacement(short: str, long: str, short_token: str,
                              long_token: str) -> bool:
    """Keys can differ only by the address-form token named by the rule."""
    if short.split("_", 1)[0] != long.split("_", 1)[0]:
        return False
    s, l = short.split("_")[1:], long.split("_")[1:]
    return (len(s) == len(l)
            and sum(a != b for a, b in zip(s, l)) == 1
            and any(a == short_token and b == long_token for a, b in zip(s, l)))


def filter_candidates(keys: list[str], operands: dict[str, list[dict]],
                      grammar: dict | None) -> list[str]:
    """Apply selectors that prove one member of a form pair is noncanonical.

    ``operands`` is a typed-operand-AST adapter supplied by the decoder.  Each
    item has at least ``tag`` and ``value``.  The grammar deliberately names
    semantic tags such as ``R.Addr`` rather than physical bit positions.
    """
    if grammar is None:
        return keys
    validate(grammar)
    current = list(keys)
    for rule in grammar["selectors"]:
        if rule["kind"] not in {"omit-component", "prefer-candidate"}:
            continue
        rejected: set[str] = set()
        for pair in rule["pairs"]:
            for short in current:
                for long in current:
                    if not _single_token_replacement(short, long,
                                                     pair["short"], pair["long"]):
                        continue
                    if rule["kind"] == "omit-component":
                        component = rule["component"]
                        if any(item.get("tag") == component["tag"]
                               and item.get("value") == component["equals"]
                               for item in operands.get(long, ())):
                            rejected.add(long)
                    else:
                        conditions = rule["conditions"]
                        matches = all(
                            any(item.get("tag") == check["tag"]
                                and item.get("value") == check["equals"]
                                for item in operands.get(short if side == "short" else long, ()))
                            for side, checks in conditions.items() for check in checks)
                        if matches:
                            rejected.add(long if rule["prefer"] == "short" else short)
        kept = [key for key in current if key not in rejected]
        # A bad generated rule must not turn a candidate set into the empty
        # set; retaining the prior set is the decoder's failure-safe behavior.
        if kept:
            current = kept
    return current


def filter_matching_const_forms(keys: list[str], candidates: dict[str, dict],
                                grammar: dict | None) -> list[str]:
    """Apply the generic short-form const gate from grammar data.

    ``candidates[key]`` supplies ``slot_count`` and a per-bit cell map.  A
    matching const claim in the shorter form is direct positive evidence only
    when the longer form treats that same bit as a configured soft kind.
    """
    if grammar is None:
        return keys
    validate(grammar)
    current = list(keys)
    for rule in grammar["selectors"]:
        if rule["kind"] != "matching-const-vs-extra-soft":
            continue
        rejected: set[str] = set()
        soft_kinds = set(rule["soft_kinds"])
        for more in current:
            for less in current:
                if candidates[more]["slot_count"] <= candidates[less]["slot_count"]:
                    continue
                for bit, cell in candidates[less]["cells_by_bit"].items():
                    other = candidates[more]["cells_by_bit"].get(bit)
                    if (cell.get("kind") == "const" and cell.get("matches")
                            and other is not None and other.get("kind") in soft_kinds):
                        rejected.add(more)
                        break
        kept = [key for key in current if key not in rejected]
        if kept:
            current = kept
    return current


def filter_role_aware_columns(keys: list[str], operands: dict[str, list[dict]],
                              grammar: dict | None) -> list[str]:
    """Apply explicitly admitted P/UP source/destination visibility rules.

    A predicate value alone does not reveal whether it is printable: ``PT``
    hides an optional destination but remains a real source in forms such as
    ``HFMA2 ... !PT``.  Rules name the parser column (not its physical bits)
    and enumerate only evidence-backed full-key pairs.
    """
    if grammar is None:
        return keys
    validate(grammar)
    current = list(keys)
    for rule in grammar["selectors"]:
        if rule["kind"] != "role-aware-column":
            continue
        column = rule["column"]
        rejected: set[str] = set()
        for pair in rule["pairs"]:
            short, long = pair["short"], pair["long"]
            if short not in current or long not in current:
                continue
            value = next((item.get("value") for item in operands.get(long, ())
                          if item.get("slot") == column["slot"]
                          and item.get("tag") == column["tag"]), None)
            if value is None:
                continue
            if column["role"] in {"src", "dst"}:
                rejected.add(short)
            elif value in set(column["invisible_values"]):
                rejected.add(long)
            else:
                rejected.add(short)
        kept = [key for key in current if key not in rejected]
        if kept:
            current = kept
    return current


def _has_modifier(operands: list[dict], token: str) -> bool:
    return any(item.get("kind") == "modifier" and item.get("tag") == token
               and item.get("value") == 1 for item in operands)


def _column_shape(key: str, shape: dict) -> bool:
    parts = key.split("_")[1:]
    if shape["kind"] == "final-predicate":
        return bool(parts) and parts[-1] in {"P", "UP"}
    # Structural recipe for LEA's carry column.  It intentionally refers only
    # to parser token positions; the rule data supplies the affected families.
    for drop in shape["drop"]:
        if drop.get("where") == "last" and parts and parts[-1] in set(drop.get("tags", ())):
            parts = parts[:-1]
        elif drop.get("where") == "index":
            index = drop.get("index")
            if isinstance(index, int) and 0 <= index < len(parts) and parts[index] in set(drop.get("tags", ())):
                parts.pop(index)
    return len(parts) == shape["length"]


def filter_conditional_columns(keys: list[str], operands: dict[str, list[dict]],
                               grammar: dict | None) -> list[str]:
    """Filter forms whose printed column is controlled by semantic modifiers."""
    if grammar is None:
        return keys
    validate(grammar)
    current = list(keys)
    for rule in grammar["selectors"]:
        if rule["kind"] != "conditional-column":
            continue
        kept = []
        for key in current:
            if not any(key.startswith(prefix + "_") for prefix in rule["key_prefixes"]):
                kept.append(key)
                continue
            kind, tokens = next(iter(rule["when"].items()))
            hits = [_has_modifier(operands.get(key, ()), token) for token in tokens]
            enabled = all(hits) if kind == "all" else sum(hits) == 1
            if _column_shape(key, rule["column"]) == (enabled == rule["present"]):
                kept.append(key)
        if kept:
            current = kept
    return current


def pick_optional_component_form(keys: list[str], operands: dict[str, list[dict]],
                                 grammar: dict | None) -> str | None:
    """Select a form whose only extra typed components are visible or invisible.

    This faithfully expresses the current PT/UPT rule without claiming whether
    an individual predicate is a source or destination; that role refinement
    belongs to P3.
    """
    if grammar is None:
        return None
    validate(grammar)
    rules = [rule for rule in grammar["selectors"] if rule["kind"] == "optional-component"]
    if not rules or not keys:
        return None
    # P1 has one admitted compatibility rule.  Multiple role-aware rules will
    # be composed explicitly in P3 rather than relying on an arbitrary order.
    rule = rules[0]
    tags, invisible = set(rule["tags"]), rule["invisible_value"]

    def components(key: str) -> dict[tuple[int | None, str], int]:
        return {(item.get("slot"), item.get("tag")): item.get("value")
                for item in operands.get(key, ()) if item.get("tag") in tags}

    cur = keys[0]
    for other in keys[1:]:
        a, b = components(cur), components(other)
        if set(a) > set(b):
            more, less, extra = cur, other, set(a) - set(b)
            values = a
        elif set(b) > set(a):
            more, less, extra = other, cur, set(b) - set(a)
            values = b
        else:
            return None
        cur = less if all(values[item] == invisible for item in extra) else more
    return cur
