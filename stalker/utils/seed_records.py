from __future__ import annotations

from typing import Any


def _default_site(suspect: dict[str, Any]) -> dict[str, Any]:
    return {
        "file": str(suspect.get("file", "") or ""),
        "line": int(suspect.get("line", -1) or -1),
        "role": "counterfactual_probe_site",
    }


def _record(site: dict[str, Any], variable: Any, value: Any) -> dict[str, Any]:
    normalized_site = dict(site or {})
    normalized_site.setdefault("role", "counterfactual_probe_site")
    return {
        "site": normalized_site,
        "variable": str(variable),
        "value": value,
    }


def angelic_seed_records(suspect: dict[str, Any]) -> list[dict[str, Any]]:
    records = suspect.get("angelic_seed_records")
    if isinstance(records, list):
        valid = [
            _record(item.get("site") or _default_site(suspect), item.get("variable"), item.get("value"))
            for item in records
            if isinstance(item, dict) and item.get("variable") and item.get("value") is not None
        ]
        if valid:
            return valid

    default_site = _default_site(suspect)
    out: list[dict[str, Any]] = []
    assignments = suspect.get("known_angelic_assignments") or suspect.get("known_angelic_values") or []
    if isinstance(assignments, list):
        for assignment in assignments:
            if not isinstance(assignment, dict):
                continue
            if assignment.get("variable") and assignment.get("value") is not None:
                out.append(_record(assignment.get("site") or default_site, assignment["variable"], assignment["value"]))
                continue
            for variable, value in assignment.items():
                out.append(_record(default_site, variable, value))
    if out:
        return out

    variables = list(suspect.get("variable_names", []) or [])
    legacy = suspect.get("known_angelic_values_legacy", []) or []
    if variables and isinstance(legacy, list):
        return [_record(default_site, variables[0], value) for value in legacy]
    return []


def demonic_seed_records(suspect: dict[str, Any]) -> list[dict[str, Any]]:
    records = suspect.get("demonic_seed_records")
    if isinstance(records, list):
        valid = [
            _record(item.get("site") or _default_site(suspect), item.get("variable"), item.get("value"))
            for item in records
            if isinstance(item, dict) and item.get("variable") and item.get("value") is not None
        ]
        if valid:
            return valid

    values = suspect.get("demonic_seed_values") or {}
    if isinstance(values, dict):
        default_site = _default_site(suspect)
        return [_record(default_site, variable, value) for variable, value in values.items()]
    return []


def angelic_assignment_sets(suspect: dict[str, Any]) -> list[dict[str, Any]]:
    return [{record["variable"]: record["value"]} for record in angelic_seed_records(suspect)]


def demonic_value_map(suspect: dict[str, Any]) -> dict[str, Any]:
    return {record["variable"]: record["value"] for record in demonic_seed_records(suspect)}


def record_values(records: list[dict[str, Any]]) -> list[Any]:
    return [record["value"] for record in records if record.get("value") is not None]
