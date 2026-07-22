from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class InterventionHandle:
    name: str
    kind: str
    declared_type: str
    priority: int = 0


def infer_intervention_handles(suspect_object: dict[str, Any]) -> list[InterventionHandle]:
    declared_type = str(
        suspect_object.get("debugger_reported_type")
        or suspect_object.get("llm_inferred_type")
        or "unknown"
    ).strip()
    variable_names = [str(name).strip() for name in suspect_object.get("variable_names", []) or [] if str(name).strip()]
    context_variables = suspect_object.get("context_variables", {}) or {}
    context_names = [str(name).strip() for name in context_variables.keys() if str(name).strip()]
    ordered_names = _unique(variable_names + context_names)
    handles: list[InterventionHandle] = []
    for idx, name in enumerate(ordered_names):
        kind = _classify_handle(name=name, declared_type=declared_type, primary=(idx == 0))
        handles.append(
            InterventionHandle(
                name=name,
                kind=kind,
                declared_type=declared_type,
                priority=_priority_for_kind(kind, primary=(idx == 0)),
            )
        )
    handles.sort(key=lambda handle: (-handle.priority, handle.name))
    return handles


def choose_primary_handle(handles: list[InterventionHandle]) -> InterventionHandle | None:
    return handles[0] if handles else None


def find_handle(handles: list[InterventionHandle], name: str) -> InterventionHandle | None:
    target = str(name or "").strip()
    for handle in handles:
        if handle.name == target:
            return handle
    return None


def should_skip_debugger_type_probe(suspect_object: dict[str, Any]) -> bool:
    inferred = str(suspect_object.get("llm_inferred_type") or "").strip()
    debugger_reported = str(suspect_object.get("debugger_reported_type") or "").strip()
    if debugger_reported and debugger_reported.lower() != "unknown":
        return True
    if not inferred or inferred.lower() == "unknown":
        return False
    handles = infer_intervention_handles(suspect_object)
    if not handles:
        return False
    return any(handle.kind in {"pointer_slot", "pointer_boundary", "size_slot"} for handle in handles)


def _classify_handle(name: str, declared_type: str, primary: bool) -> str:
    lower = name.lower()
    normalized_type = declared_type.lower()
    boundary_like = any(token in lower for token in ("end", "limit", "bound", "stop"))
    size_like = any(token in lower for token in ("len", "size", "count", "offset", "idx", "index", "cap", "remaining"))
    pointer_like = "*" in normalized_type or any(token in lower for token in ("ptr", "cursor", "buf", "data", "base"))

    if pointer_like and boundary_like:
        return "pointer_boundary"
    if size_like:
        return "size_slot"
    if pointer_like:
        return "pointer_slot"
    if primary:
        return "scalar_slot"
    return "scalar_slot"


def _priority_for_kind(kind: str, primary: bool) -> int:
    base = {
        "pointer_slot": 90,
        "pointer_boundary": 85,
        "size_slot": 80,
        "scalar_slot": 70,
    }.get(kind, 50)
    if primary:
        base += 10
    return base


def _unique(items: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out
