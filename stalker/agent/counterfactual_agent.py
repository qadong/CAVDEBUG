import hashlib
import json
import os
import re
from dataclasses import asdict
from typing import Any, List

from agent import debug_agent
from agent.contracts import CounterfactualContract, RootCauseReport
from agent.generic_agent import GenericAgent
from agent.prompts import (
    COUNTERFACTUAL_INVARIANT_INITIAL_PROMPT,
    COUNTERFACTUAL_INVARIANT_SYSTEM_PROMPT,
    build_debugger_session_protocol,
)
from tools.debugger.functions import (
    debugger_add_functional_guard,
    debugger_assign,
    debugger_assign_expression,
    debugger_continue,
    debugger_run_to_line,
)
from utils.files import dump_json
from utils.logger import get_logger
from utils.parsers import check_sanitizer_error
from utils.seed_records import angelic_seed_records, demonic_seed_records


NAME = "agent-counterfactual"
AGENT_STATE: dict[str, Any] = {
    "context": None,
    "contract": None,
    "actions": set(),
    "action_version": 0,
    "action_counts": {},
    "failed_interventions": [],
    "submit_block": None,
}


SANITIZER_KIND_RE = re.compile(
    r"(AddressSanitizer|MemorySanitizer|UndefinedBehaviorSanitizer|LeakSanitizer|ThreadSanitizer|runtime error)",
    re.IGNORECASE,
)


def reset_agent_state() -> None:
    AGENT_STATE["context"] = None
    AGENT_STATE["contract"] = None
    AGENT_STATE["actions"] = set()
    AGENT_STATE["action_version"] = 0
    AGENT_STATE["action_counts"] = {}
    AGENT_STATE["failed_interventions"] = []
    AGENT_STATE["submit_block"] = None
SANITIZER_ERROR_RE = re.compile(
    r"(AddressSanitizer|MemorySanitizer|UndefinedBehaviorSanitizer|LeakSanitizer|ThreadSanitizer):\s*([A-Za-z0-9_-]+)",
    re.IGNORECASE,
)


def _clean_list(value: Any, limit: int = 12) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for item in value:
        text = str(item).strip()
        if text and text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _bug_type(suspect: dict[str, Any], report: RootCauseReport | None) -> str:
    if report is not None and report.bug_type:
        return str(report.bug_type)
    profile = suspect.get("bug_type_profile") if isinstance(suspect.get("bug_type_profile"), dict) else {}
    return str(profile.get("bug_type", "unknown") or "unknown")


def _surface_bug_type_from_reproduce(reproduce_result: dict[str, Any] | None) -> str:
    text = str((reproduce_result or {}).get("error", "") or (reproduce_result or {}).get("output", "") or "").lower()
    if any(token in text for token in ("stack-buffer-overflow", "heap-buffer-overflow", "global-buffer-overflow", "container-overflow")):
        return "out_of_bounds"
    if "null" in text and any(token in text for token in ("segv", "dereference", "member access")):
        return "null_pointer_dereference"
    if "use-after-free" in text:
        return "use_after_free"
    if "double-free" in text:
        return "double_free"
    return ""


def _site_from_suspect(suspect: dict[str, Any], role: str) -> dict[str, Any]:
    return {
        "file": str(suspect.get("file", "") or ""),
        "line": int(suspect.get("line", -1) or -1),
        "function": str(suspect.get("function_name", "") or ""),
        "expression": str(suspect.get("crash_expression", "") or ""),
        "access_type": str(suspect.get("access_type", "unknown") or "unknown"),
        "role": role,
    }


def _normalize_enforcement_role(role: str, preferred_stage: str) -> str:
    text = f"{role} {preferred_stage}".lower()
    if any(token in text for token in ("init", "constructor")):
        return "init_path"
    if any(token in text for token in ("ownership", "lifetime", "free", "transfer")):
        return "ownership_transfer"
    if any(token in text for token in ("guard", "check", "validation", "input")):
        return "existing_guard"
    if any(token in text for token in ("state", "transition", "update")):
        return "state_transition"
    if any(token in text for token in ("api", "caller", "callee")):
        return "api_boundary"
    if any(token in text for token in ("root_cause", "producer", "upstream", "allocation", "extent")):
        return "producer"
    if any(token in text for token in ("same_site", "crash")):
        return "crash_site_last_resort"
    return "producer"


def _enforcement_site(suspect: dict[str, Any], report: RootCauseReport | None) -> tuple[dict[str, Any], str]:
    preferred = {}
    if report is not None and report.preferred_edit_location:
        preferred = dict(report.preferred_edit_location)
    if not preferred:
        preferred = dict(suspect.get("preferred_edit_location", {}) or {})
    if not preferred:
        candidates = suspect.get("candidate_edit_locations", []) or []
        preferred = dict(candidates[0]) if candidates and isinstance(candidates[0], dict) else {}
    if not preferred:
        preferred = _site_from_suspect(suspect, "crash_site_last_resort")

    preferred_stage = str(
        (report.preferred_repair_stage if report is not None else "")
        or suspect.get("preferred_repair_stage", "")
        or ""
    )
    role = _normalize_enforcement_role(str(preferred.get("role", "")), preferred_stage)
    site = {
        "file": str(preferred.get("file") or suspect.get("file", "") or ""),
        "line": int(preferred.get("line") or suspect.get("line", -1) or -1),
        "function": str(preferred.get("function") or preferred.get("function_name") or suspect.get("function_name", "") or ""),
        "role": role,
        "why_here": str(preferred.get("why_here", "") or "Source-level repair should maintain the invariant here."),
    }
    return site, role


def _boundary_kind(bug_type: str, suspect: dict[str, Any]) -> str:
    text = " ".join(
        [
            bug_type,
            str(suspect.get("debug_summary", "")),
            " ".join(_clean_list(suspect.get("variable_names", []))),
        ]
    ).lower()
    if any(token in text for token in ("use-after-free", "lifetime", "alive", "free")):
        return "alive_until_use"
    if any(token in text for token in ("uninitialized", "initializ")):
        return "initialized"
    if any(token in text for token in ("null", "nullptr")):
        return "non_null"
    if any(token in text for token in ("capacity", "allocation", "push", "append")):
        return "capacity_before_push"
    if any(token in text for token in ("offset", "index", "bound", "length", "len", "size", "out_of_bounds")):
        return "strict_upper_bound"
    return "unknown"


def _boundary_predicate(kind: str, variables: list[str]) -> str:
    names = [name for name in variables if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name)]
    lower = {name.lower(): name for name in names}
    if kind == "non_null" and names:
        return f"{names[0]} != NULL"
    if kind == "initialized" and names:
        return f"initialized({names[0]})"
    if kind == "alive_until_use" and names:
        return f"alive({names[0]}) at use({names[0]})"
    if kind in {"strict_upper_bound", "capacity_before_push"}:
        lhs = next((lower[key] for key in ("idx", "index", "offset", "pos") if key in lower), names[0] if names else "")
        rhs = next((lower[key] for key in ("len", "length", "size", "count", "capacity", "end") if key in lower and lower[key] != lhs), "")
        if lhs and rhs:
            return f"{lhs} < {rhs}"
    return ""


def _default_boundary_audit(source: str = "unknown", semantic_status: str = "unknown") -> dict[str, Any]:
    return {
        "derived_from": source,
        "only_sufficient_to_avoid_current_crash": source in {"crash_site_memory_capacity", "crash_avoidance_boundary"},
        "explains_invalid_state_producer": False,
        "stricter_semantic_contract": "unknown",
        "semantic_repair_status": semantic_status,
    }


def _normalize_boundary_audit(raw: Any, fallback_source: str = "unknown") -> tuple[dict[str, Any], str]:
    allowed_sources = {
        "crash_site_memory_capacity",
        "crash_avoidance_boundary",
        "object_or_type_api_contract",
        "parser_format_validity",
        "cache_lifetime_ownership",
        "producer_side_state_transition",
        "unknown",
    }
    audit = dict(raw or {}) if isinstance(raw, dict) else {}
    source = str(audit.get("derived_from", "") or fallback_source or "unknown")
    if source not in allowed_sources:
        source = "unknown"
    crash_only = bool(audit.get("only_sufficient_to_avoid_current_crash", source in {"crash_site_memory_capacity", "crash_avoidance_boundary"}))
    producer = bool(audit.get("explains_invalid_state_producer", False))
    stricter = str(audit.get("stricter_semantic_contract", "unknown") or "unknown").lower()
    if stricter not in {"yes", "no", "unknown"}:
        stricter = "unknown"
    status = str(audit.get("semantic_repair_status", "") or "").lower()
    if not status:
        if crash_only or source in {"crash_site_memory_capacity", "crash_avoidance_boundary"}:
            status = "crash_containment_only"
        elif producer or source in {"object_or_type_api_contract", "parser_format_validity", "cache_lifetime_ownership", "producer_side_state_transition"}:
            status = "semantic_repair_candidate"
        else:
            status = "unknown"
    if status not in {"semantic_repair_candidate", "crash_containment_only", "unknown"}:
        status = "unknown"
    normalized = {
        "derived_from": source,
        "only_sufficient_to_avoid_current_crash": crash_only,
        "explains_invalid_state_producer": producer,
        "stricter_semantic_contract": stricter,
        "semantic_repair_status": status,
    }
    note = str(audit.get("rationale", "") or audit.get("note", "") or "").strip()
    if note:
        normalized["rationale"] = note
    return normalized, status


def _known_angelic_observations(suspect: dict[str, Any], intervention_site: dict[str, Any]) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    for item in angelic_seed_records(suspect)[:8]:
        variable = item["variable"]
        value = str(item["value"])
        observations.append(
            {
                "intervention": f"{variable} = {value}",
                "classification": "inconclusive",
                "outcome": "inconclusive",
                "before_state": "observed unsafe value",
                "after_state": value,
                "target_crash_status": "inconclusive",
                "other_failure": "",
                "rationale": "Site-specific seed reported by DebugAgent; not a verified counterfactual observation.",
                "site": dict(item.get("site") or intervention_site),
                "state_delta": {variable: {"before": "observed unsafe value", "after": value}},
                "is_proxy_value": True,
                "notes": "Site-specific seed reported by DebugAgent; target crash status must be confirmed by validation.",
            }
        )
    return observations


def _sanitizer_signature(text: str) -> str:
    if "DEADLYSIGNAL" in text.upper():
        return "signal"
    match = SANITIZER_ERROR_RE.search(text)
    if match:
        return f"{match.group(1).lower()}:{match.group(2).lower()}"
    match = SANITIZER_KIND_RE.search(text)
    if match:
        return match.group(1).lower()
    return ""


def _target_signature(reproduce_result: dict[str, Any] | None) -> str:
    text = str((reproduce_result or {}).get("error", "") or "")
    return _sanitizer_signature(text)


def _output_signature(target_output: str, lldb_output: dict[str, Any]) -> str:
    text = f"{target_output}\n{lldb_output}"
    signature = _sanitizer_signature(text)
    if signature:
        return signature
    if str(lldb_output.get("reason", "")) == "signal-received":
        return str(lldb_output.get("signal_name", "") or "signal").lower()
    return ""


def _classify_probe_result(
    lldb_output: dict[str, Any],
    target_output: str,
    target_signature: str,
) -> tuple[str, str, str]:
    reason = str((lldb_output or {}).get("reason", "") or "")
    has_sanitizer, sanitizer_msg = check_sanitizer_error(target_output, lldb_output or {})
    signature = _output_signature(target_output, lldb_output or {})
    if has_sanitizer or reason == "signal-received":
        if target_signature == "signal" and reason == "signal-received":
            return "demonic", "persisted", sanitizer_msg or f"stop: {reason}"
        if target_signature and signature and target_signature == signature:
            return "demonic", "persisted", sanitizer_msg or f"stop: {reason}"
        return "inconclusive", "changed", sanitizer_msg or f"stop: {reason}"
    if reason == "exited-normally":
        return "angelic", "disappeared", ""
    if reason == "breakpoint-hit":
        return "inconclusive", "inconclusive", "Execution stopped at another breakpoint; target crash disappearance is not proven."
    if reason in {"error", ""}:
        return "inconclusive", "inconclusive", str((lldb_output or {}).get("error", "") or "debugger did not provide a conclusive stop reason")
    return "inconclusive", "inconclusive", f"stop: {reason}"


def _probe_specs(suspect: dict[str, Any], limit: int) -> list[dict[str, Any]]:
    specs: list[dict[str, Any]] = []
    for item in angelic_seed_records(suspect)[:limit]:
        specs.append(
            {
                "variable": item["variable"],
                "value": str(item["value"]),
                "site": dict(item.get("site") or {}),
                "source": "angelic_seed_records",
            }
        )
    return specs


def _apply_probe_assignment(variable: str, value: str) -> tuple[bool, str]:
    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", variable):
        return debugger_assign(variable, value)
    return debugger_assign_expression(f"{variable} = {value}")


def run_counterfactual_probes(
    suspect: dict[str, Any],
    intervention_site: dict[str, Any],
    reproduce_result: dict[str, Any] | None = None,
    probe_budget: int = 3,
    logger=None,
) -> list[dict[str, Any]]:
    default_file = str(intervention_site.get("file", "") or suspect.get("file", "") or "")
    default_line = int(intervention_site.get("line", -1) or -1)
    if not default_file or default_line <= 0 or probe_budget <= 0:
        return []
    target_signature = _target_signature(reproduce_result)
    observations: list[dict[str, Any]] = []
    for spec in _probe_specs(suspect, limit=probe_budget):
        variable = spec["variable"]
        value = spec["value"]
        site = dict(spec.get("site") or intervention_site)
        file = str(site.get("file", "") or default_file)
        line = int(site.get("line", -1) or default_line)
        state_delta = {variable: {"before": "observed unsafe value", "after": value}}
        try:
            lldb_at, target_at = debugger_run_to_line(file, line)
            if str(lldb_at.get("reason", "")) != "breakpoint-hit":
                observations.append(
                    {
                        "intervention": f"{variable} = {value}",
                        "outcome": "inconclusive",
                        "target_crash_status": "inconclusive",
                        "other_failure": target_at or str(lldb_at.get("error", "") or lldb_at.get("reason", "")),
                        "site": site,
                        "state_delta": state_delta,
                        "is_proxy_value": True,
                        "notes": "Counterfactual probe could not reach the intervention site.",
                    }
                )
                continue
            applied, apply_msg = _apply_probe_assignment(variable, value)
            if not applied:
                observations.append(
                    {
                        "intervention": f"{variable} = {value}",
                        "outcome": "inconclusive",
                        "target_crash_status": "inconclusive",
                        "other_failure": apply_msg,
                        "site": site,
                        "state_delta": state_delta,
                        "is_proxy_value": True,
                        "notes": "Counterfactual assignment failed.",
                    }
                )
                continue
            lldb_after, target_after = debugger_continue()
            outcome, target_status, other_failure = _classify_probe_result(lldb_after, target_after, target_signature)
            observations.append(
                {
                    "intervention": f"{variable} = {value}",
                    "outcome": outcome,
                    "target_crash_status": target_status,
                    "other_failure": other_failure,
                    "site": site,
                    "state_delta": state_delta,
                    "is_proxy_value": True,
                    "notes": f"Debugger-backed counterfactual probe from {spec['source']}.",
                }
            )
        except Exception as exc:
            if logger is not None:
                logger.warning("Counterfactual probe failed for %s = %s: %s", variable, value, exc)
            observations.append(
                {
                    "intervention": f"{variable} = {value}",
                    "outcome": "inconclusive",
                    "target_crash_status": "inconclusive",
                    "other_failure": str(exc),
                    "site": site,
                    "state_delta": state_delta,
                    "is_proxy_value": True,
                    "notes": "Counterfactual probe raised an exception.",
                }
            )
    return observations


def build_counterfactual_contract(
    suspect: dict[str, Any],
    root_cause_report: RootCauseReport | None,
    hypothesis_id: str,
    reproduce_result: dict[str, Any] | None = None,
    run_probes: bool = False,
    probe_budget: int = 3,
    logger=None,
) -> CounterfactualContract:
    bug_type = _bug_type(suspect, root_cause_report)
    variables = _clean_list(suspect.get("variable_names", []))
    crash_site = dict(suspect.get("crash_site", {}) or {}) or _site_from_suspect(suspect, "crash_site")
    crash_site["role"] = "crash_site"
    intervention_site = _site_from_suspect(suspect, "counterfactual_probe_site")
    intervention_site["why_here"] = "Runtime state can be modified here to test whether the suspected unsafe state is causal."
    enforcement_site, enforcement_priority = _enforcement_site(suspect, root_cause_report)
    kind = _boundary_kind(bug_type, suspect)
    predicate = _boundary_predicate(kind, variables)
    summary = str(suspect.get("debug_summary", "") or "").strip()
    repair_intent = (
        str(root_cause_report.operational_repair_intent or root_cause_report.direct_patch_contract)
        if root_cause_report is not None
        else ""
    )
    if not repair_intent:
        repair_intent = "Restore the invariant represented by the counterfactual safe state before the crash site consumes it."
    invariant = predicate or repair_intent
    profile = suspect.get("bug_type_profile") if isinstance(suspect.get("bug_type_profile"), dict) else {}
    contract_id_seed = f"{hypothesis_id}:{crash_site.get('file')}:{crash_site.get('line')}:{invariant}"
    angelic_observations = []
    if run_probes:
        angelic_observations = run_counterfactual_probes(
            suspect,
            intervention_site,
            reproduce_result=reproduce_result,
            probe_budget=probe_budget,
            logger=logger,
        )
    if not angelic_observations:
        angelic_observations = _known_angelic_observations(suspect, intervention_site)
    forbidden_literals = []
    for observation in angelic_observations:
        for delta in (observation.get("state_delta") or {}).values():
            if isinstance(delta, dict) and delta.get("after"):
                forbidden_literals.append(str(delta["after"]))
    validation = list(profile.get("validation_obligations", []) or [])
    if "Confirm the target crash disappears while unrelated sanitizer noise is separated from target crash status." not in validation:
        validation.append("Confirm the target crash disappears while unrelated sanitizer noise is separated from target crash status.")
    demonic_observations = [
        {
            "intervention": "original execution",
            "classification": "demonic",
            "outcome": "demonic",
            "before_state": "original unsafe state",
            "after_state": "original unsafe state",
            "target_crash_status": "persisted",
            "other_failure": "",
            "rationale": "Original reproduced crash state.",
            "site": crash_site,
            "state_delta": {},
            "is_proxy_value": False,
            "notes": "Original reproduced crash state.",
        }
    ]
    boundary_audit, semantic_status = _normalize_boundary_audit(
        suspect.get("boundary_audit"),
        fallback_source="crash_avoidance_boundary" if angelic_observations else "unknown",
    )
    return CounterfactualContract(
        contract_id="cfc-" + hashlib.sha1(contract_id_seed.encode("utf-8", errors="ignore")).hexdigest()[:10],
        hypothesis_id=hypothesis_id,
        bug_type=bug_type,
        repair_class=str(suspect.get("preferred_repair_stage", "") or (root_cause_report.preferred_repair_stage if root_cause_report else "") or kind),
        evidence_family=str(profile.get("evidence_family", "") or (root_cause_report.evidence_family if root_cause_report else "") or "counterfactual"),
        counterfactual_kind=str(profile.get("evidence_kind", "") or (root_cause_report.evidence_kind if root_cause_report else "") or kind),
        crash_site=crash_site,
        intervention_site=intervention_site,
        enforcement_site=enforcement_site,
        enforcement_priority=enforcement_priority,
        suspect_variables=variables,
        suspect_objects=_clean_list(suspect.get("suspect_objects", [])),
        observed_unsafe_state=dict(suspect.get("context_variables", {}) or {}),
        unsafe_condition=predicate or summary,
        baseline_facts=[summary] if summary else [],
        angelic_observations=angelic_observations,
        demonic_observations=demonic_observations,
        boundary_kind=kind,
        boundary_predicate=predicate,
        boundary_summary=summary,
        boundary_audit=boundary_audit,
        semantic_repair_status=semantic_status,
        repair_invariant=invariant,
        contract_scope=str(suspect.get("contract_scope", "") or summary or f"{bug_type} repair for {crash_site.get('function', '')}"),
        invariant_scope=str(suspect.get("contract_scope", "") or summary or f"{bug_type} repair for {crash_site.get('function', '')}"),
        affected_operations=_clean_list(suspect.get("affected_operations", []) or [str(suspect.get("function_name", "") or "")]),
        enforcement_role_preference=[enforcement_priority] if enforcement_priority else [],
        executable_predicate=predicate,
        repair_intent=repair_intent,
        patch_strategy_hint=str(suspect.get("preferred_repair_stage", "") or (root_cause_report.preferred_repair_stage if root_cause_report else "") or ""),
        avoid_patch_patterns=list(suspect.get("forbidden_fix_patterns", []) or []),
        forbidden_patch_patterns=list(suspect.get("forbidden_fix_patterns", []) or []),
        forbidden_literals=list(dict.fromkeys(forbidden_literals)),
        validation_obligations=validation,
        rationale=summary or "Counterfactual contract derived from DebugAgent suspect state.",
    )


def contract_to_dict(contract: CounterfactualContract) -> dict[str, Any]:
    return asdict(contract)


def _submitted_site(site: dict[str, Any], role: str) -> dict[str, Any]:
    normalized = dict(site or {})
    normalized["file"] = str(normalized.get("file", "") or "")
    try:
        normalized["line"] = int(normalized.get("line", -1) or -1)
    except (TypeError, ValueError):
        normalized["line"] = -1
    normalized["role"] = role
    return normalized


def _submitted_observations(
    observations: List[dict],
    default_site: dict[str, Any],
) -> tuple[list[dict[str, Any]], str]:
    allowed_statuses = {"disappeared", "persisted", "changed", "inconclusive"}
    allowed_classifications = {"angelic", "demonic", "inconclusive"}
    normalized: list[dict[str, Any]] = []
    for index, raw in enumerate(observations or []):
        item = dict(raw or {})
        status = str(item.get("target_crash_status", "") or "").lower()
        if status not in allowed_statuses:
            return [], f"Observation {index} has invalid target_crash_status: {status or '<missing>'}."
        classification = str(item.get("classification", "") or item.get("outcome", "") or "").lower()
        if classification not in allowed_classifications:
            return [], f"Observation {index} has invalid classification: {classification or '<missing>'}."
        item["target_crash_status"] = status
        item["classification"] = classification
        item["outcome"] = classification
        item["intervention"] = str(item.get("intervention", "") or "")
        item["before_state"] = str(item.get("before_state", "") or "")
        item["after_state"] = str(item.get("after_state", "") or "")
        item["other_failure"] = str(item.get("other_failure", "") or "")
        item["rationale"] = str(item.get("rationale", "") or "")
        item["site"] = dict(item.get("site") or default_site)
        item["state_delta"] = dict(item.get("state_delta") or {})
        normalized.append(item)
    return normalized, ""


def _submit_observation(message: str, required_tools: list[str]) -> str:
    AGENT_STATE["submit_block"] = {
        "action_version": int(AGENT_STATE.get("action_version", 0) or 0),
        "required_tools": list(required_tools),
    }
    tools = ", ".join(f"`{name}`" for name in required_tools)
    return (
        "SUBMIT_STATUS=NEEDS_MORE_EVIDENCE. "
        + message
        + f" Before submitting again, your next tool call MUST be a non-submit tool from: {tools}. "
        "Do not output CounterfactualInvariant as plain text and do not reply TERMINATE."
    )


def _repeated_submit_observation() -> str | None:
    block = AGENT_STATE.get("submit_block")
    if not isinstance(block, dict):
        return None
    if int(block.get("action_version", -1)) != int(AGENT_STATE.get("action_version", 0) or 0):
        return None
    tools = ", ".join(f"`{name}`" for name in block.get("required_tools", []))
    return (
        "SUBMIT_STATUS=REPEATED_SUBMIT_REJECTED. No required debugger/source action occurred after the previous "
        f"submit rejection. Your next tool call MUST be one of: {tools}. Do not call a submit tool and do not reply TERMINATE."
    )


def _failed_intervention_observations(default_site: dict[str, Any]) -> list[dict[str, Any]]:
    observations = []
    seen = set()
    for item in AGENT_STATE.get("failed_interventions", []) or []:
        key = (str(item.get("tool", "")), str(item.get("intervention", "")))
        if key in seen:
            continue
        seen.add(key)
        observations.append(
            {
                "intervention": str(item.get("intervention", "") or item.get("tool", "failed intervention")),
                "before_state": "runtime state at the attempted intervention site",
                "after_state": "intervention was not applied",
                "target_crash_status": "inconclusive",
                "classification": "inconclusive",
                "outcome": "inconclusive",
                "other_failure": str(item.get("error", "") or "intervention failed"),
                "rationale": "Recorded directly from a failed debugger intervention; no crash outcome is claimed.",
                "site": dict(item.get("site") or default_site),
                "state_delta": {},
            }
        )
    return observations


def _contains_fabricated_terminal_observation(observations: list[dict[str, Any]]) -> bool:
    conceptual_markers = ("conceptual", "hypothetical", "not applied", "no live injection", "would ")
    for item in observations:
        text = " ".join(
            str(item.get(key, "") or "").lower()
            for key in ("intervention", "before_state", "after_state", "other_failure", "rationale")
        )
        if any(marker in text for marker in conceptual_markers) and item.get("target_crash_status") in {"disappeared", "persisted"}:
            return True
    return False


def submit_counterfactual_invariant(
    bug_type: str,
    repair_class: str,
    unsafe_condition: str,
    baseline_facts: List[str],
    angelic_observations: List[dict],
    demonic_observations: List[dict],
    boundary_summary: str,
    boundary_audit: Any,
    repair_invariant: str,
    invariant_scope: str,
    enforcement_role_preference: List[str],
    forbidden_patch_patterns: List[str],
    forbidden_literals: List[str],
    validation_obligations: List[str],
    rationale: str,
) -> str:
    """Submit the debugger-backed counterfactual invariant for PatchAgent."""
    logger = get_logger(NAME)
    context = AGENT_STATE.get("context")
    if not isinstance(context, dict):
        return "Counterfactual agent context is not initialized."
    repeated_rejection = _repeated_submit_observation()
    if repeated_rejection:
        return repeated_rejection

    suspect = context["suspect"]
    report = context.get("root_cause_report")
    intervention = _site_from_suspect(suspect, "counterfactual_probe_site")
    angelic, error = _submitted_observations(angelic_observations, intervention)
    if error:
        return error
    demonic, error = _submitted_observations(demonic_observations, intervention)
    if error:
        return error
    insufficient_expansion = str(boundary_summary or "").strip().lower().startswith("insufficient counterfactual expansion")
    if not angelic and not insufficient_expansion:
        return "Submit at least one angelic observation, or mark boundary_summary as insufficient counterfactual expansion."
    if not demonic and not insufficient_expansion:
        return "Submit at least one demonic observation, or mark boundary_summary as insufficient counterfactual expansion."
    if not str(repair_invariant or "").strip():
        return "repair_invariant is required."
    if not str(invariant_scope or "").strip():
        return "invariant_scope is required."
    if not str(unsafe_condition or "").strip():
        return "unsafe_condition is required."
    if not isinstance(boundary_audit, dict) or not boundary_audit:
        return (
            "boundary_audit must be a non-empty JSON object, not a string or list. Example: "
            '{"derived_from":"unknown","only_sufficient_to_avoid_current_crash":false,'
            '"explains_invalid_state_producer":false,"stricter_semantic_contract":"unknown",'
            '"semantic_repair_status":"unknown"}.'
        )
    audit, semantic_status = _normalize_boundary_audit(boundary_audit)
    actions = AGENT_STATE.get("actions") if isinstance(AGENT_STATE.get("actions"), set) else set()
    failed_interventions = list(AGENT_STATE.get("failed_interventions", []) or [])
    distinct_failed_interventions = {
        (str(item.get("tool", "")), str(item.get("intervention", "")))
        for item in failed_interventions
    }
    tentative_unavailable = (
        insufficient_expansion
        and "intervention" not in actions
        and len(distinct_failed_interventions) >= 2
    )
    if "intervention" not in actions:
        if not tentative_unavailable:
            remaining = max(0, 2 - len(distinct_failed_interventions))
            return _submit_observation(
                "Continue this same CounterfactualContractAgent session and keep the current report as a draft. "
                "Perform a successful debugger intervention and continue execution. If debugger intervention is genuinely "
                f"unavailable, make {remaining or 'additional'} concrete intervention attempt(s) using a different target, "
                "expression, or supplied probe site; do not invent conceptual outcomes. After two recorded failures, inspect "
                "source and submit a tentative report whose boundary_summary starts with `insufficient counterfactual expansion`. ",
                ["run_to_line", "debugger_assign", "debugger_assign_expression", "apply_angelic_operation"],
            )
    elif "post_intervention_execution" not in actions:
        return _submit_observation(
            "A successful intervention was recorded, but execution was not continued. Continue this same session and keep "
            "the current report as a draft. Run the reproducer, classify the real outcome, expand nearby values, and revise "
            "the observations and boundary report. ",
            ["debugger_continue"],
        )
    elif not angelic and not demonic:
        return _submit_observation(
            "The intervention and continuation were performed, but the report still has no observations. Add the actual "
            "intervention outcome to the report and perform another nearby probe when possible. ",
            ["run_to_line", "debugger_assign", "debugger_assign_expression", "apply_angelic_operation"],
        )
    elif _contains_fabricated_terminal_observation(angelic + demonic):
        return _submit_observation(
            "The report claims `disappeared` or `persisted` for a conceptual/hypothetical intervention. Those terminal "
            "statuses require an executed debugger intervention followed by `debugger_continue`; otherwise record the "
            "attempt as `inconclusive` with its real tool failure. ",
            ["run_to_line", "debugger_assign", "debugger_assign_expression", "apply_angelic_operation", "debugger_continue"],
        )
    if "source_inspection" not in actions:
        return _submit_observation(
            "Continue this same session and inspect the producer, guard, init path, or ownership-transfer source. Then "
            "revise the enforcement roles, boundary audit, repair invariant, and rationale. ",
            ["file_content", "search_in_repo", "debugger_backtrace"],
        )
    if tentative_unavailable:
        angelic = _failed_intervention_observations(intervention)
        demonic = []
        audit["semantic_repair_status"] = "unknown"
        audit["stricter_semantic_contract"] = "unknown"
        semantic_status = "unknown"

    AGENT_STATE["submit_block"] = None

    profile = suspect.get("bug_type_profile") if isinstance(suspect.get("bug_type_profile"), dict) else {}
    crash_site = dict(suspect.get("crash_site", {}) or {}) or _site_from_suspect(suspect, "crash_site")
    crash_site["role"] = "crash_site"
    enforcement_site, enforcement_priority = _enforcement_site(suspect, report)
    invariant = str(repair_invariant).strip()
    contract_id_seed = f"{context['hypothesis_id']}:{crash_site.get('file')}:{crash_site.get('line')}:{invariant}"
    obligations = [str(item) for item in (validation_obligations or []) if str(item).strip()]
    target_obligation = "Confirm the target crash disappears while unrelated sanitizer noise is separated from target crash status."
    if target_obligation not in obligations:
        obligations.append(target_obligation)
    if semantic_status != "semantic_repair_candidate":
        semantic_obligation = (
            "Boundary audit marks this as crash containment or unknown; before patching, search for a stricter "
            "format/API/lifetime/producer-side semantic contract and do not implement the crash-free value literally."
        )
        if semantic_obligation not in obligations:
            obligations.append(semantic_obligation)

    contract = CounterfactualContract(
        contract_id="cfc-" + hashlib.sha1(contract_id_seed.encode("utf-8", errors="ignore")).hexdigest()[:10],
        hypothesis_id=context["hypothesis_id"],
        bug_type=str(bug_type or _bug_type(suspect, report)),
        repair_class=str(repair_class or ""),
        evidence_family=str(profile.get("evidence_family", "") or (report.evidence_family if report else "") or "counterfactual"),
        counterfactual_kind=str(profile.get("evidence_kind", "") or (report.evidence_kind if report else "") or repair_class or "counterfactual_invariant"),
        crash_site=crash_site,
        intervention_site=intervention,
        enforcement_site=enforcement_site,
        enforcement_priority=str(enforcement_priority or ""),
        suspect_variables=_clean_list(suspect.get("variable_names", [])),
        suspect_objects=_clean_list(suspect.get("suspect_objects", [])),
        observed_unsafe_state=dict(suspect.get("context_variables", {}) or {}),
        unsafe_condition=str(unsafe_condition or ""),
        baseline_facts=_clean_list(baseline_facts or [], limit=20),
        angelic_observations=angelic,
        demonic_observations=demonic,
        boundary_kind=str(repair_class or ""),
        boundary_predicate="",
        boundary_summary=str(boundary_summary or ""),
        boundary_audit=audit,
        semantic_repair_status=semantic_status,
        repair_invariant=invariant,
        contract_scope=str(invariant_scope).strip(),
        invariant_scope=str(invariant_scope).strip(),
        affected_operations=[],
        enforcement_role_preference=_clean_list(enforcement_role_preference or [], limit=8),
        executable_predicate="",
        repair_intent=invariant,
        patch_strategy_hint=str(repair_class or ""),
        avoid_patch_patterns=_clean_list(forbidden_patch_patterns or []),
        forbidden_patch_patterns=_clean_list(forbidden_patch_patterns or []),
        forbidden_literals=_clean_list(forbidden_literals or []),
        validation_obligations=obligations,
        rationale=str(rationale or ""),
    )
    AGENT_STATE["contract"] = contract
    logger.info("Counterfactual invariant submitted: %s", contract.contract_id)
    return "Counterfactual invariant submitted. Your task is complete. You MUST reply with TERMINATE."


def submit_counterfactual_contract(
    suspect_variables: List[str],
    angelic_observations: List[dict],
    demonic_observations: List[dict],
    intervention_site: dict,
    enforcement_site: dict,
    enforcement_priority: str,
    boundary_kind: str,
    boundary_predicate: str,
    boundary_summary: str,
    repair_invariant: str,
    contract_scope: str,
    affected_operations: List[str],
    repair_intent: str,
    rationale: str,
    patch_strategy_hint: str = "",
    avoid_patch_patterns: List[str] = None,
    forbidden_literals: List[str] = None,
    validation_obligations: List[str] = None,
) -> str:
    """Backward-compatible wrapper for older traces/tests."""
    result = submit_counterfactual_invariant(
        bug_type="",
        repair_class=boundary_kind or patch_strategy_hint,
        unsafe_condition=boundary_predicate or boundary_summary,
        baseline_facts=[],
        angelic_observations=angelic_observations,
        demonic_observations=demonic_observations,
        boundary_summary=boundary_summary,
        boundary_audit=_default_boundary_audit("unknown"),
        repair_invariant=repair_invariant or repair_intent,
        invariant_scope=contract_scope,
        enforcement_role_preference=[enforcement_priority] if enforcement_priority else [],
        forbidden_patch_patterns=avoid_patch_patterns or [],
        forbidden_literals=forbidden_literals or [],
        validation_obligations=validation_obligations or [],
        rationale=rationale,
    )
    contract = AGENT_STATE.get("contract")
    if isinstance(contract, CounterfactualContract):
        requested_role = str((enforcement_site or {}).get("role", "") or enforcement_priority or "")
        contract.intervention_site = _submitted_site(intervention_site, "counterfactual_probe_site")
        contract.enforcement_site = _submitted_site(enforcement_site, requested_role or contract.enforcement_priority)
        contract.enforcement_priority = requested_role or contract.enforcement_priority
    return result


_FORBIDDEN_CFC_SEARCH_RE = re.compile(
    r"(init_unit_tests|unit[_-]?tests?|test[_-]?entry|fuzz(?:er|ing)?|harness|\bmain\b|"
    r"repro(?:duce|duction)?[_-]?command|/out/|/results?/|chat|artifact|build[_-]?command)",
    re.IGNORECASE,
)


def cfc_search_in_repo(pattern: str, path: str = None, max_hits: int = 20, context: int = 2) -> str:
    query = " ".join(str(part or "") for part in (pattern, path))
    if _FORBIDDEN_CFC_SEARCH_RE.search(query):
        return (
            "CounterfactualContractAgent search rejected: this task already has an initialized debugger session "
            "and supplied seed/probe sites. Do not search for test entry points, unit-test initialization, fuzz "
            "harnesses, main functions, binaries, reproduction commands, build commands, result artifacts, or chat "
            "artifacts. Use run_to_line at a seed/probe site, then print_value/read_memory, debugger_assign, and "
            "debugger_continue to expand angelic/demonic observations."
        )
    result = debug_agent.search_in_repo(pattern=pattern, path=path, max_hits=max_hits, context=context)
    _record_action("source_inspection")
    return result


def _record_action(action: str) -> None:
    actions = AGENT_STATE.setdefault("actions", set())
    if isinstance(actions, set):
        actions.add(action)
    counts = AGENT_STATE.setdefault("action_counts", {})
    if isinstance(counts, dict):
        counts[action] = int(counts.get(action, 0) or 0) + 1
    AGENT_STATE["action_version"] = int(AGENT_STATE.get("action_version", 0) or 0) + 1


def _record_failed_intervention(tool: str, intervention: str, error: str, site: dict[str, Any] | None = None) -> None:
    failures = AGENT_STATE.setdefault("failed_interventions", [])
    if isinstance(failures, list):
        failures.append(
            {
                "tool": tool,
                "intervention": intervention,
                "error": error,
                "site": dict(site or {}),
            }
        )


def cfc_run_to_line(line: int, file: str = None) -> str:
    _record_action("probe_attempt")
    return debug_agent.run_to_line(line=line, file=file)


def cfc_continue_to_line(line: int, file: str = None) -> str:
    _record_action("probe_attempt")
    return debug_agent.continue_to_line(line=line, file=file)


def cfc_print_value(expression: str) -> str:
    _record_action("runtime_inspection")
    return debug_agent.print_value(expression)


def cfc_read_memory(address: str, size: int = 1, count: int = 16, fmt: str = "x") -> str:
    _record_action("runtime_inspection")
    return debug_agent.read_memory(address, size=size, count=count, fmt=fmt)


def cfc_file_content(start_line: int, end_line: int, file: str = None) -> str:
    _record_action("source_inspection")
    return debug_agent.file_content(start_line=start_line, end_line=end_line, file=file)


def cfc_debugger_backtrace() -> str:
    _record_action("source_inspection")
    return debug_agent.debugger_backtrace()


def cfc_debugger_assign(variable: str, value: str) -> str:
    _record_action("intervention_attempt")
    success, message = debugger_assign(variable, value)
    if success:
        _record_action("intervention")
    else:
        _record_failed_intervention("debugger_assign", f"{variable} = {value}", message)
    return f"{'ok' if success else 'failed'}: {message}"


def cfc_debugger_assign_expression(expression: str) -> str:
    _record_action("intervention_attempt")
    success, message = debugger_assign_expression(expression)
    if success:
        _record_action("intervention")
    else:
        _record_failed_intervention("debugger_assign_expression", expression, message)
    return f"{'ok' if success else 'failed'}: {message}"


def cfc_debugger_continue() -> str:
    _record_action("post_intervention_execution")
    return debug_agent._debugger_continue()


_LOGIC_AT_RE = re.compile(r"^\s*LOGIC:AT\((?P<file>.*):(?P<line>\d+)\)\s+THEN\s+(?P<body>.+?)\s*$", re.IGNORECASE | re.DOTALL)
_LOGIC_GUARD_RE = re.compile(
    r"^\s*LOGIC:IF\((?P<condition>.*)\)\s+THEN\s+RETURN\((?P<return_value>.*)\)\s*$",
    re.IGNORECASE | re.DOTALL,
)


def apply_angelic_operation(operation: str) -> str:
    """
    Apply a source-positioned counterfactual operation.

    Supported forms:
    - LOGIC:AT(/path/file.c:42) THEN variable = value
    - LOGIC:AT(/path/file.c:42) THEN LOGIC:IF(cond) THEN RETURN(value)
    """
    text = str(operation or "").strip()
    match = _LOGIC_AT_RE.match(text)
    if not match:
        return (
            "Unsupported angelic operation. Use `LOGIC:AT(file:line) THEN expression` or "
            "`LOGIC:AT(file:line) THEN LOGIC:IF(condition) THEN RETURN(value)`."
        )

    file = match.group("file").strip()
    line = int(match.group("line"))
    body = match.group("body").strip()
    guard = _LOGIC_GUARD_RE.match(body)
    if guard:
        _record_action("intervention_attempt")
        success, message = debugger_add_functional_guard(
            file,
            line,
            guard.group("condition").strip(),
            guard.group("return_value").strip(),
        )
        if success:
            _record_action("intervention")
        else:
            _record_failed_intervention(
                "apply_angelic_operation",
                text,
                message,
                {"file": file, "line": line, "role": "counterfactual_probe_site"},
            )
        return f"{'ok' if success else 'failed'}: functional guard at {file}:{line}: {message}"

    _record_action("probe_attempt")
    stop_result = debug_agent.run_to_line(line=line, file=file)
    _record_action("intervention_attempt")
    success, message = debugger_assign_expression(body)
    if success:
        _record_action("intervention")
    else:
        _record_failed_intervention(
            "apply_angelic_operation",
            text,
            message,
            {"file": file, "line": line, "role": "counterfactual_probe_site"},
        )
    return (
        f"run_to_line({file}:{line}) => {stop_result}\n"
        f"{'ok' if success else 'failed'}: angelic operation `{body}`: {message}"
    )


def _bootstrap_debugger_context(task: dict[str, Any], suspect: dict[str, Any], logger=None) -> None:
    debugger_session = task.setdefault("debugger_session", {})
    start_sites = [
        target.get("seed_site")
        for target in task.get("seed_expansion_targets", []) or []
        if isinstance(target, dict) and isinstance(target.get("seed_site"), dict)
    ]
    start_sites.extend(debugger_session.get("recommended_start_sites") or [])
    default_file = str(suspect.get("file", "") or debugger_session.get("default_source_file", "") or "")
    default_line = int(suspect.get("line", -1) or -1)
    for site in start_sites:
        if not isinstance(site, dict):
            continue
        site_file = str(site.get("file", "") or "")
        site_line = int(site.get("line", -1) or -1)
        if site_file and site_line > 0:
            default_file = site_file
            default_line = site_line
            break

    has_session = debug_agent.GLOBAL_STATE.get("session") is not None
    if has_session and default_file:
        debug_agent.GLOBAL_STATE["file"] = default_file
        debug_agent.GLOBAL_STATE["skip"] = False
        if logger is not None:
            logger.info("Counterfactual debugger context bootstrapped at %s:%s", default_file, default_line)

    debugger_session["bootstrap_status"] = "ready" if has_session else "debugger_session_missing"
    debugger_session["active_default_frame"] = {
        "file": default_file,
        "line": default_line,
        "role": "counterfactual_default_probe_frame",
    }
    debugger_session["first_debugger_action"] = {
        "tool": "run_to_line",
        "file": default_file,
        "line": default_line,
        "then": ["print_value/read_memory", "debugger_assign/debugger_assign_expression", "debugger_continue"],
    }


def _counterfactual_termination_message(message: dict[str, Any]) -> bool:
    content = str(message.get("content", "") or "").strip().rstrip(".")
    return AGENT_STATE.get("contract") is not None and content == "TERMINATE"


def get_counterfactual_contract_agent() -> GenericAgent:
    system_prompt = COUNTERFACTUAL_INVARIANT_SYSTEM_PROMPT + build_debugger_session_protocol(
        role="CounterfactualContractAgent",
        initial_process_state="may be stopped or reset; use `run_to_line` for a fresh independent probe",
        allow_mutation=True,
    )
    agent = GenericAgent(
        "CounterfactualContractAgent",
        system_prompt,
        is_termination_msg=_counterfactual_termination_message,
        default_auto_reply=(
            "No CounterfactualInvariant has been accepted. Use the required debugger/source tool and call "
            "submit_counterfactual_invariant again. Do not output the contract as plain text and do not reply TERMINATE."
        ),
    )
    agent.register_hook(
        cfc_run_to_line,
        "Use the already initialized LLDB session to start a fresh reproducer run and stop at a concrete project source line. "
        "The target and reproducer are already configured; do not search for an entry point or executable.",
        name="run_to_line",
    )
    agent.register_hook(
        cfc_continue_to_line,
        "Continue the current stopped target process to another project source line without restarting. "
        "Use run_to_line instead when no process is currently stopped.",
        name="continue_to_line",
    )
    agent.register_hook(
        debug_agent.list_breakpoints,
        "Diagnostic only. Do not use as the first action to discover the session; the initial task already supplies the default probe frame.",
    )
    agent.register_hook(
        cfc_print_value,
        "Inspect a variable or expression at the current LLDB stop in the loaded target process.",
        name="print_value",
    )
    agent.register_hook(
        cfc_read_memory,
        "Read target memory at a concrete address when expression evaluation is insufficient.",
        name="read_memory",
    )
    agent.register_hook(
        cfc_file_content,
        "Read project source context from a source file and line range. Do not read result directories, chat artifacts, or executables.",
        name="file_content",
    )
    agent.register_hook(
        cfc_search_in_repo,
        "Search project source for producers, guards, initialization paths, ownership transitions, and related operations. "
        "Only use this after debugger expansion at the supplied seed/probe site, and never search for unit tests, "
        "fuzz harnesses, main, binaries, reproduction commands, result directories, chat artifacts, or unrelated infrastructure.",
        name="search_in_repo",
    )
    agent.register_hook(
        cfc_debugger_backtrace,
        "Inspect the call stack only after a seed/probe-site debugger expansion needs call-chain context. "
        "Do not use this as the first action to discover where the session is; the initial task already supplies the default probe frame.",
        name="debugger_backtrace",
    )
    agent.register_hook(cfc_debugger_assign, "Assign a candidate angelic or demonic value at the current LLDB stop.", name="debugger_assign")
    agent.register_hook(
        cfc_debugger_assign_expression,
        "Apply a complex counterfactual assignment expression at the current stop.",
        name="debugger_assign_expression",
    )
    agent.register_hook(
        apply_angelic_operation,
        "Apply a source-positioned angelic operation such as `LOGIC:AT(file:line) THEN x = 1` or "
        "`LOGIC:AT(file:line) THEN LOGIC:IF(cond) THEN RETURN(value)`. "
        "After this, call `debugger_continue` to classify the target crash status.",
    )
    agent.register_hook(
        cfc_debugger_continue,
        "Run the already loaded reproducer after an intervention and report whether the original target crash disappeared, persisted, or changed. "
        "The debugger resets after completion, so use run_to_line before the next independent probe.",
        name="debugger_continue",
    )
    agent.register_hook(
        submit_counterfactual_invariant,
        "Submit the final CounterfactualInvariant after debugger-backed angelic/demonic expansion and invariant generalization.",
    )
    agent.register_hook(
        submit_counterfactual_contract,
        "Backward-compatible alias for older CounterfactualContract submissions.",
    )
    return agent


def _agent_tool_names(chat: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    for message in chat.get("history", []) or []:
        if not isinstance(message, dict):
            continue
        direct_name = message.get("name")
        if direct_name:
            names.add(str(direct_name))
        for tool_call in message.get("tool_calls", []) or []:
            if not isinstance(tool_call, dict):
                continue
            function = tool_call.get("function") if isinstance(tool_call.get("function"), dict) else {}
            name = function.get("name") or tool_call.get("name")
            if name:
                names.add(str(name))
    return names


def _missing_required_agent_actions(
    chat: dict[str, Any],
    contract: CounterfactualContract | None = None,
) -> list[str]:
    names = _agent_tool_names(chat)
    insufficient_expansion = bool(
        contract is not None
        and "insufficient counterfactual expansion" in str(contract.boundary_summary or "").lower()
    )
    if insufficient_expansion:
        required_groups = [
            (
                {"run_to_line", "continue_to_line", "print_value", "debugger_assign", "debugger_assign_expression", "apply_angelic_operation"},
                "counterfactual probe attempt",
            ),
            ({"search_in_repo", "file_content", "debugger_backtrace"}, "enforcement-site source inspection"),
            ({"submit_counterfactual_invariant", "submit_counterfactual_contract"}, "contract submission"),
        ]
    else:
        required_groups = [
            ({"debugger_assign", "debugger_assign_expression", "apply_angelic_operation"}, "counterfactual state intervention"),
            ({"debugger_continue"}, "post-intervention execution"),
            ({"search_in_repo", "file_content", "debugger_backtrace"}, "enforcement-site source inspection"),
            ({"submit_counterfactual_invariant", "submit_counterfactual_contract"}, "contract submission"),
        ]
    return [label for tools, label in required_groups if not names.intersection(tools)]


def _strategy_for_suspect(
    suspect: dict[str, Any],
    report: RootCauseReport | None,
    reproduce_result: dict[str, Any] | None = None,
) -> dict[str, str]:
    bug_type = _bug_type(suspect, report)
    debug_agent_bug_type = bug_type
    surface_bug_type = _surface_bug_type_from_reproduce(reproduce_result)
    if surface_bug_type in {"out_of_bounds", "null_pointer_dereference", "use_after_free", "double_free"}:
        bug_type = surface_bug_type
    profile = suspect.get("bug_type_profile") if isinstance(suspect.get("bug_type_profile"), dict) else {}
    evidence_text = " ".join(
        [
            bug_type,
            str(profile.get("angelic_shape", "")),
            str(profile.get("evidence_kind", "")),
            str(suspect.get("debug_summary", "")),
        ]
    ).lower()
    if surface_bug_type == "out_of_bounds" and "capacity" not in evidence_text and "before_push" not in evidence_text:
        strategy = "boundary"
        kind = "relation"
        goal = "Expand around the memory-safety seed while auditing whether it is only crash avoidance or a stricter semantic boundary."
    elif "capacity" in evidence_text or "before_push" in evidence_text:
        strategy = "capacity"
        kind = "relation"
        goal = "Determine when capacity must be checked or grown before an advance, push, copy, or write."
    elif bug_type == "uninitialized_use" or "initialization" in evidence_text:
        strategy = "initialization"
        kind = "initialization_protocol"
        goal = "Separate initialized and uninitialized protocol states and identify the required initialization ordering."
    elif bug_type in {"use_after_free", "double_free", "invalid_free", "memory_leak", "data_race"} or "lifetime" in evidence_text:
        strategy = "lifetime"
        kind = "event_order"
        goal = "Determine the event ordering or reachability condition that keeps ownership and lifetime valid."
    elif bug_type == "assertion_failure" or "state_machine" in evidence_text:
        strategy = "state_machine"
        kind = "state_transition"
        goal = "Separate legal and illegal states or transitions that reach the assertion or protocol sink."
    elif "type_tag" in evidence_text or "runtime_tag" in evidence_text:
        strategy = "type_tag"
        kind = "state_transition"
        goal = "Determine the runtime tag/type relation required before the operation."
    elif bug_type != "unknown":
        strategy = "boundary"
        kind = "relation"
        goal = "Expand around the candidate safe relation to find the nearest angelic/demonic boundary."
    else:
        strategy = "unknown"
        kind = "scalar_value"
        goal = "Validate the provided seed and identify the smallest supported semantic boundary."
    return {
        "bug_type": bug_type,
        "debug_agent_bug_type": debug_agent_bug_type,
        "surface_bug_type": surface_bug_type,
        "evidence_family": strategy,
        "counterfactual_kind": kind,
        "loaded_strategy": strategy,
        "goal": goal,
    }


def _target_kind(variable: str, debugger_type: str, strategy: str) -> str:
    text = f"{variable} {debugger_type}".lower()
    if strategy == "lifetime":
        return "object"
    if strategy in {"initialization", "state_machine", "type_tag"}:
        return "state"
    if "*" in debugger_type or any(token in text for token in ("ptr", "pointer")):
        return "pointer"
    if any(token in text for token in ("offset", "index", "idx")):
        return "index"
    if any(token in text for token in ("cursor", "position", "pos")):
        return "cursor"
    if any(token in text for token in ("size", "length", "len", "count", "capacity", "limit")):
        return "size"
    return "unknown"


def _variable_role(variable: str, target_kind: str, strategy: str) -> str:
    lowered = variable.lower()
    if strategy == "lifetime":
        return "owner" if any(token in lowered for token in ("owner", "ref", "handle")) else "object"
    if strategy in {"initialization", "state_machine"}:
        return "state"
    if strategy == "type_tag":
        return "tag"
    if target_kind in {"index", "cursor"}:
        return "write_cursor" if any(token in lowered for token in ("write", "dst", "out", "offset", "cursor")) else "read_index"
    if target_kind == "size":
        return "buffer_limit" if any(token in lowered for token in ("limit", "end", "capacity")) else "size"
    return target_kind


def _expansion_goal(strategy: str, variable: str, boundary_kind: str) -> dict[str, Any]:
    if strategy == "capacity":
        return {
            "find_angelic_neighbors": [f"{variable} remains within available capacity"],
            "find_demonic_neighbors": [f"{variable} reaches or exceeds available capacity"],
            "expected_boundary_shape": "capacity_before_push",
        }
    if strategy == "initialization":
        return {
            "find_angelic_neighbors": ["required subsystem or object state is initialized before use"],
            "find_demonic_neighbors": ["dependent use occurs before initialization"],
            "expected_boundary_shape": "initialized_before_use",
        }
    if strategy == "lifetime":
        return {
            "find_angelic_neighbors": ["object remains alive and reachable through the final use"],
            "find_demonic_neighbors": ["free or ownership loss occurs while a reachable use remains"],
            "expected_boundary_shape": "alive_until_use",
        }
    if strategy == "state_machine":
        return {
            "find_angelic_neighbors": ["operation executes from a legal protocol state"],
            "find_demonic_neighbors": ["operation executes from the nearest illegal state"],
            "expected_boundary_shape": "legal_state",
        }
    if strategy == "type_tag":
        return {
            "find_angelic_neighbors": ["runtime tag matches the requested operation"],
            "find_demonic_neighbors": ["runtime tag mismatches the requested operation"],
            "expected_boundary_shape": "tag_match",
        }
    return {
        "find_angelic_neighbors": [f"{variable} just inside the candidate safe boundary"],
        "find_demonic_neighbors": [f"{variable} at or just beyond the candidate boundary"],
        "expected_boundary_shape": boundary_kind or "unknown",
    }


def _unsafe_state_meaning(strategy: str, variable: str) -> str:
    meanings = {
        "boundary": f"{variable} is at or beyond the suspected safe relation.",
        "capacity": f"{variable} reaches a state where the next operation may exceed available capacity.",
        "initialization": f"{variable} is used before the required initialization protocol is complete.",
        "lifetime": f"{variable} participates in an unsafe ownership, reachability, or lifetime ordering.",
        "state_machine": f"{variable} represents an illegal state or transition at the target operation.",
        "type_tag": f"{variable} does not satisfy the runtime tag/type relation required by the operation.",
        "unknown": f"{variable} is part of the unsafe state identified by DebugAgent.",
    }
    return meanings[strategy]


def _crash_signature(suspect: dict[str, Any], reproduce_result: dict[str, Any], strategy: dict[str, str]) -> dict[str, Any]:
    error_text = str(reproduce_result.get("error", "") or reproduce_result.get("output", "") or "")
    sanitizer_match = SANITIZER_ERROR_RE.search(error_text)
    sanitizer = sanitizer_match.group(1) if sanitizer_match else "unknown"
    bug_class = sanitizer_match.group(2) if sanitizer_match else strategy["bug_type"]
    crash_site = dict(suspect.get("crash_site", {}) or {}) or _site_from_suspect(suspect, "crash_site")
    stack = reproduce_result.get("backtrace") or reproduce_result.get("stack") or []
    if not isinstance(stack, list):
        stack = []
    function = str(crash_site.get("function", "") or suspect.get("function_name", "") or reproduce_result.get("func", "") or "")
    if not stack and function:
        stack = [function]
    return {
        "sanitizer": sanitizer,
        "bug_class": bug_class,
        "access_type": str(crash_site.get("access_type", "") or suspect.get("access_type", "unknown") or "unknown"),
        "crash_site": {
            "file": str(crash_site.get("file", "") or suspect.get("file", "") or reproduce_result.get("file", "") or ""),
            "line": int(crash_site.get("line", -1) or suspect.get("line", -1) or reproduce_result.get("line", -1) or -1),
            "function": function,
        },
        "crash_expression": str(crash_site.get("expression", "") or suspect.get("crash_expression", "") or ""),
        "stack_signature": [str(item) for item in stack[:3]],
        "target_status_rule": {
            "persisted_if": ["same bug class", "same crash function", "same crash site or equivalent sink"],
            "not_persisted_if": ["only unrelated LeakSanitizer output", "different sanitizer unrelated to target site", "no sanitizer crash"],
        },
    }


def build_counterfactual_expansion_task(
    suspect: dict[str, Any],
    root_cause_report: RootCauseReport | None,
    hypothesis_id: str,
    reproduce_result: dict[str, Any] | None,
) -> dict[str, Any]:
    reproduce_result = reproduce_result or {}
    strategy = _strategy_for_suspect(suspect, root_cause_report, reproduce_result)
    crash_signature = _crash_signature(suspect, reproduce_result, strategy)
    angelic_records = angelic_seed_records(suspect)
    demonic_records = demonic_seed_records(suspect)
    demonic_by_variable = {record["variable"]: record["value"] for record in demonic_records}
    debugger_type = str(suspect.get("debugger_reported_type", "") or suspect.get("llm_inferred_type", "unknown") or "unknown")
    boundary_kind = _boundary_kind(strategy["bug_type"], suspect)
    seed_targets = []
    for index, record in enumerate(angelic_records):
        variable = str(record["variable"])
        value = record["value"]
        unsafe_value = demonic_by_variable.get(variable, "unavailable")
        site = dict(record.get("site") or {})
        seed_targets.append(
            {
                "seed_id": f"seed-{index + 1}",
                "target": variable,
                "target_kind": _target_kind(variable, debugger_type, strategy["loaded_strategy"]),
                "unsafe_state": {
                    "expression": f"{variable} = {unsafe_value}",
                    "meaning": _unsafe_state_meaning(strategy["loaded_strategy"], variable),
                },
                "seed_relation": {
                    "expression": f"{variable} = {value}",
                    "source": "DebugAgent.angelic_seed_records",
                    "status": "unverified_seed",
                },
                "seed_site": {
                    "file": str(site.get("file", "") or ""),
                    "line": int(site.get("line", -1) or -1),
                    "function": str(site.get("function", "") or suspect.get("function_name", "") or ""),
                    "role": "debug_agent_seed_site",
                },
                "site_precision": "per_seed_exact" if site.get("file") and int(site.get("line", -1) or -1) > 0 else "suspect_object_level",
                "expansion_goal": _expansion_goal(strategy["loaded_strategy"], variable, boundary_kind),
                "do_not_literalize": [str(value)],
            }
        )
    if not seed_targets:
        for index, variable in enumerate(_clean_list(suspect.get("variable_names", []), limit=4)):
            seed_targets.append(
                {
                    "seed_id": f"seed-{index + 1}",
                    "target": variable,
                    "target_kind": _target_kind(variable, debugger_type, strategy["loaded_strategy"]),
                    "unsafe_state": {
                        "expression": f"{variable} = {demonic_by_variable.get(variable, 'unavailable')}",
                        "meaning": _unsafe_state_meaning(strategy["loaded_strategy"], variable),
                    },
                    "seed_relation": {
                        "expression": str(suspect.get("estimated_safe_range", "") or "missing angelic seed"),
                        "source": "DebugAgent.estimated_safe_range",
                        "role": "crash_avoidance_boundary",
                        "status": "unverified_for_semantic_repair",
                    },
                    "seed_site": {
                        "file": str(suspect.get("file", "") or ""),
                        "line": int(suspect.get("line", -1) or -1),
                        "function": str(suspect.get("function_name", "") or ""),
                        "role": "debug_agent_seed_site",
                    },
                    "site_precision": "suspect_object_level",
                    "expansion_goal": _expansion_goal(strategy["loaded_strategy"], variable, boundary_kind),
                    "do_not_literalize": [],
                }
            )

    probe_sites = [
        {
            **crash_signature["crash_site"],
            "role": f"crash_{crash_signature['access_type']}_site" if crash_signature["access_type"] in {"read", "write"} else "crash_site",
            "allowed_intervention_targets": _clean_list(suspect.get("variable_names", [])),
        }
    ]
    for seed in seed_targets:
        probe_sites.append(
            {
                **seed["seed_site"],
                "role": "state_transition_site" if strategy["loaded_strategy"] in {"state_machine", "lifetime", "initialization"} else "pre_access_site",
                "allowed_intervention_targets": [seed["target"]],
            }
        )
    deduped_sites = []
    seen_sites = set()
    for site in probe_sites:
        key = (site.get("file"), site.get("line"), site.get("role"))
        if key not in seen_sites:
            seen_sites.add(key)
            deduped_sites.append(site)

    variables = []
    for variable in _clean_list(suspect.get("variable_names", []), limit=12):
        kind = _target_kind(variable, debugger_type, strategy["loaded_strategy"])
        variables.append(
            {
                "name": variable,
                "role": _variable_role(variable, kind, strategy["loaded_strategy"]),
                "debugger_value": demonic_by_variable.get(variable, "unavailable"),
                "type": debugger_type,
            }
        )
    relations = []
    estimated_range = str(suspect.get("estimated_safe_range", "") or "").strip()
    if estimated_range:
        relations.append(
            {
                "expression": estimated_range,
                "role": "crash_avoidance_boundary",
                "source": "DebugAgent",
                "status": "unverified_for_semantic_repair",
            }
        )

    enforcement_site, _ = _enforcement_site(suspect, root_cause_report)
    candidate_sites = []
    raw_candidates = []
    if root_cause_report is not None:
        raw_candidates.extend([root_cause_report.preferred_edit_location])
        raw_candidates.extend(root_cause_report.candidate_edit_locations)
    raw_candidates.extend([suspect.get("preferred_edit_location", {})])
    raw_candidates.extend(suspect.get("candidate_edit_locations", []) or [])
    raw_candidates.append(enforcement_site)
    seen_candidates = set()
    template_enforcement_roles = {
        "producer",
        "existing_guard",
        "loop_guard",
        "capacity_check",
        "init_path",
        "ownership_transfer",
        "unlink_path",
        "free_path",
        "protocol_gate",
        "api_boundary",
        "crash_site_last_resort",
        "reference_guard_pattern",
    }
    for candidate in raw_candidates:
        if not isinstance(candidate, dict) or not candidate:
            continue
        raw_role = str(candidate.get("role", "") or "")
        role = raw_role if raw_role in template_enforcement_roles else _normalize_enforcement_role(
            raw_role,
            str(suspect.get("preferred_repair_stage", "")),
        )
        key = (candidate.get("file"), candidate.get("line"), role)
        if key in seen_candidates:
            continue
        seen_candidates.add(key)
        candidate_sites.append(
            {
                "file": str(candidate.get("file", "") or ""),
                "line": int(candidate.get("line", -1) or -1),
                "function": str(candidate.get("function", "") or suspect.get("function_name", "") or ""),
                "role": role,
                "why_here": str(candidate.get("why_here", "") or "Candidate invariant-maintenance site from DebugAgent repair frame."),
            }
        )

    preferred_roles = {
        "boundary": ["producer", "existing_guard", "loop_guard", "api_boundary"],
        "capacity": ["capacity_check", "producer", "loop_guard"],
        "initialization": ["init_path", "api_boundary"],
        "lifetime": ["ownership_transfer", "unlink_path", "free_path"],
        "state_machine": ["protocol_gate", "state_transition", "api_boundary"],
        "type_tag": ["protocol_gate", "api_boundary"],
        "unknown": ["producer", "existing_guard", "api_boundary"],
    }
    default_topology = {
        "boundary": "local_invariant",
        "capacity": "capacity_fix",
        "initialization": "init_protocol",
        "lifetime": "ownership_lifetime",
        "state_machine": "state_transition",
        "type_tag": "type_check",
        "unknown": "unknown",
    }
    avoid_patterns = ["literalize_angelic_value", "hardcoded_poc_specific_bound", "crash_site_guard_only", "redebug_root_cause_without_new_evidence"]
    avoid_patterns.extend(list(suspect.get("forbidden_fix_patterns", []) or []))
    if root_cause_report is not None:
        avoid_patterns.extend(root_cause_report.forbidden_fix_patterns)
    validation = list((suspect.get("bug_type_profile") or {}).get("validation_obligations", []) or [])
    if root_cause_report is not None:
        validation.extend(root_cause_report.validation_obligations)

    raw_topology = str(
        (root_cause_report.repair_topology if root_cause_report is not None else "")
        or suspect.get("repair_topology", "")
    )
    allowed_topologies = {
        "local_invariant",
        "producer_guard",
        "capacity_fix",
        "init_protocol",
        "ownership_lifetime",
        "state_transition",
        "type_check",
        "unknown",
    }
    repair_topology = raw_topology if raw_topology in allowed_topologies else default_topology[strategy["loaded_strategy"]]

    recommended_start_sites = [
        {
            "file": str(site.get("file", "") or ""),
            "line": int(site.get("line", -1) or -1),
            "role": str(site.get("role", "") or ""),
        }
        for site in deduped_sites
        if site.get("file") and int(site.get("line", -1) or -1) > 0
    ]

    return {
        "debugger_session": {
            "initialized": True,
            "backend": "LLDB",
            "target_configuration": "inherited_from_DebugAgent",
            "reproducer_loaded": True,
            "current_process_state": "may_be_stopped_or_reset; use run_to_line for a fresh independent probe",
            "default_source_file": str(suspect.get("file", "") or ""),
            "recommended_start_sites": recommended_start_sites,
        },
        "task_metadata": {
            "task_type": "CounterfactualExpansionTask",
            "schema_version": "counterfactual_expansion.v1",
            "hypothesis_id": hypothesis_id,
            "source_agent": "DebugAgent",
        },
        "loaded_strategy": strategy,
        "target_crash_signature": crash_signature,
        "seed_expansion_targets": seed_targets,
        "suspect_runtime_scope": {
            "function": str(suspect.get("function_name", "") or crash_signature["crash_site"].get("function", "") or ""),
            "probe_sites": deduped_sites,
            "variables": variables,
            "relations": relations,
            "scope_lock": {
                "allow_new_root_cause_search": False,
                "allow_source_edit": False,
                "allow_patch_generation": False,
                "allow_probe_outside_scope": False,
            },
        },
        "repair_frame": {
            "repair_topology": repair_topology,
            "candidate_enforcement_sites": candidate_sites,
            "preferred_enforcement_roles": preferred_roles[strategy["loaded_strategy"]],
            "avoid_patch_patterns": list(dict.fromkeys(avoid_patterns)),
            "validation_obligations": list(dict.fromkeys(str(item) for item in validation if str(item).strip())),
        },
    }


class CounterfactualContractAgent:
    def __init__(
        self,
        profile: dict[str, Any],
        suspect: dict[str, Any],
        root_cause_report: RootCauseReport | None,
        hypothesis_id: str,
        reproduce_result: dict[str, Any] | None,
    ):
        self.profile = profile
        self.suspect = suspect
        self.root_cause_report = root_cause_report
        self.hypothesis_id = hypothesis_id
        self.reproduce_result = reproduce_result or {}

    def run(self, logger=None) -> tuple[CounterfactualContract | None, dict[str, Any]]:
        reset_agent_state()
        AGENT_STATE["context"] = {
            "suspect": self.suspect,
            "root_cause_report": self.root_cause_report,
            "hypothesis_id": self.hypothesis_id,
            "reproduce_result": self.reproduce_result,
        }
        task = build_counterfactual_expansion_task(
            suspect=self.suspect,
            root_cause_report=self.root_cause_report,
            hypothesis_id=self.hypothesis_id,
            reproduce_result=self.reproduce_result,
        )
        _bootstrap_debugger_context(task, self.suspect, logger=logger)
        prompt = COUNTERFACTUAL_INVARIANT_INITIAL_PROMPT.format(
            debugger_session=json.dumps(task["debugger_session"], indent=2, default=str),
            task_metadata=json.dumps(task["task_metadata"], indent=2, default=str),
            loaded_strategy=json.dumps(task["loaded_strategy"], indent=2, default=str),
            target_crash_signature=json.dumps(task["target_crash_signature"], indent=2, default=str),
            seed_expansion_targets=json.dumps(task["seed_expansion_targets"], indent=2, default=str),
            suspect_runtime_scope=json.dumps(task["suspect_runtime_scope"], indent=2, default=str),
            repair_frame=json.dumps(task["repair_frame"], indent=2, default=str),
        )
        agent = get_counterfactual_contract_agent()
        chat = agent.initiate(
            prompt,
            max_turns=int(self.profile.get("counterfactual_agent_max_turns", 300)),
        )
        contract = AGENT_STATE.get("contract")
        if contract is not None:
            missing_actions = _missing_required_agent_actions(chat, contract)
            if missing_actions:
                chat["contract_rejected"] = {
                    "reason": "missing_required_agent_actions",
                    "actions": missing_actions,
                    "contract": contract_to_dict(contract),
                }
                contract = None
        self._save_chat(chat)
        return contract, chat

    def _save_chat(self, chat: dict[str, Any]) -> None:
        chat_dir = str(self.profile.get("chat_dir", "") or "")
        if not chat_dir:
            return
        os.makedirs(chat_dir, exist_ok=True)
        safe_hypothesis_id = re.sub(r"[^A-Za-z0-9_.-]+", "_", self.hypothesis_id or "unknown")
        dump_json(chat, os.path.join(chat_dir, f"counterfactual-agent-{safe_hypothesis_id}.json"))


def run_counterfactual_agent(
    profile: dict[str, Any],
    suspect: dict[str, Any],
    root_cause_report: RootCauseReport | None,
    hypothesis_id: str,
    reproduce_result: dict[str, Any] | None,
    logger=None,
) -> tuple[CounterfactualContract | None, dict[str, Any]]:
    return CounterfactualContractAgent(
        profile=profile,
        suspect=suspect,
        root_cause_report=root_cause_report,
        hypothesis_id=hypothesis_id,
        reproduce_result=reproduce_result,
    ).run(logger=logger)
