from __future__ import annotations

from agent import patch_agent
from agent.contracts import RootCauseReport


def direct_patch_goal(preferred_stage: str, bug_type: str) -> str:
    if preferred_stage == "input_validation":
        return f"Reject malformed or out-of-range state before it reaches the {bug_type.replace('_', ' ')} sink."
    if preferred_stage == "initialization":
        return f"Restore required initialization before the {bug_type.replace('_', ' ')} sink consumes the state."
    if preferred_stage == "allocation_extent":
        return f"Repair the size or extent relation before the {bug_type.replace('_', ' ')} sink uses it."
    if preferred_stage == "ownership_lifetime":
        return f"Restore lifetime or ownership invariants before the {bug_type.replace('_', ' ')} sink."
    if preferred_stage == "state_update":
        return f"Repair the upstream state transition that feeds the {bug_type.replace('_', ' ')} sink."
    return f"Apply the minimal repair that prevents the {bug_type.replace('_', ' ')} sink from observing invalid state."


def build_root_cause_report(suspect: dict, hypothesis_id: str) -> RootCauseReport:
    bug_type_profile = suspect.get("bug_type_profile") or {}
    bug_type = str(bug_type_profile.get("bug_type", "unknown"))
    surface_bug_type = str((suspect.get("surface_bug_type_profile") or {}).get("bug_type", "unknown"))
    topology = str(suspect.get("repair_topology", "single_site"))
    preferred_stage = str(suspect.get("preferred_repair_stage", ""))
    preferred_location = dict(suspect.get("preferred_edit_location", {}) or {})
    candidate_locations = [dict(item) for item in suspect.get("candidate_edit_locations", []) or [] if isinstance(item, dict)]
    risk_factors: list[str] = []
    evidence_requirements: list[str] = []

    if topology in {"cross_file_invariant", "caller_to_callee"}:
        risk_factors.append("nonlocal_edit_topology")
        evidence_requirements.append("Validate the upstream invariant with debugger-backed evidence before accepting a local fix.")
    if preferred_stage in {"ownership_lifetime"}:
        risk_factors.append("ownership_or_lifetime_semantics")
        evidence_requirements.append("Temporal or ownership semantics require stronger replay and evidence than direct patch alone.")
    if bug_type in {"use_after_free", "double_free", "invalid_free", "heap_corruption_later_crash", "data_race", "resource_leak"}:
        risk_factors.append("high_complexity_bug_type")
        evidence_requirements.append("This bug type is structurally high-risk for Layer 1-only acceptance.")
    if not preferred_location:
        risk_factors.append("missing_preferred_edit_location")
        evidence_requirements.append("Debugger did not produce a precise repair site.")
    if not candidate_locations:
        risk_factors.append("missing_location_alternatives")

    patch_contract = direct_patch_goal(preferred_stage, bug_type)
    evidence_family = str(bug_type_profile.get("evidence_family", "predicate") or "predicate")
    evidence_kind = str(bug_type_profile.get("evidence_kind", "predicate_state") or "predicate_state")
    selective_generalization = str(bug_type_profile.get("generalization_target", "constraint") or "constraint")
    operational_repair_intent = patch_contract if evidence_family == "operational" else ""
    if evidence_family == "operational":
        risk_factors.append("operational_repair_intent")
        evidence_requirements.append("Operational evidence should bypass predicate constraints and route through Layer 2 repair intent.")
    recommended_strategies = patch_agent._rank_patch_strategies(patch_contract, suspect)[:3]
    if any(item.get("location_type") == "same_site" and item.get("semantic_risk") == "high" for item in recommended_strategies):
        risk_factors.append("high_risk_same_site_strategy")
        evidence_requirements.append("Even a replay-passing same-site guard still needs Layer 2 validation.")

    allow_direct_patch = not any(
        marker in risk_factors
        for marker in {
            "ownership_or_lifetime_semantics",
            "high_complexity_bug_type",
            "missing_preferred_edit_location",
            "operational_repair_intent",
        }
    )
    direct_patch_risk = "low" if allow_direct_patch and topology == "single_site" else "medium" if allow_direct_patch else "high"
    rationale = (
        "Preferred edit location is concrete and current bug shape is local enough for a direct patch fast path."
        if allow_direct_patch
        else "Root-cause shape suggests this case should escalate to Layer 2 evidence gathering instead of relying on direct patching."
    )
    return RootCauseReport(
        hypothesis_id=hypothesis_id,
        summary=str(suspect.get("debug_summary", "")),
        bug_type=bug_type,
        surface_bug_type=surface_bug_type,
        repair_topology=topology,
        preferred_repair_stage=preferred_stage,
        preferred_edit_location=preferred_location,
        candidate_edit_locations=candidate_locations,
        direct_patch_allowed=allow_direct_patch,
        direct_patch_risk=direct_patch_risk,
        direct_patch_reason=rationale,
        direct_patch_contract=patch_contract,
        evidence_family=evidence_family,
        evidence_kind=evidence_kind,
        selective_generalization=selective_generalization,
        operational_repair_intent=operational_repair_intent,
        forbidden_fix_patterns=list(suspect.get("forbidden_fix_patterns", []) or []),
        validation_obligations=list(bug_type_profile.get("validation_obligations", []) or []),
        escalation_target="layer2",
        evidence_requirements=evidence_requirements,
    )
