from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from agent.contracts import ConstraintCandidate, CounterfactualContract
from utils.ablation import state_only_no_angelic


def _compact_counterfactual_text(value: str, *, limit: int = 280) -> str:
    text = re.sub(r"0x[0-9a-fA-F]+", "<address>", str(value or ""))
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) > limit:
        text = text[: limit - 3].rstrip() + "..."
    return text


def _counterfactual_summary(contract: CounterfactualContract) -> dict[str, str]:
    demonic = contract.unsafe_condition or contract.boundary_summary
    angelic = contract.repair_invariant
    boundary = contract.boundary_summary or contract.repair_invariant
    return {
        "demonic": _compact_counterfactual_text(demonic),
        "angelic": _compact_counterfactual_text(angelic),
        "boundary": _compact_counterfactual_text(boundary),
    }


@dataclass
class PatchRoundPlan:
    layer: str
    direct_patch_mode: bool
    pending_constraints: list[ConstraintCandidate] = field(default_factory=list)
    root_cause_report: dict[str, Any] = field(default_factory=dict)
    empty_next_actor: str = "fuzz"
    empty_claim: str = "No new validated constraints are available for patch generation."


def _direct_patch_candidate(state, suspect: dict, root_cause_report: dict, patch_agent_module) -> ConstraintCandidate:
    direct_patch_contract = str(root_cause_report.get("direct_patch_contract", ""))
    return ConstraintCandidate(
        constraint=direct_patch_contract,
        constraint_status="layer1_direct_patch",
        challenge_status="not_run",
        reason=str(root_cause_report.get("direct_patch_reason", "")),
        bug_type_profile=suspect.get("bug_type_profile", {}) or {},
        strategy_hints=patch_agent_module._rank_patch_strategies(direct_patch_contract, suspect)[:3],
    )


def _operational_repair_candidate(state, suspect: dict, root_cause_report: dict, patch_agent_module) -> ConstraintCandidate:
    state_only_mode = state_only_no_angelic(getattr(state, "profile", None))
    repair_intent = str(
        root_cause_report.get("operational_repair_intent")
        or root_cause_report.get("direct_patch_contract")
        or "Repair the operational mechanism identified by debugger evidence."
    )
    evidence_kind = str(root_cause_report.get("evidence_kind", "operational_state_transition"))
    typed_evidence = {}
    if not state_only_mode:
        typed_evidence = dict(suspect.get("typed_angelic_evidence", {}) or {})
        typed_evidence.setdefault("evidence_family", "operational")
        typed_evidence.setdefault("evidence_kind", evidence_kind)
        typed_evidence.setdefault("generalization_target", "repair_intent")
        typed_evidence.setdefault("constraint_required", False)
    intent_inference = dict(suspect.get("operational_repair_intent_inference", {}) or {})
    mechanism_hint = evidence_kind.replace("operational_", "")
    if intent_inference.get("mechanism_hint"):
        mechanism_hint = str(intent_inference["mechanism_hint"])
    constraint = f"OPERATIONAL_REPAIR_INTENT: {repair_intent}"
    challenge_result = {}
    if not state_only_mode:
        challenge_result = {
            "status": "supported",
            "recommended_next_actor": "patch",
            "reason": "Selective Generalization routed operational evidence directly to PatchAgent.",
        }
    return ConstraintCandidate(
        constraint=constraint,
        constraint_kind="operational",
        status="validated",
        constraint_status="operational_repair_intent",
        precheck_status="skipped",
        challenge_status="skipped",
        source="debug",
        reason=str(root_cause_report.get("direct_patch_reason", "")) or "Operational evidence bypasses predicate constraint extraction.",
        evidence=[
            str(root_cause_report.get("summary", "")),
            f"evidence_kind={evidence_kind}",
            "constraint_extraction=skipped",
        ],
        generalization_score=0.75,
        repair_intent=repair_intent,
        demonic_summary=str(suspect.get("debug_summary", "")),
        mechanism_hint=mechanism_hint,
        constraint_role="operational_repair_intent",
        challenge_result=challenge_result,
        recommended_next_actor="patch",
        overall_score=0.75,
        causal_chain_summary=str(suspect.get("causal_chain_summary", "")),
        preferred_repair_stage=str(root_cause_report.get("preferred_repair_stage", "")),
        forbidden_repair_stages=list(suspect.get("forbidden_repair_stages", []) or []),
        bug_type_profile=suspect.get("bug_type_profile", {}) or {},
        typed_angelic_evidence=typed_evidence,
        demonic_trace_summary=dict(suspect.get("demonic_trace_summary", {}) or {}),
        abstract_constraint={
            "type": "observation_only_repair_intent" if state_only_mode else "operational_repair_intent",
            "evidence_kind": evidence_kind,
            "repair_intent": repair_intent,
            "llm_intent_inference": {} if state_only_mode else intent_inference,
            "constraint_extraction": "skipped",
        },
        strategy_hints=patch_agent_module._rank_patch_strategies(repair_intent, suspect)[:3],
    )


def _counterfactual_contract_candidate(contract: CounterfactualContract, suspect: dict, patch_agent_module) -> ConstraintCandidate:
    constraint = contract.executable_predicate or contract.repair_invariant or contract.repair_intent
    if not constraint:
        constraint = "Repair the invariant described by the counterfactual invariant."
    semantic_candidate = contract.semantic_repair_status == "semantic_repair_candidate"
    generalization_score = 0.8 if semantic_candidate else 0.45
    challenge_status = "supported" if semantic_candidate else "needs_source_check"
    typed_evidence = {
        "evidence_family": contract.evidence_family,
        "evidence_kind": contract.counterfactual_kind,
        "repair_class": contract.repair_class,
        "unsafe_condition": contract.unsafe_condition,
        "boundary_audit": contract.boundary_audit,
        "semantic_repair_status": contract.semantic_repair_status,
        "counterfactual_summary": _counterfactual_summary(contract),
        "target_crash_statuses": [
            item.get("target_crash_status")
            for item in contract.angelic_observations + contract.demonic_observations
        ],
    }
    return ConstraintCandidate(
        constraint=constraint,
        constraint_kind="counterfactual_contract",
        status="validated",
        constraint_status="counterfactual_contract",
        precheck_status="skipped",
        challenge_status="skipped",
        source="counterfactual",
        reason=contract.rationale,
        evidence=[contract.boundary_summary, contract.repair_invariant],
        generalization_score=generalization_score,
        repair_intent=contract.repair_intent,
        top_angelic_examples=contract.angelic_observations[:3],
        demonic_summary=contract.boundary_summary,
        mechanism_hint=contract.repair_class or contract.boundary_kind,
        constraint_role="counterfactual_invariant",
        challenge_result={
            "status": challenge_status,
            "recommended_next_actor": "patch",
            "notes": contract.validation_obligations[:6],
            "boundary_audit": contract.boundary_audit,
            "semantic_repair_status": contract.semantic_repair_status,
        },
        recommended_next_actor="patch",
        overall_score=generalization_score,
        causal_chain_summary=contract.rationale,
        preferred_repair_stage=contract.patch_strategy_hint,
        forbidden_repair_stages=["crash_guard"] if contract.enforcement_priority != "crash_site_last_resort" else [],
        strategy_hints=patch_agent_module._rank_patch_strategies(contract.repair_invariant, suspect)[:3],
        bug_type_profile=suspect.get("bug_type_profile", {}) or {},
        typed_angelic_evidence=typed_evidence,
        demonic_trace_summary={},
        abstract_constraint={
            "type": "counterfactual_invariant",
            "contract_id": contract.contract_id,
            "bug_type": contract.bug_type,
            "repair_class": contract.repair_class,
            "unsafe_condition": contract.unsafe_condition,
            "counterfactual_summary": _counterfactual_summary(contract),
            "boundary_summary": contract.boundary_summary,
            "boundary_audit": contract.boundary_audit,
            "semantic_repair_status": contract.semantic_repair_status,
            "repair_invariant": contract.repair_invariant,
            "invariant_scope": contract.invariant_scope or contract.contract_scope,
            "enforcement_role_preference": contract.enforcement_role_preference,
            "forbidden_patch_patterns": contract.forbidden_patch_patterns or contract.avoid_patch_patterns,
            "forbidden_literals": contract.forbidden_literals,
            "validation_obligations": contract.validation_obligations,
            "rationale": contract.rationale,
        },
    )


def plan_patch_round(state, suspect: dict, pending_constraints: list[ConstraintCandidate], patch_agent_module) -> PatchRoundPlan:
    active_root_cause_report = state.current_root_cause_report()
    root_cause_report = active_root_cause_report.__dict__ if active_root_cause_report is not None else {}
    contract = state.current_counterfactual_contract()
    if contract is not None:
        return PatchRoundPlan(
            layer="counterfactual",
            direct_patch_mode=False,
            pending_constraints=[_counterfactual_contract_candidate(contract, suspect, patch_agent_module)],
            root_cause_report=root_cause_report,
            empty_next_actor="counterfactual",
            empty_claim="PatchAgent could not produce a usable patch candidate from the counterfactual contract.",
        )
    direct_patch_mode = not pending_constraints and state.can_attempt_direct_patch()

    if direct_patch_mode:
        return PatchRoundPlan(
            layer="layer1",
            direct_patch_mode=True,
            pending_constraints=[_direct_patch_candidate(state, suspect, root_cause_report, patch_agent_module)],
            root_cause_report=root_cause_report,
            empty_next_actor="layer2",
            empty_claim="PatchAgent could not produce a usable direct patch candidate.",
        )

    if pending_constraints:
        return PatchRoundPlan(
            layer="layer2",
            direct_patch_mode=False,
            pending_constraints=list(pending_constraints),
            root_cause_report=root_cause_report,
            empty_next_actor="constraint",
            empty_claim="PatchAgent could not produce a usable patch candidate.",
        )

    if root_cause_report.get("evidence_family") == "operational":
        return PatchRoundPlan(
            layer="layer2",
            direct_patch_mode=False,
            pending_constraints=[_operational_repair_candidate(state, suspect, root_cause_report, patch_agent_module)],
            root_cause_report=root_cause_report,
            empty_next_actor="fuzz",
            empty_claim="PatchAgent could not produce a usable operational repair-intent patch candidate.",
        )

    return PatchRoundPlan(
        layer="layer2",
        direct_patch_mode=False,
        pending_constraints=[],
        root_cause_report=root_cause_report,
        empty_next_actor="constraint" if state.current_constraint_candidates() else "fuzz",
        empty_claim="No new validated constraints are available for patch generation.",
    )
