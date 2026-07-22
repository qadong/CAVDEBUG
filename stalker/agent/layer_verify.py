from __future__ import annotations

from dataclasses import dataclass


@dataclass
class VerifyRoundDecision:
    candidate_status: str
    next_actor: str
    claim: str
    confidence: float
    event: str | None = None
    success: bool = False
    done: bool = False
    question: str = ""


def classify_verification_outcome(candidate, feedback: dict) -> VerifyRoundDecision:
    allowed_followups = {"debug", "counterfactual", "layer2", "constraint", "fuzz", "patch", "done"}
    direct_patch_assessment = (
        feedback.get("direct_patch_assessment")
        if isinstance(feedback.get("direct_patch_assessment"), dict)
        else {}
    )
    layer1_verdict = str(feedback.get("layer1_verdict", "") or "")
    candidate_metadata = getattr(candidate, "metadata", {}) if candidate is not None else {}
    operational_repair = (
        str(candidate_metadata.get("evidence_family", "") or "") == "operational"
        or str(getattr(candidate, "constraint", "") or "").startswith("OPERATIONAL_REPAIR_INTENT:")
    )
    repair_layer = str(candidate_metadata.get("repair_layer", "") or "")
    counterfactual_repair = repair_layer == "counterfactual" or str(candidate_metadata.get("evidence_family", "") or "") == "counterfactual"

    if layer1_verdict == "weak":
        return VerifyRoundDecision(
            candidate_status="weak_pass",
            next_actor="counterfactual",
            claim="VerifyAgent kept the direct patch as a useful clue, but it is not strong enough to accept without a counterfactual contract.",
            confidence=0.5,
            event="direct_patch_weak_pass",
            success=True,
            question="Can CounterfactualContractAgent validate this direct repair intent with stronger counterfactual evidence?",
        )

    if layer1_verdict == "suspicious":
        return VerifyRoundDecision(
            candidate_status="suspicious",
            next_actor="counterfactual",
            claim="VerifyAgent marked the direct patch as suspicious and is escalating to counterfactual repair.",
            confidence=0.5,
            event="direct_patch_suspicious",
            success=False,
            question="Can CounterfactualContractAgent replace this suspicious direct patch with contract-backed repair guidance?",
        )

    if feedback["status"] == "pass":
        residual_risk = feedback.get("details", {}).get("residual_risk")
        claim = "VerifyAgent confirmed the patch candidate fixes the crash."
        if residual_risk:
            claim = f"VerifyAgent confirmed the patch candidate fixes the crash with residual risk `{residual_risk}`."
        return VerifyRoundDecision(
            candidate_status="validated",
            next_actor="done",
            claim=claim,
            confidence=0.95,
            event="verified_patch",
            success=True,
            done=True,
        )

    followup = str(feedback.get("recommended_next_actor", "layer2") or "layer2")
    if followup not in allowed_followups:
        followup = "counterfactual" if counterfactual_repair else "layer2"
    if counterfactual_repair and followup in {"layer2", "constraint", "fuzz"}:
        followup = "counterfactual"
    elif repair_layer == "layer2" and followup in {"constraint", "fuzz"}:
        followup = "layer2"
    if operational_repair and followup == "debug":
        followup = "fuzz"
    if feedback["status"] in {"bad_patch_location", "nonlocal_invariant"}:
        question = "Replay points to a local sink fix; prefer an upstream invariant repair."
    elif feedback["status"] in {"semantic_regression", "overfit_poc"}:
        question = "Regression/variant replay failed; prefer a lower-risk upstream fix."
    else:
        question = f"Based on verification status `{feedback['status']}`, can the next actor refine the current hypothesis?"
    return VerifyRoundDecision(
        candidate_status="rejected",
        next_actor=followup,
        claim="VerifyAgent rejected the current patch candidate and produced feedback for another round.",
        confidence=0.45,
        success=False,
        question=question,
    )
