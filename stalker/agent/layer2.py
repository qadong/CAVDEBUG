from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class Layer2EntryDecision:
    next_actor: str
    claim: str
    question: str
    has_angelic_values: bool
    has_supported_constraints: bool
    evidence_family: str = "unknown"
    evidence_kind: str = "unknown"
    skip_constraint_reason: str = ""
    forced_fuzz_refresh: bool = False
    refresh_reason: str = ""

    def to_artifact(self, hypothesis_id: str) -> dict[str, Any]:
        return {
            "hypothesis_id": hypothesis_id,
            "has_angelic_values": self.has_angelic_values,
            "has_supported_constraints": self.has_supported_constraints,
            "evidence_family": self.evidence_family,
            "evidence_kind": self.evidence_kind,
            "skip_constraint_reason": self.skip_constraint_reason,
            "forced_fuzz_refresh": self.forced_fuzz_refresh,
            "refresh_reason": self.refresh_reason,
            "next_actor": self.next_actor,
        }


class Layer2Orchestrator:
    def _classify_entry_evidence(self, state, fuzz_result: dict[str, Any]) -> tuple[str, str, str]:
        typed = fuzz_result.get("typed_angelic_evidence") if isinstance(fuzz_result, dict) else {}
        typed = typed if isinstance(typed, dict) else {}
        family = str(typed.get("evidence_family", "") or "")
        kind = str(typed.get("evidence_kind", "") or "")
        reason = str(typed.get("reason", "") or "")
        if family:
            return family, kind or "unknown", reason

        report = state.current_root_cause_report() if hasattr(state, "current_root_cause_report") else None
        if report is not None:
            family = str(getattr(report, "evidence_family", "") or "")
            kind = str(getattr(report, "evidence_kind", "") or "")
            reason = str(getattr(report, "operational_repair_intent", "") or "")
            if family:
                return family, kind or "unknown", reason

        profile = getattr(state, "bug_type_profile", None) or {}
        if isinstance(profile, dict):
            family = str(profile.get("evidence_family", "") or "")
            kind = str(profile.get("evidence_kind", "") or "")
            reason = str(profile.get("reason", "") or "")
            if family:
                return family, kind or "unknown", reason
        return "unknown", "unknown", ""

    def decide_entry(self, state) -> Layer2EntryDecision:
        active_hypothesis_id = state.active_hypothesis_id
        fuzz_result = state.current_fuzz_result() if hasattr(state, "current_fuzz_result") else state.fuzz_result
        fuzz_result = fuzz_result if isinstance(fuzz_result, dict) else {}
        same_hypothesis_fuzz = bool(fuzz_result) and str(fuzz_result.get("hypothesis_id", "") or active_hypothesis_id) == str(active_hypothesis_id)
        has_angelic = bool(fuzz_result.get("angelic_values")) if same_hypothesis_fuzz else False
        has_constraints = bool(state.current_valid_constraints())
        evidence_family, evidence_kind, evidence_reason = self._classify_entry_evidence(state, fuzz_result)
        refresh_reason = ""
        if hasattr(state, "layer2_fuzz_refresh_reasons"):
            refresh_reason = str(state.layer2_fuzz_refresh_reasons.get(active_hypothesis_id, "") or "")

        if evidence_family == "operational":
            return Layer2EntryDecision(
                next_actor="patch",
                claim="Layer 2 classified this hypothesis as operational evidence and will skip predicate constraint extraction.",
                question="Can PatchAgent turn the typed operational repair intent into an evidence-guided repair?",
                has_angelic_values=has_angelic,
                has_supported_constraints=has_constraints,
                evidence_family=evidence_family,
                evidence_kind=evidence_kind,
                skip_constraint_reason=evidence_reason or "Operational evidence generalizes directly to repair intent.",
                forced_fuzz_refresh=bool(refresh_reason),
                refresh_reason=refresh_reason,
            )

        if refresh_reason:
            return Layer2EntryDecision(
                next_actor="fuzz",
                claim="Layer 2 is forcing a fresh debugger-backed fuzz round before reusing older evidence.",
                question="Can FuzzAgent refresh angelic and demonic evidence for the active hypothesis before ConstraintAgent adjudicates it?",
                has_angelic_values=has_angelic,
                has_supported_constraints=has_constraints,
                evidence_family=evidence_family,
                evidence_kind=evidence_kind,
                forced_fuzz_refresh=True,
                refresh_reason=refresh_reason,
            )

        if has_constraints:
            return Layer2EntryDecision(
                next_actor="patch",
                claim="Layer 2 already has supported constraints for the active hypothesis.",
                question="Can PatchAgent turn the supported Layer 2 constraints into an evidence-guided repair?",
                has_angelic_values=has_angelic,
                has_supported_constraints=has_constraints,
                evidence_family=evidence_family,
                evidence_kind=evidence_kind,
                refresh_reason=refresh_reason,
            )
        if has_angelic:
            return Layer2EntryDecision(
                next_actor="constraint",
                claim="Layer 2 is reusing existing angelic evidence for the active hypothesis.",
                question="Can ConstraintAgent adjudicate the current Layer 2 evidence into executable repair constraints?",
                has_angelic_values=has_angelic,
                has_supported_constraints=has_constraints,
                evidence_family=evidence_family,
                evidence_kind=evidence_kind,
                refresh_reason=refresh_reason,
            )
        return Layer2EntryDecision(
            next_actor="fuzz",
            claim="Layer 2 is entering through debugger-backed evidence gathering for the active hypothesis.",
            question="Can FuzzAgent gather angelic and demonic evidence for the active hypothesis?",
            has_angelic_values=has_angelic,
            has_supported_constraints=has_constraints,
            evidence_family=evidence_family,
            evidence_kind=evidence_kind,
            refresh_reason=refresh_reason,
        )


_ORCHESTRATOR = Layer2Orchestrator()


def decide_layer2_entry(state) -> Layer2EntryDecision:
    return _ORCHESTRATOR.decide_entry(state)
