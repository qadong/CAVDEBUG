from __future__ import annotations

from dataclasses import asdict, dataclass, field, fields
from typing import Any

from agent.contracts import (
    AgentMessage,
    ConstraintCandidate,
    CounterfactualContract,
    HypothesisRecord,
    OpenQuestion,
    PatchCandidate,
    RootCauseReport,
    RootCauseHypothesis,
    VerificationFeedback,
    to_jsonable,
)


@dataclass
class BugHypothesisState:
    profile: dict[str, Any]
    max_rounds: int = 8
    top_k_hypotheses: int = 3
    round_index: int = 0
    next_actor: str = "debug"
    reproduce_result: dict[str, Any] | None = None
    analysis: list[dict[str, Any]] = field(default_factory=list)
    suspects: list[dict[str, Any]] = field(default_factory=list)
    current_suspect_index: int = 0
    hypotheses: list[RootCauseHypothesis] = field(default_factory=list)
    root_cause_report: RootCauseReport | None = None
    root_cause_reports: dict[str, RootCauseReport] = field(default_factory=dict)
    hypothesis_pool: list[HypothesisRecord] = field(default_factory=list)
    active_hypothesis_id: str = ""
    direct_patch_attempted_hypotheses: list[str] = field(default_factory=list)
    fuzz_result: dict[str, Any] | None = None
    fuzz_results: dict[str, dict[str, Any]] = field(default_factory=dict)
    counterfactual_contract: CounterfactualContract | None = None
    counterfactual_contracts: dict[str, CounterfactualContract] = field(default_factory=dict)
    constraint_candidates: list[ConstraintCandidate] = field(default_factory=list)
    constraint_candidates_by_hypothesis: dict[str, list[ConstraintCandidate]] = field(default_factory=dict)
    patch_candidates: list[PatchCandidate] = field(default_factory=list)
    patch_candidates_by_hypothesis: dict[str, list[PatchCandidate]] = field(default_factory=dict)
    # Constraints for which PatchAgent ran but produced no usable patch (LLM empty/resign).
    patch_constraints_tried: list[str] = field(default_factory=list)
    patch_constraints_tried_by_hypothesis: dict[str, list[str]] = field(default_factory=dict)
    verification_feedback: list[VerificationFeedback] = field(default_factory=list)
    verification_feedback_by_hypothesis: dict[str, list[VerificationFeedback]] = field(default_factory=dict)
    layer2_fuzz_refresh_reasons: dict[str, str] = field(default_factory=dict)
    open_questions: list[OpenQuestion] = field(default_factory=list)
    messages: list[AgentMessage] = field(default_factory=list)
    champion_patch: dict[str, Any] | None = None
    champion_feedback: dict[str, Any] | None = None
    failure: dict[str, Any] | None = None
    rounds_without_progress: int = 0
    recent_progress: list[str] = field(default_factory=list)
    route_history: list[dict[str, Any]] = field(default_factory=list)
    debug_empty_analysis_retries: int = 0
    debug_retry_observation: str = ""
    bug_type_profile: dict[str, Any] | None = None
    surface_bug_type_profile: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        hid = self.active_hypothesis_id
        if not hid:
            return
        if self.root_cause_report is not None and hid not in self.root_cause_reports:
            self.root_cause_report.hypothesis_id = self.root_cause_report.hypothesis_id or hid
            self.root_cause_reports[hid] = self.root_cause_report
        if self.fuzz_result is not None and hid not in self.fuzz_results:
            stored = dict(self.fuzz_result)
            stored["hypothesis_id"] = str(stored.get("hypothesis_id") or hid)
            self.fuzz_results[hid] = stored
            self.fuzz_result = stored
        if self.counterfactual_contract is not None and hid not in self.counterfactual_contracts:
            self.counterfactual_contract.hypothesis_id = self.counterfactual_contract.hypothesis_id or hid
            self.counterfactual_contracts[hid] = self.counterfactual_contract
        if self.constraint_candidates and hid not in self.constraint_candidates_by_hypothesis:
            self.constraint_candidates_by_hypothesis[hid] = list(self.constraint_candidates)
        if self.patch_candidates and hid not in self.patch_candidates_by_hypothesis:
            self.patch_candidates_by_hypothesis[hid] = list(self.patch_candidates)
        if self.patch_constraints_tried and hid not in self.patch_constraints_tried_by_hypothesis:
            self.patch_constraints_tried_by_hypothesis[hid] = list(self.patch_constraints_tried)
        if self.verification_feedback and hid not in self.verification_feedback_by_hypothesis:
            self.verification_feedback_by_hypothesis[hid] = list(self.verification_feedback)
        self._sync_active_views()

    def select_next_hypothesis(self) -> HypothesisRecord | None:
        active = [h for h in self.hypothesis_pool if h.status == "active"]
        if not active:
            return None
        active.sort(key=lambda h: h.score, reverse=True)
        chosen = active[0]
        self.active_hypothesis_id = chosen.id
        self._sync_active_views()
        for idx, suspect in enumerate(self.suspects):
            if suspect.get("hypothesis_id") == chosen.id:
                self.current_suspect_index = idx
                break
        return chosen

    def active_hypothesis(self) -> HypothesisRecord | None:
        if not self.hypothesis_pool:
            return None
        if not self.active_hypothesis_id:
            return self.select_next_hypothesis()
        for hypothesis in self.hypothesis_pool:
            if hypothesis.id == self.active_hypothesis_id:
                return hypothesis
        return self.select_next_hypothesis()

    def current_suspect(self) -> dict[str, Any] | None:
        if not self.suspects:
            return None
        active = self.active_hypothesis()
        if active:
            for idx, suspect in enumerate(self.suspects):
                if suspect.get("hypothesis_id") == active.id:
                    self.current_suspect_index = idx
                    return suspect
        if self.current_suspect_index < 0 or self.current_suspect_index >= len(self.suspects):
            self.current_suspect_index = 0
        return self.suspects[self.current_suspect_index]

    def current_hypothesis(self) -> RootCauseHypothesis | None:
        if not self.hypotheses:
            return None
        index = min(max(self.current_suspect_index, 0), len(self.hypotheses) - 1)
        return self.hypotheses[index]

    def record_route(self, actor: str, reason: str = "") -> None:
        self.route_history.append(
            {
                "round": self.round_index,
                "actor": actor,
                "hypothesis_id": self.active_hypothesis_id,
                "layer": self.current_layer(actor),
                "reason": reason,
            }
        )

    def current_root_cause_report(self) -> RootCauseReport | None:
        if self.active_hypothesis_id:
            report = self.root_cause_reports.get(self.active_hypothesis_id)
            if report is not None:
                self.root_cause_report = report
                return report
        return self.root_cause_report

    def _resolved_hypothesis_id(self, hypothesis_id: str | None = None) -> str:
        return str(hypothesis_id or self.active_hypothesis_id or "")

    def _sync_active_views(self) -> None:
        hid = self.active_hypothesis_id
        if not hid:
            return
        self.root_cause_report = self.root_cause_reports.get(hid)
        self.fuzz_result = self.fuzz_results.get(hid)
        self.counterfactual_contract = self.counterfactual_contracts.get(hid)
        self.constraint_candidates = list(self.constraint_candidates_by_hypothesis.get(hid, []))
        self.patch_candidates = list(self.patch_candidates_by_hypothesis.get(hid, []))
        self.patch_constraints_tried = list(self.patch_constraints_tried_by_hypothesis.get(hid, []))
        self.verification_feedback = list(self.verification_feedback_by_hypothesis.get(hid, []))

    def set_root_cause_report(self, report: RootCauseReport | None, hypothesis_id: str | None = None) -> None:
        if report is None:
            self.root_cause_report = None
            return
        resolved_hypothesis_id = str(hypothesis_id or report.hypothesis_id or self.active_hypothesis_id or "")
        if resolved_hypothesis_id:
            report.hypothesis_id = resolved_hypothesis_id
            self.root_cause_reports[resolved_hypothesis_id] = report
        self.root_cause_report = report
        if resolved_hypothesis_id == self.active_hypothesis_id:
            self._sync_active_views()

    def current_fuzz_result(self) -> dict[str, Any] | None:
        hid = self._resolved_hypothesis_id()
        if hid:
            if hid not in self.fuzz_results and not self.fuzz_results and self.fuzz_result is not None:
                payload_hid = str(self.fuzz_result.get("hypothesis_id", "") or hid)
                if payload_hid == hid:
                    self.fuzz_results[hid] = dict(self.fuzz_result)
            self.fuzz_result = self.fuzz_results.get(hid)
        return self.fuzz_result

    def set_fuzz_result(self, fuzz_result: dict[str, Any] | None, hypothesis_id: str | None = None) -> None:
        if fuzz_result is None:
            self.fuzz_result = None
            return
        resolved_hid = self._resolved_hypothesis_id(hypothesis_id or str(fuzz_result.get("hypothesis_id", "") or ""))
        stored = dict(fuzz_result)
        if resolved_hid:
            stored["hypothesis_id"] = resolved_hid
            self.fuzz_results[resolved_hid] = stored
            self.clear_layer2_fuzz_refresh(resolved_hid)
        self.fuzz_result = stored
        if resolved_hid == self.active_hypothesis_id:
            self._sync_active_views()

    def current_counterfactual_contract(self) -> CounterfactualContract | None:
        hid = self._resolved_hypothesis_id()
        if hid:
            if (
                hid not in self.counterfactual_contracts
                and not self.counterfactual_contracts
                and self.counterfactual_contract is not None
            ):
                if not self.counterfactual_contract.hypothesis_id:
                    self.counterfactual_contract.hypothesis_id = hid
                if self.counterfactual_contract.hypothesis_id == hid:
                    self.counterfactual_contracts[hid] = self.counterfactual_contract
            self.counterfactual_contract = self.counterfactual_contracts.get(hid)
        return self.counterfactual_contract

    def set_counterfactual_contract(
        self,
        contract: CounterfactualContract | None,
        hypothesis_id: str | None = None,
    ) -> None:
        if contract is None:
            self.counterfactual_contract = None
            return
        resolved_hid = self._resolved_hypothesis_id(hypothesis_id or contract.hypothesis_id)
        if resolved_hid:
            contract.hypothesis_id = resolved_hid
            self.counterfactual_contracts[resolved_hid] = contract
        self.counterfactual_contract = contract
        if resolved_hid == self.active_hypothesis_id:
            self._sync_active_views()

    def current_constraint_candidates(self) -> list[ConstraintCandidate]:
        hid = self._resolved_hypothesis_id()
        if hid:
            if hid not in self.constraint_candidates_by_hypothesis and not self.constraint_candidates_by_hypothesis and self.constraint_candidates:
                self.constraint_candidates_by_hypothesis[hid] = list(self.constraint_candidates)
            self.constraint_candidates = list(self.constraint_candidates_by_hypothesis.get(hid, []))
        return self.constraint_candidates

    def current_patch_candidates(self) -> list[PatchCandidate]:
        hid = self._resolved_hypothesis_id()
        if hid:
            if hid not in self.patch_candidates_by_hypothesis and not self.patch_candidates_by_hypothesis and self.patch_candidates:
                self.patch_candidates_by_hypothesis[hid] = list(self.patch_candidates)
            self.patch_candidates = list(self.patch_candidates_by_hypothesis.get(hid, []))
        return self.patch_candidates

    def current_verification_feedback(self) -> list[VerificationFeedback]:
        hid = self._resolved_hypothesis_id()
        if hid:
            if hid not in self.verification_feedback_by_hypothesis and not self.verification_feedback_by_hypothesis and self.verification_feedback:
                self.verification_feedback_by_hypothesis[hid] = list(self.verification_feedback)
            self.verification_feedback = list(self.verification_feedback_by_hypothesis.get(hid, []))
        return self.verification_feedback

    def current_patch_constraints_tried(self) -> list[str]:
        hid = self._resolved_hypothesis_id()
        if hid:
            if hid not in self.patch_constraints_tried_by_hypothesis and not self.patch_constraints_tried_by_hypothesis and self.patch_constraints_tried:
                self.patch_constraints_tried_by_hypothesis[hid] = list(self.patch_constraints_tried)
            self.patch_constraints_tried = list(self.patch_constraints_tried_by_hypothesis.get(hid, []))
        return self.patch_constraints_tried

    def requires_layer2_fuzz_refresh(self, hypothesis_id: str | None = None) -> bool:
        hid = self._resolved_hypothesis_id(hypothesis_id)
        return bool(hid and self.layer2_fuzz_refresh_reasons.get(hid))

    def request_layer2_fuzz_refresh(self, reason: str, hypothesis_id: str | None = None) -> None:
        hid = self._resolved_hypothesis_id(hypothesis_id)
        if hid:
            self.layer2_fuzz_refresh_reasons[hid] = str(reason or "refresh_requested")

    def clear_layer2_fuzz_refresh(self, hypothesis_id: str | None = None) -> None:
        hid = self._resolved_hypothesis_id(hypothesis_id)
        if hid:
            self.layer2_fuzz_refresh_reasons.pop(hid, None)

    def mark_patch_constraint_tried(self, constraint: str) -> None:
        text = str(constraint or "").strip()
        if not text:
            return
        hid = self._resolved_hypothesis_id()
        tried = list(self.current_patch_constraints_tried())
        if text not in tried:
            tried.append(text)
        if hid:
            self.patch_constraints_tried_by_hypothesis[hid] = tried
        self.patch_constraints_tried = tried
        if hid == self.active_hypothesis_id:
            self._sync_active_views()

    def last_verification_feedback(self) -> VerificationFeedback | None:
        feedback = self.current_verification_feedback()
        return feedback[-1] if feedback else None

    def current_layer(self, actor: str | None = None) -> str:
        actor = actor or self.next_actor
        if actor == "debug":
            return "layer1"
        if actor == "counterfactual":
            return "counterfactual"
        if actor in {"layer2", "fuzz", "constraint"}:
            return "layer2"
        if actor == "patch":
            if self.current_counterfactual_contract() is not None:
                return "counterfactual"
            if self.current_valid_constraints():
                return "layer2"
            if self.can_attempt_direct_patch():
                return "layer1"
        if actor == "verify":
            candidate = self.next_unverified_patch()
            if candidate is not None:
                return str(candidate.metadata.get("repair_layer", "layer2"))
        if self.champion_patch and self.champion_patch.get("repair_layer"):
            return str(self.champion_patch.get("repair_layer"))
        return "layer1"

    def register_progress(self, summary: str) -> None:
        if summary:
            self.recent_progress.append(summary)
        self.rounds_without_progress = 0

    def register_no_progress(self) -> None:
        self.rounds_without_progress += 1

    def add_message(self, message: AgentMessage) -> None:
        self.messages.append(message)
        self.open_questions.extend(message.questions_for_others)
        if message.recommended_next_actor:
            self.next_actor = message.recommended_next_actor
        report = (message.artifacts or {}).get("root_cause_report")
        if isinstance(report, dict) and report:
            allowed = {item.name for item in fields(RootCauseReport)}
            hydrated_report = RootCauseReport(**{key: value for key, value in report.items() if key in allowed})
            self.set_root_cause_report(hydrated_report, hypothesis_id=hydrated_report.hypothesis_id or self.active_hypothesis_id)
        contract = (message.artifacts or {}).get("counterfactual_contract")
        if isinstance(contract, dict) and contract:
            allowed = {item.name for item in fields(CounterfactualContract)}
            hydrated_contract = CounterfactualContract(**{key: value for key, value in contract.items() if key in allowed})
            self.set_counterfactual_contract(
                hydrated_contract,
                hypothesis_id=hydrated_contract.hypothesis_id or self.active_hypothesis_id,
            )

    def update_active_hypothesis(self, event: str, success: bool = False, details: dict[str, Any] | None = None) -> None:
        hypothesis = self.active_hypothesis()
        if hypothesis is None:
            return
        details = details or {}
        if success:
            hypothesis.evidence.append({"event": event, **details})
        else:
            hypothesis.failures.append({"type": event, **details})
        hypothesis.score = self.score_hypothesis(hypothesis)
        if self._failure_count(hypothesis, "no_angelic_values") >= 2:
            hypothesis.status = "exhausted"
        if self._failure_count(hypothesis, "weak_constraint") >= 2:
            hypothesis.status = "exhausted"
        if self._failure_count(hypothesis, "fuzz_budget_exhausted") >= 1:
            hypothesis.status = "exhausted"

    def _failure_count(self, hypothesis: HypothesisRecord, failure_type: str) -> int:
        return sum(1 for failure in hypothesis.failures if failure.get("type") == failure_type)

    def score_hypothesis(self, hypothesis: HypothesisRecord) -> float:
        debug_confidence = float(hypothesis.payload.get("debug_confidence", 0.55))
        evidence_quality = min(1.0, len(hypothesis.evidence) / 3.0)
        interventions = [
            event for event in hypothesis.evidence
            if event.get("event") in {
                "angelic_found",
                "counterfactual_contract_generated",
                "constraint_validated",
                "constraint_supported",
                "challenger_found_new_split",
                "patch_generated",
            }
        ]
        failures = max(1, len(hypothesis.failures) + len(interventions))
        intervention_success_rate = len(interventions) / failures
        patchability = 1.0 if any(event.get("event") == "patch_generated" for event in hypothesis.evidence) else 0.5
        novelty = 1.0 / (1.0 + max(0, self.current_suspect_index))
        score = (
            0.35 * debug_confidence
            + 0.25 * evidence_quality
            + 0.20 * intervention_success_rate
            + 0.10 * patchability
            + 0.10 * novelty
        )
        penalties = {
            "weak_constraint": 0.15,
            "no_angelic_values": 0.20,
            "fuzz_budget_exhausted": 0.20,
            "constraint_falsified": 0.25,
            "constraint_overfit": 0.15,
            "constraint_inconclusive": 0.10,
            "semantic_regression": 0.25,
            "overfit_poc": 0.20,
            "bad_patch_location": 0.15,
            "nonlocal_invariant": 0.15,
            "direct_patch_suspicious": 0.15,
            "direct_patch_failed": 0.15,
        }
        for failure in hypothesis.failures:
            score -= penalties.get(failure.get("type", ""), 0.05)
        return max(0.0, min(1.0, score))

    def replace_constraint_candidates(self, candidates: list[ConstraintCandidate]) -> None:
        hid = self._resolved_hypothesis_id()
        by_constraint: dict[str, ConstraintCandidate] = {}
        for candidate in self.current_constraint_candidates():
            by_constraint[candidate.constraint] = candidate
        for candidate in candidates:
            by_constraint[candidate.constraint] = candidate
        merged = list(by_constraint.values())
        if hid:
            self.constraint_candidates_by_hypothesis[hid] = merged
        self.constraint_candidates = merged
        if hid == self.active_hypothesis_id:
            self._sync_active_views()

    def can_attempt_direct_patch(self) -> bool:
        report = self.current_root_cause_report()
        if report is None or not self.active_hypothesis_id:
            return False
        if not report.direct_patch_allowed:
            return False
        return self.active_hypothesis_id not in self.direct_patch_attempted_hypotheses

    def mark_direct_patch_attempted(self) -> None:
        if self.active_hypothesis_id and self.active_hypothesis_id not in self.direct_patch_attempted_hypotheses:
            self.direct_patch_attempted_hypotheses.append(self.active_hypothesis_id)

    def current_valid_constraints(self) -> list[ConstraintCandidate]:
        candidates = [
            candidate for candidate in self.current_constraint_candidates()
            if candidate.constraint_status in {
                "supported_and_executable",
                "supported_but_proxy_like",
                "weakly_supported",
                "operational_repair_intent",
            }
        ]
        candidates.sort(
            key=lambda candidate: (
                candidate.constraint_status != "supported_and_executable",
                candidate.constraint_status == "weakly_supported",
                -float(candidate.overall_score or 0.0),
                -float(candidate.generalization_score or 0.0),
                candidate.attempts,
            )
        )
        return candidates

    def add_patch_candidates(self, candidates: list[PatchCandidate]) -> None:
        hid = self._resolved_hypothesis_id()
        merged = list(self.current_patch_candidates()) + list(candidates)
        if hid:
            self.patch_candidates_by_hypothesis[hid] = merged
        self.patch_candidates = merged
        if hid == self.active_hypothesis_id:
            self._sync_active_views()

    def next_unverified_patch(self) -> PatchCandidate | None:
        for candidate in self.current_patch_candidates():
            if candidate.status == "generated":
                return candidate
        return None

    def add_verification_feedback(self, feedback: VerificationFeedback) -> None:
        hid = self._resolved_hypothesis_id()
        merged = list(self.current_verification_feedback()) + [feedback]
        if hid:
            self.verification_feedback_by_hypothesis[hid] = merged
        self.verification_feedback = merged
        if hid == self.active_hypothesis_id:
            self._sync_active_views()
        if feedback.status == "new_site_crash":
            crash_site = feedback.details.get("crash_site") if feedback.details else None
            if crash_site:
                hid = f"hyp-new-{len(self.hypothesis_pool) + 1}"
                record = HypothesisRecord(
                    id=hid,
                    summary=f"Crash moved to {crash_site.get('file')}:{crash_site.get('line')}",
                    suspect_file=crash_site.get("file", ""),
                    suspect_line=int(crash_site.get("line", -1) or -1),
                    suspect_variables=[],
                    suspect_expressions=[],
                    score=0.45,
                    evidence=[{"event": "new_site_crash", "crash_site": crash_site}],
                    payload={"debug_confidence": 0.45, "crash_site": crash_site},
                )
                self.hypothesis_pool.append(record)
        if feedback.layer1_verdict == "weak":
            return
        if feedback.layer1_verdict == "suspicious":
            self.update_active_hypothesis("direct_patch_suspicious", success=False, details={"message": feedback.message})
            return
        if feedback.status != "pass":
            self.update_active_hypothesis(feedback.status, success=False, details={"message": feedback.message})
            if feedback.direct_patch_assessment and feedback.direct_patch_assessment.get("verdict") == "failed":
                self.update_active_hypothesis("direct_patch_failed", success=False, details={"message": feedback.message})
            if feedback.status in {"semantic_regression", "overfit_poc"}:
                hypothesis = self.active_hypothesis()
                if hypothesis is not None:
                    hypothesis.status = "active"

    def should_stop(self) -> bool:
        if self.next_actor in {"done", "stop"}:
            return True
        if self.champion_patch is not None:
            return True
        if self.next_actor == "verify" and self.next_unverified_patch() is not None:
            return False
        if self.round_index >= self.max_rounds:
            return True
        if self.rounds_without_progress >= 3:
            return True
        return False

    def to_dict(self) -> dict[str, Any]:
        return to_jsonable(asdict(self))
