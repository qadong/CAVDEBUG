from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal


ActorName = Literal[
    "reproduce",
    "debug",
    "counterfactual",
    "layer2",
    "fuzz",
    "constraint",
    "patch",
    "verify",
    "vote",
    "done",
    "stop",
]


@dataclass
class EvidenceItem:
    source: str
    summary: str
    kind: str = "observation"
    payload: dict[str, Any] = field(default_factory=dict)


@dataclass
class OpenQuestion:
    source: str
    question: str
    target_actor: str | None = None
    priority: int = 1


@dataclass
class RootCauseHypothesis:
    summary: str
    suspect_file: str = ""
    suspect_line: int = -1
    suspect_variables: list[str] = field(default_factory=list)
    confidence: float = 0.0
    payload: dict[str, Any] = field(default_factory=dict)


@dataclass
class RootCauseReport:
    hypothesis_id: str = ""
    summary: str = ""
    bug_type: str = "unknown"
    surface_bug_type: str = "unknown"
    repair_topology: str = "single_site"
    preferred_repair_stage: str = ""
    preferred_edit_location: dict[str, Any] = field(default_factory=dict)
    candidate_edit_locations: list[dict[str, Any]] = field(default_factory=list)
    direct_patch_allowed: bool = False
    direct_patch_risk: str = "high"
    direct_patch_reason: str = ""
    direct_patch_contract: str = ""
    evidence_family: str = "predicate"
    evidence_kind: str = "predicate_state"
    selective_generalization: str = "constraint"
    operational_repair_intent: str = ""
    forbidden_fix_patterns: list[str] = field(default_factory=list)
    validation_obligations: list[str] = field(default_factory=list)
    escalation_target: str = "fuzz"
    evidence_requirements: list[str] = field(default_factory=list)


@dataclass
class ProgramStateSnapshot:
    location: dict[str, Any] = field(default_factory=dict)
    variables: dict[str, Any] = field(default_factory=dict)
    expressions: dict[str, Any] = field(default_factory=dict)
    memory_summaries: dict[str, Any] = field(default_factory=dict)
    backtrace: list[str] = field(default_factory=list)
    availability: dict[str, str] = field(default_factory=dict)


@dataclass
class Intervention:
    kind: str = "assignment"
    actions: list[dict[str, Any]] = field(default_factory=list)
    target_location: dict[str, Any] = field(default_factory=dict)
    applied: bool = False
    apply_error: str = ""


@dataclass
class TracePair:
    hypothesis_id: str = ""
    demonic_before: dict[str, Any] = field(default_factory=dict)
    intervention: dict[str, Any] = field(default_factory=dict)
    angelic_after: dict[str, Any] = field(default_factory=dict)
    outcome: dict[str, Any] = field(default_factory=dict)
    path_delta: dict[str, Any] = field(default_factory=dict)


@dataclass
class HypothesisRecord:
    id: str
    summary: str
    suspect_file: str = ""
    suspect_line: int = -1
    suspect_variables: list[str] = field(default_factory=list)
    suspect_expressions: list[str] = field(default_factory=list)
    score: float = 0.0
    status: str = "active"
    evidence: list[dict[str, Any]] = field(default_factory=list)
    failures: list[dict[str, Any]] = field(default_factory=list)
    payload: dict[str, Any] = field(default_factory=dict)


@dataclass
class PatchStrategyDecision:
    strategy: str = "bounds_check_before_access"
    location_type: str = "same_site"
    rationale: str = ""
    semantic_risk: str = "medium"


@dataclass
class ConstraintCandidate:
    constraint: str
    constraint_kind: str = "predicate"
    status: str = "proposed"
    constraint_status: str = "proposed"
    precheck_status: str = "pending"
    precheck_score: float = 0.0
    challenge_status: str = "pending"
    challenge_score: float = 0.0
    source: str = "constraint"
    reason: str = ""
    evidence: list[str] = field(default_factory=list)
    attempts: int = 0
    verification: dict[str, Any] = field(default_factory=dict)
    required_expressions: list[str] = field(default_factory=list)
    positive_examples: list[dict[str, Any]] = field(default_factory=list)
    negative_examples: list[dict[str, Any]] = field(default_factory=list)
    counterexamples: list[dict[str, Any]] = field(default_factory=list)
    generalization_score: float = 0.0
    repair_intent: str = ""
    top_angelic_examples: list[Any] = field(default_factory=list)
    demonic_summary: str = ""
    support_stats: dict[str, Any] = field(default_factory=dict)
    mechanism_hint: str = ""
    constraint_role: str = "generalized_hypothesis"
    execution_check: dict[str, Any] = field(default_factory=dict)
    challenge_result: dict[str, Any] = field(default_factory=dict)
    recommended_next_actor: str = "patch"
    overall_score: float = 0.0
    causal_chain_summary: str = ""
    preferred_repair_stage: str = ""
    forbidden_repair_stages: list[str] = field(default_factory=list)
    strategy_hints: list[dict[str, Any]] = field(default_factory=list)
    bug_type_profile: dict[str, Any] = field(default_factory=dict)
    typed_angelic_evidence: dict[str, Any] = field(default_factory=dict)
    demonic_trace_summary: dict[str, Any] = field(default_factory=dict)
    abstract_constraint: dict[str, Any] = field(default_factory=dict)


@dataclass
class CounterfactualContract:
    contract_id: str
    hypothesis_id: str

    bug_type: str
    evidence_family: str
    counterfactual_kind: str

    crash_site: dict[str, Any]
    intervention_site: dict[str, Any]
    enforcement_site: dict[str, Any]
    enforcement_priority: str

    suspect_variables: list[str]
    repair_class: str = ""
    suspect_objects: list[str] = field(default_factory=list)
    observed_unsafe_state: dict[str, Any] = field(default_factory=dict)
    unsafe_condition: str = ""
    baseline_facts: list[str] = field(default_factory=list)

    angelic_observations: list[dict[str, Any]] = field(default_factory=list)
    demonic_observations: list[dict[str, Any]] = field(default_factory=list)

    boundary_kind: str = ""
    boundary_predicate: str = ""
    boundary_summary: str = ""
    boundary_audit: dict[str, Any] = field(default_factory=dict)
    semantic_repair_status: str = "unknown"

    repair_invariant: str = ""
    contract_scope: str = ""
    invariant_scope: str = ""
    affected_operations: list[str] = field(default_factory=list)
    enforcement_role_preference: list[str] = field(default_factory=list)

    executable_predicate: str = ""
    repair_intent: str = ""
    patch_strategy_hint: str = ""

    avoid_patch_patterns: list[str] = field(default_factory=list)
    forbidden_patch_patterns: list[str] = field(default_factory=list)
    forbidden_literals: list[str] = field(default_factory=list)
    validation_obligations: list[str] = field(default_factory=list)

    rationale: str = ""


@dataclass
class PatchCandidate:
    constraint: str = ""
    status: str = "generated"
    source: str = "patch"
    patches: list[dict[str, Any]] = field(default_factory=list)
    retry: int = 0
    valid: bool = False
    resign: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)
    verification: dict[str, Any] | None = None
    strategy: str = "bounds_check_before_access"
    location_type: str = "same_site"
    semantic_risk: str = "medium"
    requires_regression_check: bool = False


@dataclass
class VerificationFeedback:
    status: str
    message: str
    error_signature: str = ""
    old_site_vs_new_site: str = ""
    blame_hint: str = ""
    recommended_next_actor: str = "done"
    layer1_verdict: str = ""
    direct_patch_assessment: dict[str, Any] = field(default_factory=dict)
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentMessage:
    actor: str
    claims: list[str] = field(default_factory=list)
    evidence: list[EvidenceItem] = field(default_factory=list)
    confidence: float = 0.0
    questions_for_others: list[OpenQuestion] = field(default_factory=list)
    recommended_next_actor: str | None = None
    artifacts: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def to_jsonable(value: Any) -> Any:
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if isinstance(value, list):
        return [to_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {key: to_jsonable(item) for key, item in value.items()}
    return value
