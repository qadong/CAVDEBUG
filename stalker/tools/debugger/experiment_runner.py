from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from tools.debugger.observability import DebuggerObservability
from tools.debugger.runtime_policy import DebuggerRuntimePolicy
from tools.debugger.session import AssignmentResult, BreakpointTarget, DebuggerSession, NavigationResult
from tools.debugger.snapshotter import DebuggerSnapshotter, ProgramStateSnapshot, SnapshotRequest


@dataclass(frozen=True)
class DebuggerIntervention:
    kind: str
    payload: dict[str, Any]


@dataclass(frozen=True)
class ExperimentPlan:
    target: BreakpointTarget
    before_snapshot: SnapshotRequest | None = None
    interventions: list[DebuggerIntervention] = field(default_factory=list)
    after_snapshot: SnapshotRequest | None = None
    continue_after: bool = False
    reset_runtime_metrics: bool = True
    workload_metrics: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ExperimentResult:
    preparation: NavigationResult
    before_snapshot: ProgramStateSnapshot | None
    interventions: list[AssignmentResult]
    after_snapshot: ProgramStateSnapshot | None
    continue_result: tuple[dict[str, Any], str] | None
    policy_state: dict[str, Any]
    metrics: dict[str, Any]
    health: dict[str, Any]


class DebuggerExperimentRunner:
    def __init__(
        self,
        *,
        session: DebuggerSession,
        snapshotter: DebuggerSnapshotter,
        policy: DebuggerRuntimePolicy,
        observability: DebuggerObservability,
    ) -> None:
        self._session = session
        self._snapshotter = snapshotter
        self._policy = policy
        self._observability = observability

    def run(self, plan: ExperimentPlan) -> ExperimentResult:
        self._session.reset_metrics()
        if plan.reset_runtime_metrics:
            self._session.reset_runtime_metrics()

        preparation = self._session.prepare(plan.target)
        policy_state = self._policy.observe_runtime(
            self._session.get_runtime_metrics(),
            workload_metrics=plan.workload_metrics,
        ).to_dict()
        self._observability.record_policy_state(policy_state)

        before_snapshot = None
        if plan.before_snapshot is not None:
            before_snapshot = self._snapshotter.capture(plan.before_snapshot, policy=self._policy)
            self._observability.record_snapshot(before_snapshot.metrics)

        intervention_results: list[AssignmentResult] = []
        for intervention in plan.interventions:
            result = self.apply_intervention(intervention)
            intervention_results.append(result)
            self._observability.record_intervention(result.success)

        after_snapshot = None
        if plan.after_snapshot is not None:
            expression_evals = before_snapshot.metrics.get("expression_evals", 0) if before_snapshot else 0
            after_snapshot = self._snapshotter.capture(
                plan.after_snapshot,
                policy=self._policy,
                prior_expression_evals=int(expression_evals or 0),
            )
            self._observability.record_snapshot(after_snapshot.metrics)

        continue_result = None
        if plan.continue_after:
            continue_result = self._session.continue_run()
            self._observability.record_continue()

        runtime_metrics = self._session.get_runtime_metrics()
        policy_state = self._policy.observe_runtime(runtime_metrics, workload_metrics=plan.workload_metrics).to_dict()
        self._observability.record_policy_state(policy_state)
        self._observability.record_experiment()
        metrics = self._observability.export_metrics(
            session_metrics=self._session.export_metrics(),
            runtime_metrics=runtime_metrics,
        )
        health = self._observability.health(
            session_metrics=metrics["session"],
            runtime_metrics=metrics["runtime"],
        ).to_dict()
        return ExperimentResult(
            preparation=preparation,
            before_snapshot=before_snapshot,
            interventions=intervention_results,
            after_snapshot=after_snapshot,
            continue_result=continue_result,
            policy_state=policy_state,
            metrics=metrics,
            health=health,
        )

    def apply_intervention(self, intervention: DebuggerIntervention) -> AssignmentResult:
        payload = intervention.payload
        if intervention.kind == "assign":
            return self._session.assign(payload["variable"], payload["value"])
        if intervention.kind == "assign_expression":
            return self._session.assign_expression(payload["expression"])
        if intervention.kind == "functional_guard":
            return self._session.add_functional_guard(
                payload["file"], payload["line"], payload["condition"], payload["return_value"]
            )
        if intervention.kind == "execute":
            message = self._session.execute(payload["command"])
            return AssignmentResult(success=True, message=message, kind="execute")
        raise ValueError(f"Unsupported debugger intervention kind: {intervention.kind}")
