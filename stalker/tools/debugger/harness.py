from __future__ import annotations

from typing import Any

from tools.debugger.experiment_runner import (
    DebuggerExperimentRunner,
    DebuggerIntervention,
    ExperimentPlan,
    ExperimentResult,
)
from tools.debugger.observability import DebuggerObservability
from tools.debugger.runtime_policy import DebuggerRuntimePolicy
from tools.debugger.session import AssignmentResult, BreakpointTarget, DebuggerSession, NavigationResult
from tools.debugger.snapshotter import DebuggerSnapshotter, ProgramStateSnapshot, SnapshotRequest


DebuggerHarnessPolicy = DebuggerRuntimePolicy


class DebuggerHarness:
    """Stable shared harness facade for debugger-backed workflows."""

    def __init__(self, suspect_object: dict[str, Any] | None = None, *, backend=None) -> None:
        self.session = DebuggerSession(backend=backend)
        self.policy = DebuggerRuntimePolicy(suspect_object or {})
        self.snapshotter = DebuggerSnapshotter(self.session)
        self.observability = DebuggerObservability()
        self.experiment_runner = DebuggerExperimentRunner(
            session=self.session,
            snapshotter=self.snapshotter,
            policy=self.policy,
            observability=self.observability,
        )

    def prepare(
        self,
        file: str,
        line: int,
        *,
        end_line: int | None = None,
        ignore_count: int | None = None,
        condition: str | None = None,
        last_hit: bool = False,
    ) -> NavigationResult:
        result = self.session.prepare(
            BreakpointTarget(
                file=file,
                line=line,
                end_line=end_line,
                ignore_count=ignore_count,
                condition=condition,
                last_hit=last_hit,
            )
        )
        self.refresh_policy()
        return result

    def snapshot(
        self,
        *,
        variables: list[str] | None = None,
        expressions: list[str] | None = None,
        expression_budget: int | None = None,
        include_backtrace: bool = False,
        backtrace_limit: int | None = None,
    ) -> ProgramStateSnapshot:
        snapshot = self.snapshotter.capture(
            SnapshotRequest(
                variables=list(variables or []),
                expressions=list(expressions or []),
                expression_budget=expression_budget,
                include_backtrace=include_backtrace,
                backtrace_limit=backtrace_limit,
            ),
            policy=self.policy,
        )
        self.observability.record_snapshot(snapshot.metrics)
        return snapshot

    def apply(self, intervention: DebuggerIntervention) -> AssignmentResult:
        result = self.experiment_runner.apply_intervention(intervention)
        self.observability.record_intervention(result.success)
        return result

    def run_experiment(self, plan: ExperimentPlan) -> ExperimentResult:
        return self.experiment_runner.run(plan)

    def refresh_policy(self, workload_metrics: dict[str, Any] | None = None) -> dict[str, Any]:
        state = self.policy.observe_runtime(
            self.session.get_runtime_metrics(),
            workload_metrics=workload_metrics,
        ).to_dict()
        self.observability.record_policy_state(state)
        return state

    def metrics(self) -> dict[str, Any]:
        return self.observability.export_metrics(
            session_metrics=self.session.export_metrics(),
            runtime_metrics=self.session.get_runtime_metrics(),
        )

    def health(self) -> dict[str, Any]:
        return self.observability.health(
            session_metrics=self.session.export_metrics(),
            runtime_metrics=self.session.get_runtime_metrics(),
        ).to_dict()

    def export_state(self) -> dict[str, Any]:
        return {
            "policy": self.policy.export_state(),
            "metrics": self.metrics(),
            "health": self.health(),
            "last_target": None
            if self.session.last_target is None
            else {
                "file": self.session.last_target.file,
                "line": self.session.last_target.line,
                "end_line": self.session.last_target.end_line,
                "ignore_count": self.session.last_target.ignore_count,
                "condition": self.session.last_target.condition,
                "last_hit": self.session.last_target.last_hit,
            },
        }
