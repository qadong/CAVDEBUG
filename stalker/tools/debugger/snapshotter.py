from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from tools.debugger.runtime_policy import DebuggerRuntimePolicy
from tools.debugger.session import DebuggerSession


_UNAVAILABLE_MARKERS = ("error:", "timeout", "not available", "unavailable", "lldb_eval")


@dataclass(frozen=True)
class SnapshotRequest:
    variables: list[str] = field(default_factory=list)
    expressions: list[str] = field(default_factory=list)
    expression_budget: int | None = None
    include_backtrace: bool = False
    backtrace_limit: int | None = None


@dataclass(frozen=True)
class ProgramStateSnapshot:
    variables: dict[str, str]
    expressions: dict[str, str]
    backtrace: list[str]
    metrics: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "variables": dict(self.variables),
            "expressions": dict(self.expressions),
            "backtrace": list(self.backtrace),
            "metrics": dict(self.metrics),
        }


class DebuggerSnapshotter:
    def __init__(self, session: DebuggerSession) -> None:
        self._session = session

    def capture(
        self,
        request: SnapshotRequest,
        *,
        policy: DebuggerRuntimePolicy | None = None,
        prior_expression_evals: int = 0,
    ) -> ProgramStateSnapshot:
        variables: dict[str, str] = {}
        expressions: dict[str, str] = {}
        variable_evals = 0
        expression_evals = 0
        skipped_expressions = 0

        for variable in request.variables:
            variables[variable] = self._normalize_value(self._session.print_value(variable))
            variable_evals += 1

        effective_budget = request.expression_budget
        if policy is not None:
            effective_budget = policy.effective_snapshot_eval_budget(request.expression_budget, prior_expression_evals)

        for expression in request.expressions:
            if effective_budget is not None and expression_evals >= effective_budget:
                expressions[expression] = "Error: Snapshot expression budget exhausted"
                skipped_expressions += 1
                continue
            expressions[expression] = self._normalize_value(self._session.print_value(expression))
            expression_evals += 1

        include_backtrace = bool(request.include_backtrace)
        if policy is not None and include_backtrace:
            include_backtrace = policy.should_capture_backtrace()
        backtrace = self._session.backtrace() if include_backtrace else []
        if request.backtrace_limit is not None:
            backtrace = backtrace[: max(0, request.backtrace_limit)]

        self._session.record_snapshot()

        return ProgramStateSnapshot(
            variables=variables,
            expressions=expressions,
            backtrace=backtrace,
            metrics={
                "variable_evals": variable_evals,
                "expression_evals": expression_evals,
                "skipped_expressions": skipped_expressions,
                "backtrace_captured": bool(backtrace),
                "expression_budget": effective_budget,
            },
        )

    def _normalize_value(self, value: Any) -> str:
        if value is None:
            return "Error: Value unavailable"
        text = str(value)
        lowered = text.lower()
        if any(marker in lowered for marker in _UNAVAILABLE_MARKERS):
            return text
        return text
