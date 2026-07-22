from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class HarnessHealth:
    status: str
    reasons: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {"status": self.status, "reasons": list(self.reasons)}


class DebuggerObservability:
    def __init__(self) -> None:
        self._metrics: dict[str, Any] = {
            "snapshots": 0,
            "snapshot_expression_evals": 0,
            "snapshot_skipped_expressions": 0,
            "experiments": 0,
            "interventions": 0,
            "intervention_failures": 0,
            "continue_runs": 0,
            "policy_updates": 0,
            "degradation_events": 0,
            "latest_policy": {},
        }

    def record_snapshot(self, snapshot_metrics: dict[str, Any]) -> None:
        self._metrics["snapshots"] += 1
        self._metrics["snapshot_expression_evals"] += int(snapshot_metrics.get("expression_evals", 0) or 0)
        self._metrics["snapshot_skipped_expressions"] += int(snapshot_metrics.get("skipped_expressions", 0) or 0)

    def record_intervention(self, success: bool) -> None:
        self._metrics["interventions"] += 1
        if not success:
            self._metrics["intervention_failures"] += 1

    def record_continue(self) -> None:
        self._metrics["continue_runs"] += 1

    def record_policy_state(self, policy_state: dict[str, Any]) -> None:
        self._metrics["policy_updates"] += 1
        previous_mode = (self._metrics.get("latest_policy") or {}).get("mode")
        current_mode = (policy_state or {}).get("mode")
        if previous_mode and previous_mode != current_mode:
            self._metrics["degradation_events"] += 1
        self._metrics["latest_policy"] = dict(policy_state or {})

    def record_experiment(self) -> None:
        self._metrics["experiments"] += 1

    def export_metrics(self, *, session_metrics: dict[str, Any], runtime_metrics: dict[str, Any]) -> dict[str, Any]:
        return {
            "harness": dict(self._metrics),
            "session": dict(session_metrics),
            "runtime": dict(runtime_metrics),
        }

    def health(self, *, session_metrics: dict[str, Any], runtime_metrics: dict[str, Any]) -> HarnessHealth:
        reasons: list[str] = []
        policy_mode = (self._metrics.get("latest_policy") or {}).get("mode")
        lldb = runtime_metrics.get("lldb") if isinstance(runtime_metrics.get("lldb"), dict) else {}
        if session_metrics.get("prepare_failures", 0):
            reasons.append("prepare_failures")
        if session_metrics.get("assignment_failures", 0):
            reasons.append("assignment_failures")
        if int(lldb.get("eval_timeouts", 0) or 0) > 0:
            reasons.append("eval_timeouts")
        if policy_mode == "minimal":
            reasons.append("policy_minimal")
        elif policy_mode == "reduced":
            reasons.append("policy_reduced")

        status = "healthy"
        if "policy_minimal" in reasons or "eval_timeouts" in reasons or "prepare_failures" in reasons:
            status = "degraded"
        elif reasons:
            status = "warning"
        return HarnessHealth(status=status, reasons=reasons)

