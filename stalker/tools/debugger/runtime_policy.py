from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class DebuggerPolicyState:
    mode: str
    reasons: list[str]
    actions: dict[str, Any]
    config: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "reasons": list(self.reasons),
            "actions": dict(self.actions),
            "config": dict(self.config),
        }


class DebuggerRuntimePolicy:
    """Debugger-only degradation policy shared by higher-level workflows."""

    def __init__(self, suspect_object: dict[str, Any] | None = None) -> None:
        suspect_object = suspect_object or {}
        self._config = {
            "eval_timeout_soft_limit": self._read_int(
                suspect_object, "fuzz_harness_eval_timeout_soft_limit", "FUZZ_HARNESS_EVAL_TIMEOUT_SOFT_LIMIT", 2
            ),
            "respawn_soft_limit": self._read_int(
                suspect_object, "fuzz_harness_respawn_soft_limit", "FUZZ_HARNESS_RESPAWN_SOFT_LIMIT", 3
            ),
            "cache_miss_soft_limit": self._read_int(
                suspect_object, "fuzz_harness_cache_miss_soft_limit", "FUZZ_HARNESS_CACHE_MISS_SOFT_LIMIT", 10
            ),
            "total_eval_seconds_soft_limit": self._read_float(
                suspect_object, "fuzz_harness_total_eval_seconds_soft_limit", "FUZZ_HARNESS_TOTAL_EVAL_SECONDS_SOFT_LIMIT", 8.0
            ),
            "reduced_snapshot_eval_window": self._read_int(
                suspect_object, "fuzz_harness_reduced_snapshot_eval_window", "FUZZ_HARNESS_REDUCED_SNAPSHOT_EVAL_WINDOW", 8
            ),
            "minimal_snapshot_eval_window": self._read_int(
                suspect_object, "fuzz_harness_minimal_snapshot_eval_window", "FUZZ_HARNESS_MINIMAL_SNAPSHOT_EVAL_WINDOW", 2
            ),
        }
        self._state = DebuggerPolicyState(
            mode="normal",
            reasons=[],
            actions={
                "disable_preemptive_respawn": False,
                "respawn_interval_multiplier": 1,
                "snapshot_eval_window": None,
                "skip_snapshot_backtrace": False,
            },
            config=dict(self._config),
        )

    def _read_int(self, suspect_object: dict[str, Any], field: str, env_name: str, default: int) -> int:
        raw = suspect_object.get(field, os.environ.get(env_name, default))
        try:
            value = int(raw)
        except Exception:
            value = default
        return max(0, value)

    def _read_float(self, suspect_object: dict[str, Any], field: str, env_name: str, default: float) -> float:
        raw = suspect_object.get(field, os.environ.get(env_name, default))
        try:
            value = float(raw)
        except Exception:
            value = default
        return max(0.0, value)

    def observe(self, workload_metrics: dict[str, Any] | None, debugger_runtime: dict[str, Any] | None) -> dict[str, Any]:
        return self.observe_runtime(debugger_runtime, workload_metrics=workload_metrics).to_dict()

    def observe_runtime(
        self, debugger_runtime: dict[str, Any] | None, workload_metrics: dict[str, Any] | None = None
    ) -> DebuggerPolicyState:
        workload_metrics = workload_metrics or {}
        debugger_runtime = debugger_runtime or {}
        debugger_stats = workload_metrics.get("debugger_stats") if isinstance(workload_metrics.get("debugger_stats"), dict) else {}
        lldb = debugger_runtime.get("lldb") if isinstance(debugger_runtime.get("lldb"), dict) else {}

        eval_timeouts = int(lldb.get("eval_timeouts", 0) or 0)
        total_eval_seconds = float(lldb.get("total_eval_seconds", 0.0) or 0.0)
        cache_misses = int(debugger_runtime.get("print_cache_misses", 0) or 0)
        respawns = int(debugger_stats.get("respawns", 0) or 0)
        prepare_failures = int(debugger_stats.get("prepare_failures", 0) or 0)
        slow_evals = int(lldb.get("slow_evals", 0) or 0)

        minimal_reasons: list[str] = []
        reduced_reasons: list[str] = []

        if eval_timeouts >= self._config["eval_timeout_soft_limit"]:
            minimal_reasons.append("eval_timeouts")
        if respawns >= self._config["respawn_soft_limit"]:
            minimal_reasons.append("respawns")
        if total_eval_seconds >= self._config["total_eval_seconds_soft_limit"]:
            minimal_reasons.append("total_eval_seconds")

        if cache_misses >= self._config["cache_miss_soft_limit"]:
            reduced_reasons.append("cache_misses")
        if prepare_failures > 0:
            reduced_reasons.append("prepare_failures")
        if slow_evals > 0:
            reduced_reasons.append("slow_evals")

        if minimal_reasons:
            state = DebuggerPolicyState(
                mode="minimal",
                reasons=sorted(set(minimal_reasons + reduced_reasons)),
                actions={
                    "disable_preemptive_respawn": True,
                    "respawn_interval_multiplier": 0,
                    "snapshot_eval_window": self._config["minimal_snapshot_eval_window"],
                    "skip_snapshot_backtrace": True,
                },
                config=dict(self._config),
            )
        elif reduced_reasons:
            state = DebuggerPolicyState(
                mode="reduced",
                reasons=sorted(set(reduced_reasons)),
                actions={
                    "disable_preemptive_respawn": False,
                    "respawn_interval_multiplier": 2,
                    "snapshot_eval_window": self._config["reduced_snapshot_eval_window"],
                    "skip_snapshot_backtrace": False,
                },
                config=dict(self._config),
            )
        else:
            state = DebuggerPolicyState(
                mode="normal",
                reasons=[],
                actions={
                    "disable_preemptive_respawn": False,
                    "respawn_interval_multiplier": 1,
                    "snapshot_eval_window": None,
                    "skip_snapshot_backtrace": False,
                },
                config=dict(self._config),
            )

        self._state = state
        return state

    def effective_respawn_interval(self, base_interval: int) -> int | None:
        if self._state.actions.get("disable_preemptive_respawn"):
            return None
        multiplier = int(self._state.actions.get("respawn_interval_multiplier", 1) or 1)
        return max(1, int(base_interval or 1) * multiplier)

    def effective_snapshot_eval_budget(self, base_budget: int | None, expression_evals: int) -> int | None:
        window = self._state.actions.get("snapshot_eval_window")
        if window is None:
            return base_budget
        cap = max(0, int(expression_evals or 0) + int(window or 0))
        if base_budget is None:
            return cap
        if int(base_budget) == 0:
            return 0
        return min(int(base_budget), cap)

    def should_capture_backtrace(self) -> bool:
        return not bool(self._state.actions.get("skip_snapshot_backtrace", False))

    def export_state(self) -> dict[str, Any]:
        return self._state.to_dict()
