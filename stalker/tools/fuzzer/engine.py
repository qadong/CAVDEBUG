from tools.debugger.functions import (
    debugger_run_to_line, debugger_assign, debugger_assign_expression, 
    debugger_continue, debugger_clear_breakpoints, debugger_backtrace, 
    debugger_print, debugger_get_type, debugger_run_to_last_hit, 
    debugger_set_breakpoint, debugger_set_breakpoint_with_ids,
    debugger_get_breakpoint_hit_count, debugger_run,
    debugger_execute, debugger_add_functional_guard,
    debugger_get_cost_stats, debugger_reset_cost_stats,
)
from tools.file.functions import file_get_decorated_content
from tools.lsp.functions import lsp_get_function
from agent.generic_agent import GenericAgent
from utils.logger import get_logger
from utils.llm_helper import LLMHelper
from utils.files import load_json
from utils.seed_records import (
    angelic_assignment_sets,
    angelic_seed_records,
    demonic_seed_records,
    demonic_value_map,
    record_values,
)
import re
import os
import glob
import time
from typing import Any, Callable, Optional, Tuple
# Import from new modules
from .utils import check_asan_error_in_output, extract_base_type_for_const_cast, parse_address
from .type_utils import get_actual_variable_type, get_mutator
from .handles import InterventionHandle, infer_intervention_handles, choose_primary_handle, find_handle
from .filtering import filter_angelic_outliers, filter_angelic_values_with_agent
from .constraint import deduce_constraint
from .synthesized_mutator import MutationOrchestrator
from agent.prompts import FUZZ_AT_ACTION_RULES_PROMPT, FUZZ_AT_ACTION_ERROR_TEMPLATE
from agent.type_angelic import build_typed_angelic_evidence, infer_bug_type_profile
from tools.debugger.experiment_runner import DebuggerIntervention, ExperimentPlan
from tools.debugger.harness import DebuggerHarness, DebuggerHarnessPolicy
from tools.debugger.session import BreakpointTarget
from tools.debugger.snapshotter import SnapshotRequest


class _EngineDebuggerBackend:
    def run(self):
        return debugger_run()

    def continue_run(self):
        return debugger_continue()

    def run_to_line(self, file, start_line, end_line=None, ignore_count=None, condition=None):
        return debugger_run_to_line(file, start_line, end_line=end_line, ignore_count=ignore_count, condition=condition)

    def run_to_last_hit(self, file, line):
        return debugger_run_to_last_hit(file, line)

    def clear_breakpoints(self):
        return debugger_clear_breakpoints()

    def set_breakpoint(self, file, start_line, end_line=None, ignore_count=None, condition=None):
        return debugger_set_breakpoint(file, start_line, end_line=end_line, ignore_count=ignore_count, condition=condition)

    def get_breakpoint_hit_count(self, breakpoint_id):
        return debugger_get_breakpoint_hit_count(breakpoint_id)

    def print_value(self, expression):
        return debugger_print(expression)

    def get_type(self, expression):
        return debugger_get_type(expression)

    def assign(self, variable, value):
        return debugger_assign(variable, value)

    def assign_expression(self, expression):
        return debugger_assign_expression(expression)

    def add_functional_guard(self, file, line, condition, return_value):
        return debugger_add_functional_guard(file, line, condition, return_value)

    def execute(self, command):
        return debugger_execute(command)

    def backtrace(self):
        return debugger_backtrace()

    def reset_cost_stats(self):
        debugger_reset_cost_stats()

    def get_cost_stats(self):
        return debugger_get_cost_stats()


class _FuzzerDebuggerHarness:
    """Shared debugger harness facade consumed by the fuzzer path.

    This keeps session preparation, respawn policy, snapshot capture, and
    runtime degradation decisions out of the angelic reasoning loop.
    """

    def __init__(
        self,
        logger,
        cost_stats: dict[str, Any],
        policy: DebuggerHarnessPolicy,
        mark_budget_exhausted: Callable[[str], None],
    ) -> None:
        self.logger = logger
        self.cost_stats = cost_stats
        self.policy = policy
        self._mark_budget_exhausted = mark_budget_exhausted
        self._harness = DebuggerHarness(
            suspect_object={},
            backend=_EngineDebuggerBackend(),
        )
        self._harness.policy = policy
        self._harness.experiment_runner._policy = policy
        self._harness.snapshotter = self._harness.experiment_runner._snapshotter

    def refresh_policy(self) -> dict[str, Any]:
        debugger_runtime = self._harness.session.get_runtime_metrics()
        state = self.policy.observe(self.cost_stats, debugger_runtime)
        self.cost_stats["harness_policy"] = state
        return debugger_runtime

    def export_runtime(self) -> dict[str, Any]:
        return self.refresh_policy()

    def _consume_respawn_budget(self) -> bool:
        budgets = self.cost_stats.get("budgets", {})
        if budgets.get("respawn_budget") and self.cost_stats["debugger_stats"]["respawns"] >= budgets["respawn_budget"]:
            self._mark_budget_exhausted("respawn_budget")
            return False
        return True

    def respawn(self) -> bool:
        if not self._consume_respawn_budget():
            return False
        from tools.debugger.driver import debugger_respawn

        debugger_respawn()
        self.cost_stats["debugger_stats"]["respawns"] += 1
        return True

    def prepare(self, file: str, line: int, ignore_count: int) -> bool:
        self.cost_stats["debugger_stats"]["prepare_calls"] += 1
        retry_budget = self.cost_stats["budgets"]["state_prepare_retry_budget"]
        if retry_budget and self.cost_stats["debugger_stats"]["prepare_failures"] >= retry_budget:
            self._mark_budget_exhausted("state_prepare_retry_budget")
            return False
        result = self._harness.prepare(file, line, ignore_count=ignore_count if ignore_count > 0 else None)
        ok = result.reached
        if not ok:
            self.cost_stats["debugger_stats"]["prepare_failures"] += 1
        return ok

    def prepare_for_candidate(self, file: str, line: int, ignore_count: int, candidate_index: int) -> bool:
        budgets = self.cost_stats["budgets"]
        base_respawn_interval = max(1, budgets.get("force_respawn_every_n_candidates", 1))
        respawn_interval = self.policy.effective_respawn_interval(base_respawn_interval)
        if respawn_interval and candidate_index > 0 and candidate_index % respawn_interval == 0:
            if not self.respawn():
                return False

        if self.prepare(file, line, ignore_count):
            return True

        self.logger.warning("Failed to prepare state after respawn. Retrying once...")
        if not self.respawn():
            return False
        return self.prepare(file, line, ignore_count)

    def capture_snapshot(self, suspect_object: dict[str, Any]) -> dict[str, Any]:
        file = suspect_object.get("file", "")
        line = suspect_object.get("line", -1)
        expressions = list(
            dict.fromkeys(
                list(suspect_object.get("suspect_expressions", []) or [])
                + [str(v) for v in suspect_object.get("variable_names", []) if v]
            )
        )[:20]
        self.refresh_policy()
        prior_expression_evals = int(self.cost_stats["snapshot_stats"]["expression_evals"] or 0)
        variable_names = [str(v) for v in suspect_object.get("variable_names", []) if v]
        total_budget = self.cost_stats["budgets"]["snapshot_expression_budget"]
        effective_total_budget = self.policy.effective_snapshot_eval_budget(total_budget, prior_expression_evals)
        expression_budget = effective_total_budget
        if expression_budget is not None:
            expression_budget = max(0, int(expression_budget) - len(variable_names))
        snapshot = self._harness.snapshotter.capture(
            SnapshotRequest(
                variables=variable_names,
                expressions=[expr for expr in expressions if expr not in set(variable_names)],
                expression_budget=expression_budget,
                include_backtrace=True,
                backtrace_limit=5,
            ),
            policy=self.policy,
            prior_expression_evals=prior_expression_evals,
        )
        self.cost_stats["snapshot_stats"]["snapshots"] += 1
        self.cost_stats["snapshot_stats"]["expression_evals"] += int(snapshot.metrics.get("expression_evals", 0) or 0)
        skipped = int(snapshot.metrics.get("skipped_expressions", 0) or 0)
        if skipped:
            self.cost_stats["snapshot_stats"]["budget_exhaustions"] += skipped
            self._mark_budget_exhausted("snapshot_expression_budget")
        availability = {
            **{name: ("ok" if not self._is_unavailable_eval(value) else value) for name, value in snapshot.variables.items()},
            **{name: ("ok" if not self._is_unavailable_eval(value) else value) for name, value in snapshot.expressions.items()},
        }
        return {
            "location": {"file": file, "line": line},
            "variables": dict(snapshot.variables),
            "expressions": dict(snapshot.expressions),
            "memory_summaries": {},
            "backtrace": list(snapshot.backtrace),
            "availability": availability,
        }

    def run_experiment(
        self,
        suspect_object: dict[str, Any],
        candidate_index: int,
        ignore_count: int,
        apply_mutation: Callable[[Any, dict[str, Any]], bool],
        value: Any,
    ) -> dict[str, Any]:
        file = suspect_object["file"]
        line = suspect_object.get("line")
        self.refresh_policy()
        if not self.prepare_for_candidate(file, line, ignore_count, candidate_index):
            return {"status": "prepare_failed"}
        before_snapshot = self.capture_snapshot(suspect_object)
        applied_ok = apply_mutation(value, suspect_object)
        result = {"status": "applied" if applied_ok else "apply_failed", "before_snapshot": before_snapshot, "after_snapshot": {}}
        if applied_ok:
            result["after_snapshot"] = self.capture_snapshot(suspect_object)
        return result

    @staticmethod
    def _is_unavailable_eval(value: Any) -> bool:
        text = str(value).lower()
        return any(marker in text for marker in ("error:", "timeout", "not available", "unavailable", "lldb_eval"))


class InDebuggerFuzzer:
    def __init__(self, debugger, llm_agent):
        self.debugger = debugger
        self.llm = llm_agent
        self.logger = get_logger("fuzzer-engine")
        self.llm_helper = LLMHelper(llm_agent)
        self.orchestrator = MutationOrchestrator(debugger, self.logger)
        self._mutator_cache = {}
        self._submitted_constraint = None
        self._trace_pairs: list[dict] = []
        self._safe_interventions: list[dict] = []
        self._unsafe_interventions: list[dict] = []
        self._intervention_handles: list[InterventionHandle] = []
        # capture last mutation failure detail for richer feedback to the planner
        self._last_apply_error_msg: Optional[str] = None
        self._cost_stats: dict = {}
        self._harness_policy: Optional[DebuggerHarnessPolicy] = None
        self._debugger_harness: Optional[_FuzzerDebuggerHarness] = None

    def _json_safe_value(self, value):
        if isinstance(value, (str, int, float, bool)) or value is None:
            return value
        if isinstance(value, dict):
            return {str(k): self._json_safe_value(v) for k, v in value.items()}
        if isinstance(value, (list, tuple, set)):
            return [self._json_safe_value(v) for v in value]
        if hasattr(value, "_asdict"):
            try:
                return self._json_safe_value(value._asdict())
            except Exception:
                pass
        if hasattr(value, "__dict__"):
            try:
                return {
                    "__class__": value.__class__.__name__,
                    **self._json_safe_value(vars(value)),
                }
            except Exception:
                pass
        return repr(value)

    def _truncate_for_prompt(self, value, limit: int = 1200):
        text = str(value or "")
        if len(text) <= limit:
            return text
        return text[:limit] + f"\n...[truncated {len(text) - limit} chars]..."

    def _compact_mapping_for_prompt(self, mapping: dict | None, *, value_limit: int = 500, item_limit: int = 12) -> dict:
        if not isinstance(mapping, dict):
            return {}
        compact = {}
        for idx, (key, value) in enumerate(mapping.items()):
            if idx >= item_limit:
                compact["..."] = f"{len(mapping) - item_limit} more entries omitted"
                break
            if isinstance(value, (dict, list, tuple, set)):
                compact[str(key)] = self._truncate_for_prompt(self._json_safe_value(value), value_limit)
            else:
                compact[str(key)] = self._truncate_for_prompt(value, value_limit)
        return compact

    def _compact_bug_profile_for_prompt(self, profile: dict | None) -> dict:
        if not isinstance(profile, dict):
            return {}
        keys = [
            "bug_type",
            "classification_mode",
            "display_name",
            "angelic_shape",
            "spec_text",
            "repair_locations",
            "forbidden_patch_patterns",
            "validation_obligations",
        ]
        return {
            key: self._truncate_for_prompt(profile.get(key), 700)
            for key in keys
            if profile.get(key) not in (None, "", [], {})
        }

    def _compact_typed_evidence_for_prompt(self, evidence: dict | None) -> dict:
        if not isinstance(evidence, dict):
            return {}
        keys = [
            "bug_type",
            "angelic_type",
            "generalized_spec",
            "repair_locations",
            "validation_obligations",
            "demonic_trace_summary",
        ]
        return {
            key: self._truncate_for_prompt(self._json_safe_value(evidence.get(key)), 900)
            for key in keys
            if evidence.get(key) not in (None, "", [], {})
        }

    def _compact_suspect_for_prompt(self, suspect_object: dict) -> dict:
        compact = {
            "variable_names": suspect_object.get("variable_names", []),
            "focus_targets": suspect_object.get("focus_targets", suspect_object.get("variable_names", [])),
            "primary_mutation_target": suspect_object.get("primary_mutation_target"),
            "file": suspect_object.get("file"),
            "line": suspect_object.get("line"),
            "function_name": suspect_object.get("function_name"),
            "debugger_reported_type": suspect_object.get("debugger_reported_type"),
            "llm_inferred_type": suspect_object.get("llm_inferred_type"),
            "estimated_safe_range": self._truncate_for_prompt(suspect_object.get("estimated_safe_range"), 700),
            "debug_summary": self._truncate_for_prompt(suspect_object.get("debug_summary"), 1800),
            "context_variables": self._compact_mapping_for_prompt(suspect_object.get("context_variables"), value_limit=500),
            "demonic_seed_records": self._truncate_for_prompt(self._json_safe_value(demonic_seed_records(suspect_object)), 900),
            "angelic_seed_records": self._truncate_for_prompt(self._json_safe_value(angelic_seed_records(suspect_object)), 900),
            "suspect_expressions": list(suspect_object.get("suspect_expressions", []) or [])[:20],
            "preferred_edit_location": self._compact_mapping_for_prompt(suspect_object.get("preferred_edit_location"), value_limit=300),
            "candidate_edit_locations": self._truncate_for_prompt(self._json_safe_value(suspect_object.get("candidate_edit_locations", [])[:5]), 1200),
            "intervention_handles": self._truncate_for_prompt(self._json_safe_value(suspect_object.get("intervention_handles", [])[:8]), 1200),
        }
        return {key: value for key, value in compact.items() if value not in (None, "", [], {})}

    def _init_cost_stats(self, suspect_object: dict) -> None:
        self._cost_stats = {
            "budgets": {
                "candidate_budget": self._read_budget(suspect_object, "fuzz_candidate_budget", "FUZZ_CANDIDATE_BUDGET", 48),
                "snapshot_expression_budget": self._read_budget(suspect_object, "fuzz_snapshot_expression_budget", "FUZZ_SNAPSHOT_EXPRESSION_BUDGET", 120),
                "respawn_budget": self._read_budget(suspect_object, "fuzz_respawn_budget", "FUZZ_RESPAWN_BUDGET", 48),
                "state_prepare_retry_budget": self._read_budget(suspect_object, "fuzz_state_prepare_retry_budget", "FUZZ_STATE_PREPARE_RETRY_BUDGET", 8),
                "force_respawn_every_n_candidates": self._read_budget(suspect_object, "fuzz_force_respawn_every_n_candidates", "FUZZ_FORCE_RESPAWN_EVERY_N", 1),
                "candidate_wall_clock_seconds": self._read_budget(suspect_object, "fuzz_candidate_wall_clock_seconds", "FUZZ_CANDIDATE_WALL_CLOCK_SECONDS", 90),
            },
            "candidate_stats": {
                "seen": 0,
                "tested": 0,
                "duplicate_skips": 0,
                "pruned_skips": 0,
                "budget_skips": 0,
                "apply_failures": 0,
                "wall_clock_timeouts": 0,
            },
            "snapshot_stats": {
                "snapshots": 0,
                "expression_evals": 0,
                "budget_exhaustions": 0,
            },
            "debugger_stats": {
                "prepare_calls": 0,
                "prepare_failures": 0,
                "respawns": 0,
            },
            "budget_exhausted": False,
            "exhausted_budget": "",
            "pruning_reasons": {},
            "harness_policy": {},
        }

    def _init_harness_policy(self, suspect_object: dict) -> None:
        self._harness_policy = DebuggerHarnessPolicy(suspect_object)
        self._cost_stats["harness_policy"] = self._harness_policy.export_state()
        self._debugger_harness = None

    def _ensure_debugger_harness(self) -> _FuzzerDebuggerHarness:
        if self._harness_policy is None:
            self._init_harness_policy({})
        if (
            self._debugger_harness is None
            or self._debugger_harness.cost_stats is not self._cost_stats
            or self._debugger_harness.policy is not self._harness_policy
        ):
            self._debugger_harness = _FuzzerDebuggerHarness(
                logger=self.logger,
                cost_stats=self._cost_stats,
                policy=self._harness_policy,
                mark_budget_exhausted=self._mark_budget_exhausted,
            )
        return self._debugger_harness

    def _refresh_harness_policy(self) -> dict:
        return self._ensure_debugger_harness().refresh_policy()

    def _read_budget(self, suspect_object: dict, field: str, env_name: str, default: int) -> int:
        raw = suspect_object.get(field, os.environ.get(env_name, default))
        try:
            value = int(raw)
        except Exception:
            value = default
        return max(0, value)

    def _mark_budget_exhausted(self, budget_name: str) -> None:
        if self._cost_stats.get("budget_exhausted"):
            return
        self._cost_stats["budget_exhausted"] = True
        self._cost_stats["exhausted_budget"] = budget_name
        self.logger.warning("Fuzz cost budget exhausted: %s", budget_name)

    def _record_pruning_reason(self, reason: str) -> None:
        reasons = self._cost_stats.setdefault("pruning_reasons", {})
        reasons[reason] = reasons.get(reason, 0) + 1

    def run(self, suspect_object: dict, profile: dict) -> dict:
        self.logger.info(f"Starting Agent-Led JIT Fuzzing for suspect: {suspect_object}")
        self._trace_pairs = []
        self._safe_interventions = []
        self._unsafe_interventions = []
        self._intervention_handles = []
        self._init_cost_stats(suspect_object)
        self._init_harness_policy(suspect_object)
        debugger_reset_cost_stats()
        all_angelic_values: list = []
        all_demonic_values: list = []

        # 0. 获取变量类型（辅助 Agent）；debugger 失败时用 llm_inferred_type 回退
        actual_type = get_actual_variable_type(suspect_object, self.logger)
        if actual_type and actual_type != "unknown":
            suspect_object["debugger_reported_type"] = actual_type
            suspect_object["llm_inferred_type"] = actual_type
        else:
            fb = (suspect_object.get("llm_inferred_type") or "").strip()
            if fb and fb.lower() != "unknown":
                suspect_object["debugger_reported_type"] = fb
                self.logger.info(f"Fuzz using inferred type after debugger unknown: {fb}")
        self._intervention_handles = infer_intervention_handles(suspect_object)
        suspect_object["intervention_handles"] = [handle.__dict__ for handle in self._intervention_handles]

        # 1. 在同一 hypothesis 内分批扩展 primary mutation targets
        focus_batches = self._build_focus_batches(suspect_object)
        self.logger.info(
            "Prepared %d focus batch(es) for fuzzing: %s",
            len(focus_batches),
            [batch.get("focus_targets", batch.get("variable_names", [])) for batch in focus_batches],
        )
        for batch_idx, focus_suspect in enumerate(focus_batches):
            self.logger.info(
                "Delegating candidate generation to Fuzzing Agent for focus batch %d/%d: %s",
                batch_idx + 1,
                len(focus_batches),
                focus_suspect.get("focus_targets", focus_suspect.get("variable_names", [])),
            )
            angelic_values, demonic_values = self._run_synthesized_fuzzing(focus_suspect, profile)
            all_angelic_values.extend(angelic_values)
            all_demonic_values.extend(demonic_values)
            if angelic_values or self._cost_stats.get("budget_exhausted"):
                self.logger.info("Found angelic values in focus batch %d; stopping target expansion.", batch_idx + 1)
                break

        # 2. 如果 Agent 颗粒无收（可能由于脚本报错或逻辑不通），作为最后保底跑一下极简变异
        if not all_angelic_values and not all_demonic_values and not self._cost_stats.get("budget_exhausted"):
            self.logger.warning("Agent failed to provide candidates. Falling back to emergency basic fuzzing.")
            for batch_idx, focus_suspect in enumerate(focus_batches):
                base_candidates = self._generate_emergency_candidates(focus_suspect)
                base_candidates.extend(self._expand_known_assignment_candidates(focus_suspect))
                angelic_values, demonic_values = self._run_mutation_loop(base_candidates, focus_suspect, profile)
                all_angelic_values.extend(angelic_values)
                all_demonic_values.extend(demonic_values)
                if angelic_values or self._cost_stats.get("budget_exhausted"):
                    self.logger.info("Emergency fuzzing found angelic values in focus batch %d.", batch_idx + 1)
                    break

        # 3. 数据清洗、过滤与约束推导
        angelic_values, cleaned_demonic_values = self._clean_data(all_angelic_values, all_demonic_values, suspect_object)
        angelic_values = self._filter_results(angelic_values, suspect_object, profile)
        bug_type_profile = (
            suspect_object.get("bug_type_profile")
            or infer_bug_type_profile(profile=profile, suspect_object=suspect_object, debug_summary=suspect_object.get("debug_summary", ""))
        )
        minimal_deltas = self._compute_minimal_deltas(self._trace_pairs)
        typed_angelic_evidence = build_typed_angelic_evidence(
            bug_type_profile=bug_type_profile,
            suspect_object=suspect_object,
            angelic_values=angelic_values,
            demonic_values=cleaned_demonic_values,
            trace_pairs=self._trace_pairs,
            minimal_deltas=minimal_deltas,
        )
        suspect_object["typed_angelic_evidence"] = typed_angelic_evidence
        suspect_object["demonic_trace_summary"] = typed_angelic_evidence.get("demonic_trace_summary", {})
        if typed_angelic_evidence.get("evidence_family") == "operational":
            repair_text = str(
                typed_angelic_evidence.get("generalized_spec", {}).get("text")
                or bug_type_profile.get("patch_hint")
                or bug_type_profile.get("spec_text")
                or "Repair the operational mechanism confirmed by debugger intervention."
            )
            constraint = f"OPERATIONAL_REPAIR_INTENT: {repair_text}"
            self.logger.info(
                "Selective Generalization: skipping predicate constraint extraction for %s evidence.",
                typed_angelic_evidence.get("evidence_kind", "operational"),
            )
        else:
            constraint = deduce_constraint(
                suspect_object, angelic_values, cleaned_demonic_values, 
                profile, self.llm, self.debugger, self.llm_helper, self.logger, self._submitted_constraint
            )

        return {
            "hypothesis_id": suspect_object.get("hypothesis_id", ""),
            "bug_type_profile": bug_type_profile,
            "intervention_handles": [handle.__dict__ for handle in self._intervention_handles],
            "angelic_values": angelic_values,
            "demonic_values": cleaned_demonic_values,
            "typed_angelic_evidence": typed_angelic_evidence,
            "demonic_trace_summary": typed_angelic_evidence.get("demonic_trace_summary", {}),
            "deduced_constraint": constraint,
            "trace_pairs": self._trace_pairs,
            "safe_interventions": self._safe_interventions,
            "unsafe_interventions": self._unsafe_interventions,
            "minimal_deltas": minimal_deltas,
            "cost_stats": {**self._cost_stats, "debugger_runtime": debugger_get_cost_stats()},
        }

    def _generate_emergency_candidates(self, suspect_object: dict) -> list:
        """极简保底逻辑：仅在 Agent 彻底挂掉时运行。"""
        candidates = [0, 1, -1, "NULL"]
        known_assignments = angelic_assignment_sets(suspect_object)
        if isinstance(known_assignments, list):
            for assignment in known_assignments[:4]:
                if assignment:
                    candidates.append(assignment)
        return candidates

    def _stable_value_key(self, value):
        if isinstance(value, dict):
            return tuple(sorted((str(k), str(v)) for k, v in value.items()))
        if isinstance(value, list):
            return tuple(self._stable_value_key(item) for item in value)
        return str(value)

    def _unique_values(self, values: list) -> list:
        out: list = []
        seen = set()
        for value in values:
            key = self._stable_value_key(value)
            if key in seen:
                continue
            seen.add(key)
            out.append(value)
        return out

    def _display_values(self, values: list, limit: int = 12) -> list:
        return self._unique_values(values)[:limit]

    def _candidate_targets(self, suspect_object: dict) -> list[str]:
        targets: list[str] = []
        for name in suspect_object.get("variable_names", []) or []:
            text = str(name).strip()
            if text and text not in targets:
                targets.append(text)
        ctx = suspect_object.get("context_variables", {})
        if isinstance(ctx, dict):
            for name in ctx.keys():
                text = str(name).strip()
                if text and text not in targets:
                    targets.append(text)
        return targets[:8]

    def _is_assignable_target(self, expr: str) -> bool:
        text = str(expr or "").strip()
        if not text:
            return False
        return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*(?:->?[A-Za-z_][A-Za-z0-9_]*)*|\*[A-Za-z_][A-Za-z0-9_]*", text))

    def _group_target_candidates(self, suspect_object: dict) -> list[list[str]]:
        ordered = self._candidate_targets(suspect_object)
        for expr in suspect_object.get("suspect_expressions", []) or []:
            text = str(expr).strip()
            if self._is_assignable_target(text) and text not in ordered:
                ordered.append(text)
        bug_type = str((suspect_object.get("bug_type_profile") or {}).get("bug_type", "unknown")).lower()
        original_order = {target: idx for idx, target in enumerate(ordered)}
        if bug_type in {"use_after_free", "double_free", "invalid_free", "resource_leak"}:
            ordered.sort(
                key=lambda target: (
                    0 if any(token in target.lower() for token in ("owner", "ref", "free", "release", "ctx", "state")) else 1,
                    original_order.get(target, len(original_order)),
                )
            )
        elif bug_type in {"out_of_bounds", "integer_overflow"}:
            ordered.sort(
                key=lambda target: (
                    0 if any(token in target.lower() for token in ("len", "size", "count", "offset", "idx", "index", "cap", "end", "base")) else 1,
                    original_order.get(target, len(original_order)),
                )
            )
        elif bug_type in {"null_dereference", "invalid_pointer"}:
            ordered.sort(
                key=lambda target: (
                    0 if any(token in target.lower() for token in ("ptr", "buf", "cursor", "base", "end", "data")) or target.startswith("*") else 1,
                    original_order.get(target, len(original_order)),
                )
            )
        elif bug_type == "uninitialized_use":
            ordered.sort(
                key=lambda target: (
                    0 if any(token in target.lower() for token in ("state", "init", "len", "size", "type", "flag")) else 1,
                    original_order.get(target, len(original_order)),
                )
            )

        pointer_group: list[str] = []
        bounds_group: list[str] = []
        misc_group: list[str] = []
        for target in ordered:
            lower = target.lower()
            if any(token in lower for token in ("ptr", "buf", "cursor", "base", "end")) or target.startswith("*"):
                pointer_group.append(target)
            elif any(token in lower for token in ("offset", "len", "size", "count", "index", "idx", "cap")):
                bounds_group.append(target)
            else:
                misc_group.append(target)

        groups: list[list[str]] = []
        primary = [str(v).strip() for v in suspect_object.get("variable_names", []) if str(v).strip()]
        if primary:
            groups.append(primary[:4])
        for group in (bounds_group, pointer_group, misc_group):
            deduped: list[str] = []
            for target in group:
                if target not in deduped:
                    deduped.append(target)
            if deduped and deduped not in groups:
                groups.append(deduped[:4])
        return groups[:4]

    def _build_focus_batches(self, suspect_object: dict) -> list[dict]:
        batches: list[dict] = []
        groups = self._group_target_candidates(suspect_object)
        for idx, group in enumerate(groups):
            batch = dict(suspect_object)
            batch["variable_names"] = group
            batch["primary_mutation_target"] = group[0]
            batch["focus_targets"] = group
            batch["focus_batch_index"] = idx
            batches.append(batch)
        return batches or [dict(suspect_object)]

    def _expand_known_assignment_candidates(self, suspect_object: dict) -> list:
        expanded: list = []
        known_assignments = angelic_assignment_sets(suspect_object)
        bug_type = str((suspect_object.get("bug_type_profile") or {}).get("bug_type", "unknown")).lower()
        if isinstance(known_assignments, list):
            for assignment in known_assignments[:8]:
                if isinstance(assignment, dict) and assignment:
                    expanded.append(assignment)

        seed_values = {
            name: value
            for name, value in demonic_value_map(suspect_object).items()
            if not self._is_unavailable_eval(value)
        }
        for target in self._candidate_targets(suspect_object)[:4]:
            if target not in seed_values:
                continue
            expanded.extend([{target: "0"}, {target: "1"}])

        for name, value in seed_values.items():
            lowered = str(name).lower()
            numeric = re.search(r"-?\d+|0x[0-9a-fA-F]+", str(value))
            if numeric and any(token in lowered for token in ("len", "size", "count", "offset")):
                rhs = numeric.group(0)
                expanded.extend([{str(name): rhs}, {str(name): "0"}, {str(name): "1"}])

        if bug_type in {"out_of_bounds", "integer_overflow"}:
            for target in self._candidate_targets(suspect_object)[:6]:
                lowered = target.lower()
                if any(token in lowered for token in ("len", "size", "count", "offset", "idx", "index", "cap")):
                    expanded.extend([{target: "0"}, {target: "1"}, {target: "2"}])
        elif bug_type in {"null_dereference", "invalid_pointer"}:
            for target in self._candidate_targets(suspect_object)[:6]:
                lowered = target.lower()
                if any(token in lowered for token in ("ptr", "buf", "cursor", "data")) or target.startswith("*"):
                    expanded.extend([{target: "NULL"}])
        elif bug_type in {"use_after_free", "double_free", "invalid_free", "resource_leak"}:
            for target in self._candidate_targets(suspect_object)[:6]:
                lowered = target.lower()
                if any(token in lowered for token in ("owner", "state", "freed", "released", "ref", "count")):
                    expanded.extend([{target: "0"}, {target: "1"}])
        elif bug_type == "uninitialized_use":
            for target in self._candidate_targets(suspect_object)[:6]:
                lowered = target.lower()
                if any(token in lowered for token in ("init", "state", "flag", "type", "len", "size")):
                    expanded.extend([{target: "0"}])

        return self._unique_values(expanded)

    def _bug_type_tokens(self, suspect_object: dict) -> list[str]:
        bug_type = str((suspect_object.get("bug_type_profile") or {}).get("bug_type", "unknown")).lower()
        if bug_type in {"out_of_bounds", "integer_overflow"}:
            return ["len", "size", "count", "offset", "idx", "index", "cap", "bound", "limit", "end"]
        if bug_type in {"null_dereference", "invalid_pointer"}:
            return ["ptr", "buf", "cursor", "data", "base", "end", "null"]
        if bug_type in {"use_after_free", "double_free", "invalid_free", "resource_leak"}:
            return ["owner", "ref", "free", "release", "state", "ctx", "alias", "freed"]
        if bug_type == "uninitialized_use":
            return ["init", "state", "flag", "type", "mode", "status", "len", "size"]
        return []

    def _candidate_target_names(self, value) -> list[str]:
        if isinstance(value, dict):
            return [str(key).strip() for key in value.keys() if str(key).strip()]
        if isinstance(value, str):
            if value.startswith("LOGIC:AT("):
                match = re.search(r"THEN\s+([A-Za-z_][A-Za-z0-9_]*(?:->?[A-Za-z_][A-Za-z0-9_]*)*)\s*=", value)
                if match:
                    return [match.group(1).strip()]
            match = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*(?:->?[A-Za-z_][A-Za-z0-9_]*)*|\*[A-Za-z_][A-Za-z0-9_]*)\s*=", value)
            if match:
                return [match.group(1).strip()]
        return []

    def _prune_candidates_for_bug_type(self, candidates: list, suspect_object: dict) -> list:
        focus_targets = {str(target).strip() for target in suspect_object.get("focus_targets", []) or [] if str(target).strip()}
        family_tokens = self._bug_type_tokens(suspect_object)
        pruned: list = []
        for value in candidates:
            targets = self._candidate_target_names(value)
            if not targets:
                pruned.append(value)
                continue
            overlap = any(target in focus_targets for target in targets)
            token_match = any(any(token in target.lower() for token in family_tokens) for target in targets)
            if overlap or token_match:
                pruned.append(value)
                continue
            self._cost_stats["candidate_stats"]["pruned_skips"] += 1
            self._record_pruning_reason("target_mismatch")
        return pruned

    def _summarize_reason_counts(self, pairs: list[tuple[object, str]], limit: int = 5) -> list[str]:
        counts: dict[str, int] = {}
        for _, reason in pairs:
            key = str(reason).strip() or "unknown"
            counts[key] = counts.get(key, 0) + 1
        ranked = sorted(counts.items(), key=lambda item: item[1], reverse=True)
        return [f"{reason} x{count}" for reason, count in ranked[:limit]]

    def _summarize_recent_trace_deltas(self, trace_pairs: list[dict], limit: int = 3) -> list[dict]:
        summaries: list[dict] = []
        for pair in trace_pairs[:limit]:
            changed = pair.get("path_delta", {}).get("changed_expressions", {}) or {}
            compact = []
            for expr, delta in list(changed.items())[:4]:
                compact.append(
                    {
                        "expr": expr,
                        "before": str(delta.get("before"))[:80],
                        "after": str(delta.get("after"))[:80],
                    }
                )
            summaries.append(
                {
                    "outcome": pair.get("outcome", {}),
                    "intervention": pair.get("intervention", {}),
                    "changed_expressions": compact,
                }
            )
        return summaries

    def _planner_batch_summary(
        self,
        suspect_object: dict,
        candidates: list,
        report: dict,
        local_trace_pairs: list[dict],
        angelic: list,
        demonic: list,
    ) -> str:
        focus_targets = suspect_object.get("focus_targets", suspect_object.get("variable_names", []))
        parts = [
            "[System Batch Summary]:",
            f"- focus_targets: {focus_targets}",
            f"- tested_candidates: {len(candidates)}",
            f"- angelic_count: {len(angelic)}",
            f"- demonic_count: {len(demonic)}",
            f"- failed_to_apply_count: {len(report.get('failed_to_apply', []))}",
        ]
        if report.get("demonic"):
            parts.append(f"- dominant_crash_reasons: {self._summarize_reason_counts(report['demonic'])}")
        if report.get("failed_to_apply"):
            parts.append(f"- dominant_apply_failures: {self._summarize_reason_counts(report['failed_to_apply'])}")
        if local_trace_pairs:
            parts.append(f"- recent_state_deltas: {self._summarize_recent_trace_deltas(local_trace_pairs)}")
        if not angelic:
            parts.append(
                "- next_action_hint: keep the same focus batch, but switch strategy class "
                "(numeric boundary -> multi-variable assignment -> relocated action -> logic guard)."
            )
        return "\n".join(parts)

    def _typed_fuzzing_playbook(self, suspect_object: dict) -> str:
        profile = suspect_object.get("bug_type_profile") or {}
        bug_type = str(profile.get("bug_type", "unknown")).lower()
        typed_evidence = suspect_object.get("typed_angelic_evidence") or {}
        repair_locations = profile.get("repair_locations") or typed_evidence.get("repair_locations") or []
        generalized_spec = typed_evidence.get("generalized_spec", {})
        spec_text = generalized_spec.get("text") or profile.get("spec_text") or ""

        common = [
            "Prefer interventions that repair the mechanism, not just the observed sink.",
            "When a scalar tweak fails repeatedly, switch to relocated `at(file,line,action)` or `logic_*` actions at an earlier state-construction site.",
            "Use multi-variable assignments only when they encode one coherent invariant, not a bag of unrelated guesses.",
        ]
        by_type = {
            "out_of_bounds": [
                "Bias toward index/offset/len/count relations, earlier normalization, or relocated assignments at size-parsing sites.",
                "Prefer candidate families that make `offset + size <= bound` true, instead of only clamping the final access.",
                "If simple numeric guesses fail, emit `logic_assign(...)` or `at(...)` near loop-bound or API-boundary code.",
            ],
            "integer_overflow": [
                "Prefer arithmetic precondition repairs: count-size coupling, allocation-size normalization, or overflow-avoidance relations.",
                "Generate candidates around safe multiplicative/additive boundaries, not only the observed crashing count.",
                "If raw numeric changes fail, relocate to the arithmetic producer and repair the size computation there.",
            ],
            "null_dereference": [
                "Treat this as pointer-contract evidence: try caller-side null rejection, earlier initialization, or state restoration before dereference.",
                "Prefer `logic_return(...)` or relocated state repair at the API boundary over crash-site-only null checks.",
            ],
            "invalid_pointer": [
                "Focus on pointer provenance and offset repair, not concrete addresses.",
                "Prefer relocated fixes at pointer source / arithmetic sites, or pointer-state guards that encode the actual contract.",
            ],
            "use_after_free": [
                "Prioritize temporal interventions: delay or skip a free, null a stale alias after release, or repair ownership/state flags before use.",
                "Use `at(...)` near free/cleanup/ownership-transfer sites when the use-site variable itself cannot encode lifetime.",
                "Prefer event-order or alias-invalidation hypotheses over raw scalar guesses.",
            ],
            "double_free": [
                "Prefer cleanup-state or ownership-transfer interventions: make release happen once, or consume ownership after the first free.",
                "Target free-site predecessor logic or cleanup flags before trying sink-local branch skips.",
            ],
            "invalid_free": [
                "Prefer deallocation-target or ownership-origin repairs over turning off `free` blindly.",
                "Relocate interventions to pointer-source or ownership-boundary code when the freeing site is only the symptom.",
            ],
            "resource_leak": [
                "Bias toward cleanup-path completion, ownership transfer, and destructor/release helper repairs.",
                "Prefer event-order or cleanup-flag interventions over generic return-path suppression.",
            ],
            "uninitialized_use": [
                "Prioritize initialization-state interventions: zeroing, default field setup, state refresh, or earlier constructor/init coverage.",
                "Use `at(...)` near init/refresh sites when the crash-site variable is only a downstream consumer.",
                "Avoid overfitting to one scalar value if the real effect is expanded initialization coverage.",
            ],
            "assertion_failure": [
                "Prefer earlier state-machine or contract-restoring interventions over direct branch suppression of the assertion.",
                "Look for one missing transition, flag update, or validation step that makes the assertion hold.",
            ],
            "divide_by_zero": [
                "Prefer denominator-production or caller-contract interventions rather than replacing the zero with an arbitrary constant.",
                "Use guards only when they encode the real arithmetic precondition.",
            ],
            "stack_overflow": [
                "Bias toward termination/base-case and progress-related interventions, not arbitrary depth literals.",
                "Prefer relocated repairs at recursion entry or loop-progress logic.",
            ],
            "heap_corruption_later_crash": [
                "Treat the current sink as late symptom evidence; search for earlier write-size, offset, or lifetime interventions.",
                "Prefer `at(...)` relocation to first writable predecessor states over allocator-site guards.",
            ],
            "data_race": [
                "Prefer ordering/state ownership interventions that approximate happens-before relations.",
                "Target synchronization flags, ownership transfer, or producer/consumer state updates instead of sink-local skips.",
            ],
        }
        sections = common + by_type.get(bug_type, [])
        if repair_locations:
            sections.append(f"Preferred repair locations to probe: {repair_locations}.")
        if spec_text:
            sections.append(f"Target generalized safety spec: {spec_text}")
        return "\n".join(f"- {line}" for line in sections if line)

    def _generate_candidates(self, suspect_object: dict) -> list:
        var_type = (suspect_object.get("debugger_reported_type") or 
                    suspect_object.get("llm_inferred_type") or "unknown")
        
        mutator = get_mutator(var_type, self._mutator_cache, self.logger)
        if not mutator:
            return []

        return sorted(list(mutator.generate_candidates(suspect_object)))

    def _clean_data(self, angelic_values, demonic_values, suspect_object):
        cleaned_demonic = []
        for value in demonic_values:
            if isinstance(value, dict):
                cleaned_demonic.append(value)
                continue
            parsed = parse_address(value)
            cleaned_demonic.append(parsed if parsed else value)

        angelic_values = self._unique_values(angelic_values)
        cleaned_demonic = self._unique_values(cleaned_demonic)

        demonic_keys = {self._stable_value_key(value) for value in cleaned_demonic}
        angelic_values = [
            value for value in angelic_values
            if self._stable_value_key(value) not in demonic_keys
        ]
        return angelic_values, cleaned_demonic

    def _filter_results(self, angelic_values, suspect_object, profile):
        structured_values = [value for value in angelic_values if isinstance(value, dict)]
        scalar_values = [value for value in angelic_values if not isinstance(value, dict)]

        # Rule-based outlier filtering
        scalar_values = filter_angelic_outliers(scalar_values, suspect_object, self.logger)
        
        # Distance-based filtering for pointers
        demonic_seed_str = str(next(iter(demonic_value_map(suspect_object).values()), None))
        base_addr_str = parse_address(demonic_seed_str)
        if base_addr_str:
            base_addr = int(base_addr_str, 16)
            scalar_values = [v for v in scalar_values if self._is_within_distance(v, base_addr)]

        # Agent-based filtering
        if len(scalar_values) > 5:
            scalar_values = filter_angelic_values_with_agent(scalar_values, suspect_object, profile, self.logger)
        return self._unique_values(structured_values + scalar_values)

    def _is_within_distance(self, val, base_addr, max_dist=4096):
        """Checks if a value is a pointer close to the base address."""
        val_str = parse_address(str(val))
        if not val_str:
            return True # Not a pointer, keep it
        try:
            val_addr = int(val_str, 16)
            return abs(val_addr - base_addr) < max_dist
        except ValueError:
            return True

    def _normalize_at_action(self, action: str) -> tuple[str | None, str | None]:
        """
        LLDB `expr` in MI mode is picky:
        - It does not accept `return ...;` (the wrapper function is `void $__lldb_expr`).
        - It often fails on compound statement blocks `{ ... }`.
        - Calls like memcpy/memset/memmove may require explicit `(void)` cast to silence return-type issues.
        """
        if action is None:
            return None, "Empty action"
        s = str(action).strip()
        if not s:
            return None, "Empty action"

        # Reject block statements (common hallucination when trying to create a safe buffer)
        if s.startswith("{") or "{" in s or "}" in s:
            return (
                None,
                f"{FUZZ_AT_ACTION_ERROR_TEMPLATE}\nReason: action contains '{{' or '}}'.",
            )

        # Convert `if (cond) return X;` into LOGIC:IF(cond) THEN RETURN(X)
        if re.search(r"\breturn\b", s):
            m = re.match(r"^\s*if\s*\((.*)\)\s*return\s*(.*?);\s*$", s, flags=re.DOTALL)
            if m:
                cond = m.group(1).strip()
                ret = m.group(2).strip()
                if cond and ret:
                    return f"LOGIC:IF({cond}) THEN RETURN({ret})", None
            return (
                None,
                f"{FUZZ_AT_ACTION_ERROR_TEMPLATE}\nReason: action contains raw `return`.",
            )

        # For common libc memory ops, prefer `(void)` cast when used as a statement.
        # Example: "memcpy(dst,src,n);" -> "(void)memcpy(dst,src,n);"
        if re.match(r"^\s*(memcpy|memmove|memset)\s*\(", s) and not re.match(r"^\s*\(\s*void\s*\)\s*(memcpy|memmove|memset)\s*\(", s):
            s = re.sub(r"^\s*(memcpy|memmove|memset)\s*\(", r"(void)\1(", s, count=1)

        return s, None

    def _should_try_synthesis(self, suspect_object: dict) -> bool:
        """Determines if the type or context warrants a synthesized mutator."""
        var_type = (suspect_object.get("debugger_reported_type") or 
                    suspect_object.get("llm_inferred_type") or "unknown").lower()
        var_names = str(suspect_object.get("variable_names", [])).lower()
        
        # 更加激进的判定：
        # 1. 类型中包含指针、数组、字符特征
        # 2. 或者变量名中包含 buffer, ptr, path, old 等提示性词汇
        # 3. 或者类型干脆就是 unknown (因为 unknown 往往意味着复杂的结构体或宏)
        is_complex = '*' in var_type or 'char' in var_type or 'unknown' in var_type
        is_pointer_name = any(k in var_names for k in ['ptr', 'buf', 'old', 'path', 'data'])
        
        return is_complex or is_pointer_name

    def _run_synthesized_fuzzing(self, suspect_object: dict, profile: dict) -> tuple[list, list]:
        """
        Tool-driven, stateful workflow:
        - A planner Agent decides when to call TOOL:JIT_SYNTHESIZE(...)
        - The planner MUST provide the JIT mutator script (as a ```python block) in the same message.
        - The system executes the script to get candidates, runs fuzzing, and returns results as feedback.
        """
        # Let the planner decide when to stop via "DONE SUBMIT".
        # Keep a generous hard cap to avoid infinite loops.
        max_turns = int(profile.get("fuzz_planner_max_turns", 30)) if isinstance(profile, dict) else 30
        all_angelic: list = []
        all_demonic: list = []

        # A stateful planner agent (keeps history)
        planner_name = "FuzzPlanner"
        planner = GenericAgent(
            name=planner_name,
            system_prompt=self._build_planner_system_prompt(),
        )

        variable_states = self._prefill_variable_states(suspect_object)
        initial = self._build_planner_initial_prompt(suspect_object, variable_states)

        self.logger.info("Starting tool-driven JIT planning conversation...")
        chat_log = planner.initiate(initial, logger=self.logger, max_turns=1)
        initial_error = str(chat_log.get("error", "") or "").strip()
        if initial_error:
            self.logger.error("Planner chat failed before first turn: %s", initial_error)
            return all_angelic, all_demonic

        last_assistant = self._extract_named_message(chat_log.get("history"), planner_name)
        if not last_assistant:
            self.logger.error("Planner produced no assistant message on first turn. Stopping JIT planning.")
            return all_angelic, all_demonic

        feedback = ""

        for turn in range(max_turns):
            self.logger.info(f"[PLANNER TURN {turn+1}/{max_turns}]")

            if turn > 0:
                # IMPORTANT: feedback is written into the planner conversation via `step(...)`.
                # We also log it here (truncated) so it is visible in fuzzer-engine.log.
                if feedback:
                    preview = feedback if len(feedback) <= 2000 else (feedback[:2000] + "\n...[truncated]...")
                    self.logger.info(f"[System->Planner Feedback]:\n{preview}")
                chat_log = planner.step(chat_log, feedback, logger=self.logger, max_turns=1)
                step_error = str(chat_log.get("error", "") or "").strip()
                if step_error:
                    self.logger.error("Planner chat failed during turn %d: %s", turn + 1, step_error)
                    break
                last_assistant = self._extract_named_message(chat_log.get("history"), planner_name)
                if not last_assistant:
                    self.logger.error("Planner produced no assistant message during turn %d. Stopping JIT planning.", turn + 1)
                    break

            self.logger.info(f"[Planner]: {last_assistant}")

            # Planner-controlled termination
            # - "DONE SUBMIT": stop and return current results (even if tool was also called)
            if re.search(r"\bDONE\s+SUBMIT\b", last_assistant, re.IGNORECASE):
                self.logger.info("[Planner]: DONE SUBMIT received. Stopping planner loop.")
                break

            tool_calls = self._parse_tool_calls_loose(last_assistant)
            if not tool_calls:
                if "DONE" in last_assistant:
                    break
                feedback = "[System]: Please call TOOL:JIT_SYNTHESIZE(<optional notes>) and include a COMPLETE python code block in the SAME message, exactly in the form:\n```python\n<your JIT mutator script>\n```\nOr say DONE."
                continue

            # Extract python code blocks from the SAME message (Scheme B)
            code_blocks = re.findall(r"```python\n(.*?)\n```", last_assistant, re.DOTALL)
            script_code = code_blocks[0] if code_blocks else None

            # Execute tools in order, accumulate feedback
            feedback_parts: list[str] = []
            # Always remind planner of known good/bad anchors from crash analysis
            known_records = angelic_seed_records(suspect_object)
            known_assignments = angelic_assignment_sets(suspect_object)
            v0 = (suspect_object.get("variable_names") or [None])[0]
            known_angelic = [
                record["value"]
                for record in known_records
                if v0 is None or record["variable"] == v0
            ]
            demonic_seed = demonic_seed_records(suspect_object)

            # Render multi-var known angelic assignments as ready-to-use LLDB assignment expressions
            assignment_seeds = []
            try:
                if isinstance(known_assignments, list):
                    for one in known_assignments[:5]:
                        if isinstance(one, dict) and one:
                            parts = [f"{k}={v}" for k, v in one.items()]
                            assignment_seeds.append("; ".join(parts))
            except Exception:
                assignment_seeds = []

            feedback_parts.append(
                "[System Context Reminder]:\n"
                f"- angelic_seed_records: {known_records}\n"
                f"- projected_angelic_values: {known_angelic}\n"
                f"- projected_angelic_assignments: {known_assignments}\n"
                f"- known_angelic_seed_expressions: {assignment_seeds}\n"
                f"- demonic_seed_records: {demonic_seed}\n"
                f"- angelic_found_so_far: {self._display_values(all_angelic)}\n"
            )
            for tool_name, tool_args in tool_calls:
                if tool_name != "JIT_SYNTHESIZE":
                    feedback_parts.append(f"[System Tool Error]: Unknown tool '{tool_name}'. Supported: TOOL:JIT_SYNTHESIZE(...)")
                    continue

                if not script_code:
                    feedback_parts.append(
                        "[System Tool Result]: TOOL:JIT_SYNTHESIZE was called but no ```python``` code block was found in your message.\n"
                        "Please include the full `class AgentMutator(SynthesizedMutator)` script inside a ```python block in the SAME message."
                    )
                    continue

                feedback_parts.append("[System Tool Result]: Received JIT script. Executing...")

                candidates, exec_error = self.orchestrator.run_agent_script(suspect_object, script_code)
                if exec_error:
                    feedback_parts.append(f"[System Script Error]:\n{exec_error}")
                    continue
                if not candidates:
                    feedback_parts.append("[System Script Result]: Script executed but returned 0 candidates.")
                    continue

                self.logger.info(f"Testing {len(candidates)} candidates from JIT script...")
                report: dict = {"failed_to_apply": [], "demonic": [], "angelic": []}
                trace_pair_start = len(self._trace_pairs)
                angelic, demonic = self._run_mutation_loop(list(candidates), suspect_object, profile, report=report)
                local_trace_pairs = self._trace_pairs[trace_pair_start:]
                all_angelic.extend(angelic)
                all_demonic.extend(demonic)

                if angelic:
                    feedback_parts.append(f"[System Fuzz Result]: SUCCESS. Found {len(angelic)} angelic values: {angelic}")
                else:
                    sample = list(demonic)[:10]
                    feedback_parts.append(
                        "[System Fuzz Result]: No angelic values.\n"
                        f"- Tested {len(candidates)} candidates\n"
                        f"- Examples failing: {sample}"
                    )
                # Always show updated cumulative angelics after this run
                feedback_parts.append(
                    "[System Angelic Summary]:\n"
                    f"- angelic_found_so_far (unique): {self._display_values(all_angelic)}\n"
                    f"- newly_found_in_this_run: {angelic}\n"
                    "If these angelic values match your plan, reply with 'DONE SUBMIT'."
                )
                feedback_parts.append(
                    self._planner_batch_summary(
                        suspect_object=suspect_object,
                        candidates=list(candidates),
                        report=report,
                        local_trace_pairs=local_trace_pairs,
                        angelic=angelic,
                        demonic=demonic,
                    )
                )
                # Always attach a concise failure report so the planner can adapt strategy.
                # Only include a bounded number of items to keep prompt size under control.
                if report["failed_to_apply"]:
                    preview = report["failed_to_apply"][:10]
                    feedback_parts.append(
                        "[System Failure Details]: Failed-to-apply examples (candidate -> error):\n"
                        + "\n".join([f"- {c} -> {e}" for c, e in preview])
                    )
                if report["demonic"]:
                    preview = report["demonic"][:10]
                    feedback_parts.append(
                        "[System Failure Details]: Crash examples (candidate -> reason):\n"
                        + "\n".join([f"- {c} -> {r}" for c, r in preview])
                    )

            feedback = "\n\n".join(feedback_parts)

        return self._unique_values(all_angelic), self._unique_values(all_demonic)

    def _extract_named_message(self, history, name: str) -> str:
        """
        Autogen chat_history role/name fields are not always aligned with our expectation.
        We treat the planner output as the latest message whose `name` equals planner_name.
        """
        if not isinstance(history, list) or not history:
            return ""
        for msg in reversed(history):
            if msg.get("name") == name:
                content = msg.get("content", "") or ""
                if content.strip():
                    return content.strip()
        return ""

    def _prefill_variable_states(self, suspect_object: dict) -> dict:
        """Best-effort to run to the suspect line and capture runtime values for prompt context."""
        variable_states: dict = {}
        try:
            file = suspect_object.get("file")
            line = suspect_object.get("line")
            if file and line:
                self._prepare_debugger_state(file, line, 0)
            targets = list(dict.fromkeys(
                list(suspect_object.get("variable_names", []) or [])
                + list(suspect_object.get("focus_targets", []) or [])
            ))[:8]
            for var in targets:
                val = debugger_print(var)
                variable_states[var] = val
                if "0x" in val and "error" not in val.lower():
                    deref = debugger_print(f"*{var}")
                    if "error" not in deref.lower():
                        variable_states[f"*{var}"] = deref
        except Exception as e:
            self.logger.warning(f"Prefill variable states failed: {e}")
        return variable_states

    def _build_planner_system_prompt(self) -> str:
        return (
            "You are a Fuzzing Planner Agent.\n"
            "You will decide when to run a JIT fuzzing experiment and you MUST provide the JIT mutator script when you do.\n\n"
            "### Tool: JIT Script Synthesis\n"
            "- Call `TOOL:JIT_SYNTHESIZE(<optional notes>)` AND include a COMPLETE fenced Python code block in the SAME message: ```python ... ```.\n"
            "- The python code MUST define `class AgentMutator(SynthesizedMutator):` and implement `compose(self)` returning a list of candidates.\n"
            "- IMPORTANT: `at(file, line, action)` takes a STRING action, not a lambda. Example: `self.at(\"/src/ndpi/src/lib/ndpi_main.c\", 8189, \"pe_offset=60\")`.\n"
            f"{FUZZ_AT_ACTION_RULES_PROMPT}"
            "- Do NOT use imaginary helpers like `ctx.set(...)`, `self.randint(...)`, `ctx.write_memory(...)` unless explicitly provided.\n"
            "- The system will execute your script and reply with either:\n"
            "  - script execution errors\n"
            "  - fuzzing results (angelic/demonic)\n\n"
            "### How to use feedback\n"
            "- Script error => adjust requirements / fix approach, then call TOOL again.\n"
            "- Fuzz all failed => change strategy (guards, relocate with `at()`, conditional assigns via `logic_assign(...)`, etc.), then call TOOL again.\n"
            "- Use the batch summary. If `recent_state_deltas` changed values but still crashed, keep the same focus targets and switch strategy class instead of repeating similar numeric guesses.\n"
            "- If `dominant_apply_failures` are high, emit simpler assignment expressions or relocate with `at(...)` before mutating.\n"
            "- Prefer candidates that explain a state delta, such as changing `offset + size > len` into `offset + size <= len`.\n"
            "- Multi-variable or relocated interventions are allowed when a single variable cannot explain the crash.\n"
            "- If you believe the current angelic values are sufficient, reply with: `DONE SUBMIT`.\n"
        )

    def _build_planner_initial_prompt(self, suspect_object: dict, variable_states: dict) -> str:
        compact_suspect = self._compact_suspect_for_prompt(suspect_object)
        bug_type_profile = self._compact_bug_profile_for_prompt(suspect_object.get("bug_type_profile") or {})
        typed_evidence = self._compact_typed_evidence_for_prompt(suspect_object.get("typed_angelic_evidence") or {})
        typed_playbook = self._typed_fuzzing_playbook(suspect_object)
        compact_variable_states = self._compact_mapping_for_prompt(variable_states, value_limit=500)
        return (
            "### Crash Context (Initial)\n"
            f"{compact_suspect}\n\n"
            "### Typed Bug Profile\n"
            f"{bug_type_profile}\n\n"
            "### Typed Angelic Evidence Goal\n"
            f"{typed_evidence}\n\n"
            "### Typed Intervention Playbook\n"
            f"{typed_playbook}\n\n"
            "### Runtime Variable States (Best-effort)\n"
            f"{compact_variable_states}\n\n"
            f"### Focus Mutation Targets\n{suspect_object.get('focus_targets', suspect_object.get('variable_names', []))}\n\n"
            "If variables are not visible at the current line, plan to use `at(file,line,action)` in the next script.\n"
            "Start by calling TOOL:JIT_SYNTHESIZE with a short plan AND include your full JIT script in a COMPLETE fenced block: ```python\\n...\\n```.\n"
        )

    def _parse_tool_calls_loose(self, text: str) -> list[tuple[str, str]]:
        """Parses TOOL:NAME(args) and loose TOOL: NAME\\nargs formats."""
        if not text:
            return []

        # Strict form: TOOL:NAME(args)
        strict = re.findall(r"TOOL:\s*([A-Z_]+)\((.*?)\)", text, re.DOTALL)
        if strict:
            return [(n.strip(), a.strip()) for n, a in strict]

        # Loose multi-line form:
        # TOOL: NAME
        # arg1,arg2 or free-form args
        parts = re.split(r"TOOL:\s*", text)
        calls: list[tuple[str, str]] = []
        for part in parts[1:]:
            part = part.strip()
            if not part:
                continue
            lines = part.split("\n", 1)
            name = lines[0].strip().replace(":", "").replace(" ", "_")
            if not re.match(r"^[A-Z_]+$", name):
                continue
            args = lines[1].strip() if len(lines) > 1 else ""
            calls.append((name, args))
        return calls

    def _ask_agent_for_script(self, suspect_object: dict, feedback: str = None, feedback_type: str = None, last_script: str = None, variable_states: dict = None) -> Optional[str]:
        """Queries the LLM to generate a Python mutation script using building blocks."""
        prompt = self._build_synthesis_prompt(suspect_object, feedback, feedback_type, last_script, variable_states)
        
        # 强制切换到专门的 Fuzzing 任务上下文
        self.logger.info("Sending JIT Synthesis prompt to Agent...")
        response = self.llm.query(prompt)
        
        # 更加鲁棒的代码提取
        code_blocks = re.findall(r'```python\n(.*?)\n```', response, re.DOTALL)
        if code_blocks:
            return code_blocks[0]
        
        # 如果没带 markdown 块，尝试直接正则匹配代码特征（备选）
        if "class AgentMutator" in response:
            return response
            
        return None

    def _build_synthesis_prompt(self, suspect_object: dict, feedback: str = None, feedback_type: str = None, last_script: str = None, variable_states: dict = None) -> str:
        var_name = suspect_object["variable_names"][0]
        var_type = suspect_object.get("llm_inferred_type") or "unknown"
        focus_targets = suspect_object.get("focus_targets", suspect_object.get("variable_names", []))
        debug_mem = self._truncate_for_prompt(suspect_object.get("debug_summary", "No summary provided."), 1800)
        bug_type_profile = self._compact_bug_profile_for_prompt(suspect_object.get("bug_type_profile") or {})
        typed_evidence = self._compact_typed_evidence_for_prompt(suspect_object.get("typed_angelic_evidence") or {})
        typed_playbook = self._typed_fuzzing_playbook(suspect_object)
        compact_suspect = self._compact_suspect_for_prompt(suspect_object)
        
        # 获取源码上下文，帮助 Agent 决定 guard 的位置
        file_path = suspect_object.get("file")
        line_num = suspect_object.get("line")
        source_context = ""
        if file_path and line_num:
             try:
                # 读取前后 20 行
                start_line = max(1, line_num - 20)
                end_line = line_num + 5
                content = file_get_decorated_content(file_path, start_line, end_line)
                source_context = f"### Source Code Context ({file_path}:{line_num}):\n```c\n{content}\n```\n"
             except Exception as e:
                self.logger.warning(f"Failed to read source context: {e}")

        prompt = (
            "You are an Advanced Fuzzing Strategist. Your goal is to write a Python script that generates "
            f"mutation candidates for `{var_name}` (type: `{var_type}`) to prevent a program crash.\n\n"
            f"Primary mutation target for this batch: {var_name}\n"
            f"Other focus targets you may co-mutate: {focus_targets}\n\n"
            "### Typed Bug Profile\n"
            f"{bug_type_profile}\n\n"
            "### Target Typed Angelic Evidence\n"
            f"{typed_evidence}\n\n"
            "### Typed Intervention Playbook\n"
            f"{typed_playbook}\n\n"
            "### Debugging Memory (Insights from Debug Agent):\n"
            f"> {debug_mem}\n\n"
            f"{source_context}\n"
            "### Candidate Budget & Priority (IMPORTANT):\n"
            "- **Total candidates**: aim for **30–50** (default ~40). Do NOT exceed 50.\n"
            "- **Phase 1 (preferred)**: generate **numeric candidates first** (e.g., 20–35 values) to find the safety boundary.\n"
            "- **Phase 2 (fallback)**: generate a **small** set of logic candidates (e.g., 5–10 values) such as `add_guard`, `logic_assign`, `logic_return`, or `at(...)`.\n"
            "- Avoid huge loops (no large ranges). Downsample intentionally.\n\n"
            "### Decision Matrix: When to use which building block?\n"
            "1. **Scenario: Invalid Pointer/Memory Corruption**\n"
            "   - *Signs*: SEGFAULT at a pointer dereference, `AddressSanitizer: heap-buffer-overflow`.\n"
            "   - *Tool*: **Preferred**: Use `add_guard` or `logic_return` to avoid the access.\n"
            "   - *Alternative*: If you must modify data, use `write_buf(addr, data)` ONLY on existing valid buffers. **Do NOT allocate new memory.**\n"
            "2. **Scenario: Magic Number/Header Validation**\n"
            "   - *Signs*: Program checks for specific bytes (e.g., `if (buf[0] != 0x1f)`) and then crashes.\n"
            "   - *Tool*: Use `write_buf` to inject valid headers into the *existing* buffer (if safe).\n"
            "3. **Scenario: Integer Overflow or Size Check**\n"
            "   - *Signs*: A variable like `len` or `count` is very large or negative.\n"
            "   - *Tool*: Use `integer.int_boundaries(bits, signed)` for edge cases, or `logic_assign(cond, var, val)` to clamp values (e.g., `if (len > 1024) len = 1024`).\n"
            "4. **Scenario: Logic Flow Redirection (The 'Escape' Key)**\n"
            "   - *Signs*: Variable mutations aren't enough, or the crash is deep inside an unfixable library call.\n"
            "   - *Tool*: Use `logic_return(condition, return_value)` to bypass the entire code path by forcing an early return from the current function.\n"
            "5. **Scenario: Persistent Hot-fix / Guarding Checks**\n"
            "   - *Signs*: A specific line always causes trouble (e.g., an assertion or an unchecked array access), and you want to \"permanently\" bypass it for the rest of the fuzzing session.\n"
            "   - *Tool*: Use `add_guard(file, line, condition, return_value)`. This sets a conditional breakpoint that automatically returns, effectively \"patching\" the binary in memory.\n\n"
            "### Typed Strategy Rule (Important):\n"
            "- Let the typed bug profile decide the first intervention family. For lifetime/ownership bugs, start with order/cleanup/alias interventions. For initialization bugs, start with state refresh/zeroing/default setup. For bounds bugs, start with relation-preserving size/index changes or relocated normalization.\n"
            "- If a candidate only masks the sink but does not explain the typed generalized safety spec, switch to an earlier relocated intervention site.\n\n"
            "### CRITICAL IMPLEMENTATION DETAILS:\n"
            "1. **DO NOT** wrap function calls in strings. \n"
            "   - WRONG: `candidates.append(\"add_guard(...)\")`\n"
            "   - WRONG: `candidates.append(f\"add_guard(...)\")`\n"
            "   - CORRECT: `candidates.append(add_guard(..., ..., ..., ...))` -> The function returns the correct special string.\n"
            "2. **NO MALLOC ALLOWED**: Do not use `alloc_buf`. Modifying heap state in a crashing program is unsafe. Use `add_guard` to skip bad code instead.\n"
            "3. **CONST / READ-ONLY VARIABLES**: If the target variable is `const` or read-only (common in optimized builds), you MUST use `const_cast` in your assignment string.\n"
            "   - Example (pointer): `candidates.append(f\"*const_cast<{var_type}*>({var_name}) = {val}\")`\n"
            "   - Example (reference): `candidates.append(f\"const_cast<{var_type}&>({var_name}) = {val}\")`\n"
            "   - If simple assignment fails, the engine may attempt a fallback, but explicit `const_cast` is more reliable.\n\n"
            "### Multi-Mutation Technique:\n"
            "- You can combine multiple actions in one candidate string: `\"*n=10\"`.\n\n"
            "### Available Building Blocks & Signatures:\n"
            "- `integer.int_boundaries(bits: int, signed: bool) -> list[int]`\n"
            "  - Returns a list of boundary values (e.g., MIN, MAX, 0, -1).\n"
            "- `integer.int_bitflip(val: int, bits: int) -> list[int]`\n"
            "  - Returns a list of values with single bits flipped. **Iterate over the result.**\n"
            "- `write_buf(addr: int, data: bytes) -> None`\n"
            "  - Writes bytes to the given address. Returns None. **Use only on known valid addresses.**\n"
            "- `get_addr(symbol: str) -> int`\n"
            "  - Returns the address of a symbol as an integer.\n"
            "- `logic_return(condition: str, ret_val: str) -> str`\n"
            "  - Returns a special command string. **Do not wrap in quotes.**\n"
            "- `add_guard(file: str, line: int, cond: str, ret_val: str) -> str`\n"
            "  - Returns a special command string for persistent patching. **Do not wrap in quotes.**\n"
            "- `logic_assign(condition: str, var: str, val: str) -> str`\n"
            "  - Returns a special command string for conditional assignment.\n\n"
            "- `at(file: str, line: int, action: str) -> str`\n"
            "  - Returns a special command string to relocate execution to `file:line`, then execute `action` there.\n"
            "  - `action` can be a raw assignment (e.g. `\"pe_offset=60\"`) or another `LOGIC:...` directive.\n"
            "  - Example: `candidates.append(at(\"/src/ndpi/src/lib/ndpi_main.c\", 8175, \"pe_offset=60\"))`\n\n"
            "### Implementation Requirements:\n"
            "1. Define `class AgentMutator(SynthesizedMutator):`.\n"
            "2. Implement `compose(self)` method.\n"
            "3. Return a list of candidate strings.\n\n"
            "### Context:\n"
            f"Crash Info: {compact_suspect}\n"
        )
        
        if feedback:
            if feedback_type == "error":
                prompt += f"\n### ERROR IN YOUR PREVIOUS SCRIPT:\n{feedback}\n"
                prompt += "Please FIX the Python code. Ensure the syntax is correct and you follow the implementation requirements exactly."
            elif feedback_type == "result":
                prompt += f"\n### FEEDBACK FROM PREVIOUS FUZZING ATTEMPT:\n{feedback}\n"
                prompt += "Based on these failing results, refine your strategy. Do not repeat the same failing candidates. Try more aggressive mutations or logic returns."
            else:
                prompt += f"\n### Feedback from Previous Attempt:\n{feedback}\n"
                prompt += "Based on this feedback, refine your strategy."
            
        prompt += "\nReturn only the Python code in a ```python block."
        return prompt

    def _run_mutation_loop(self, candidates: list, suspect_object: dict, profile: dict, report: Optional[dict] = None) -> tuple[list, list]:
        angelic_values = []
        demonic_values = [
            value
            for value in record_values(demonic_seed_records(suspect_object))
            if not self._is_unavailable_eval(value)
        ]
        file, line = suspect_object["file"], suspect_object.get("line")
        
        if not line or (isinstance(line, int) and line <= 0):
            return [], []

        candidates = self._prune_candidates_for_bug_type(candidates, suspect_object)
        debugger_clear_breakpoints()
        ignore_count = self._determine_ignore_count(file, line)
        processed_values = set()
        budgets = self._cost_stats["budgets"]
        harness = self._ensure_debugger_harness()

        for idx, value in enumerate(candidates):
            self._refresh_harness_policy()
            self._cost_stats["candidate_stats"]["seen"] += 1
            if self._is_unavailable_eval(value):
                self._cost_stats["candidate_stats"]["pruned_skips"] += 1
                self._record_pruning_reason("unavailable_debugger_value")
                if report is not None:
                    report.setdefault("failed_to_apply", []).append(
                        (value, "skipped unavailable debugger value")
                    )
                continue
            value_key = self._stable_value_key(value)
            if value_key in processed_values:
                self._cost_stats["candidate_stats"]["duplicate_skips"] += 1
                continue
            if budgets["candidate_budget"] and self._cost_stats["candidate_stats"]["tested"] >= budgets["candidate_budget"]:
                self._cost_stats["candidate_stats"]["budget_skips"] += 1
                self._mark_budget_exhausted("candidate_budget")
                break
            
            self.logger.info(f"[TEST {idx+1}/{len(candidates)}] Value: {value}")
            self._last_apply_error_msg = None
            candidate_started_at = time.monotonic()

            experiment = harness.run_experiment(
                suspect_object=suspect_object,
                candidate_index=idx,
                ignore_count=ignore_count,
                apply_mutation=self._apply_mutation,
                value=value,
            )
            if experiment.get("status") == "prepare_failed":
                if self._cost_stats.get("budget_exhausted"):
                    break
                self.logger.error(f"Failed to prepare debugger state for value: {value} (even after harness retry)")
                continue

            self._cost_stats["candidate_stats"]["tested"] += 1
            applied_ok = experiment.get("status") == "applied"
            if applied_ok:
                processed_values.add(value_key)
                before_snapshot = experiment.get("before_snapshot", {})
                after_snapshot = experiment.get("after_snapshot", {})
                intervention = self._build_intervention(value, suspect_object, applied=True)
                # analyze run result and optionally record reason
                kind, reason = self._analyze_mutation_result(value, angelic_values, demonic_values)
                elapsed = time.monotonic() - candidate_started_at
                wall_clock_limit = int(budgets.get("candidate_wall_clock_seconds") or 0)
                if wall_clock_limit and elapsed > wall_clock_limit:
                    self._cost_stats["candidate_stats"]["wall_clock_timeouts"] += 1
                    self._record_pruning_reason("candidate_wall_clock_timeout")
                    self.logger.warning(
                        "Candidate exceeded wall-clock budget after completion: %.1fs > %ss",
                        elapsed,
                        wall_clock_limit,
                    )
                    harness.respawn()
                    continue
                trace_pair = self._build_trace_pair(
                    suspect_object=suspect_object,
                    before_snapshot=before_snapshot,
                    after_snapshot=after_snapshot,
                    intervention=intervention,
                    kind=kind,
                    reason=reason,
                )
                self._trace_pairs.append(trace_pair)
                if kind == "angelic":
                    self._safe_interventions.append(intervention)
                elif kind == "demonic":
                    self._unsafe_interventions.append(intervention)
                if report is not None:
                    if kind == "angelic":
                        report.setdefault("angelic", []).append((value, reason))
                    elif kind == "demonic":
                        report.setdefault("demonic", []).append((value, reason))
            else:
                self.logger.warning(f"Failed to apply mutation for value: {value}")
                self._cost_stats["candidate_stats"]["apply_failures"] += 1
                if report is not None:
                    report.setdefault("failed_to_apply", []).append(
                        (value, self._last_apply_error_msg or "unknown apply error")
                    )
                self._unsafe_interventions.append(
                    self._build_intervention(
                        value,
                        suspect_object,
                        applied=False,
                        apply_error=self._last_apply_error_msg or "unknown apply error",
                    )
                )
                # 如果是 LOGIC:GUARD 或 LOGIC:IF 失败，我们不应该把这次失败算作 ANGELIC，
                # 但也不一定是 DEMONIC。如果应用失败，最安全的做法是记录并继续，
                # 但要意识到这个 Test Case 实际上没有被正确执行。
                # 目前的代码只是打印 Warning，没有把 value 加入任何列表，这是正确的。

        return angelic_values, demonic_values

    def _capture_state_snapshot(self, suspect_object: dict) -> dict:
        return self._ensure_debugger_harness().capture_snapshot(suspect_object)

    def _is_unavailable_eval(self, value) -> bool:
        text = str(value).lower()
        return any(marker in text for marker in ("error:", "timeout", "not available", "unavailable", "lldb_eval"))

    def _build_intervention(self, value, suspect_object: dict, applied: bool, apply_error: str = "") -> dict:
        kind = "logic" if isinstance(value, str) and value.startswith("LOGIC:") else "assignment"
        target = {"file": suspect_object.get("file", ""), "line": suspect_object.get("line", -1)}
        actions = []
        if isinstance(value, dict):
            for lhs, rhs in value.items():
                handle = self._resolve_handle_for_target(suspect_object, str(lhs))
                actions.append({"variable": str(lhs), "value": self._json_safe_value(rhs)})
                if handle is not None:
                    actions[-1]["handle_kind"] = handle.kind
        else:
            primary_handle = self._resolve_primary_handle(suspect_object)
            action = {"value": self._json_safe_value(value), "variables": suspect_object.get("variable_names", [])}
            if primary_handle is not None:
                action["handle_kind"] = primary_handle.kind
                action["handle_name"] = primary_handle.name
            actions.append(action)
        return {
            "kind": kind,
            "actions": actions,
            "target_location": target,
            "applied": applied,
            "apply_error": apply_error,
        }

    def _build_trace_pair(
        self,
        suspect_object: dict,
        before_snapshot: dict,
        after_snapshot: dict,
        intervention: dict,
        kind: str,
        reason: str,
    ) -> dict:
        return {
            "hypothesis_id": suspect_object.get("hypothesis_id", ""),
            "demonic_before": before_snapshot,
            "intervention": intervention,
            "angelic_after": after_snapshot if kind == "angelic" else {},
            "outcome": {"kind": kind, "reason": reason},
            "path_delta": self._compute_snapshot_delta(before_snapshot, after_snapshot),
        }

    def _compute_snapshot_delta(self, before: dict, after: dict) -> dict:
        changed: dict = {}
        before_values = {**before.get("variables", {}), **before.get("expressions", {})}
        after_values = {**after.get("variables", {}), **after.get("expressions", {})}
        for expr, before_value in before_values.items():
            after_value = after_values.get(expr)
            if after_value != before_value:
                changed[expr] = {"before": before_value, "after": after_value}
        return {"changed_expressions": changed, "change_count": len(changed)}

    def _compute_minimal_deltas(self, trace_pairs: list[dict]) -> list[dict]:
        angelic = [tp for tp in trace_pairs if tp.get("outcome", {}).get("kind") == "angelic"]
        angelic.sort(key=lambda tp: tp.get("path_delta", {}).get("change_count", 999))
        return [
            {
                "hypothesis_id": tp.get("hypothesis_id", ""),
                "intervention": tp.get("intervention", {}),
                "path_delta": tp.get("path_delta", {}),
                "outcome": tp.get("outcome", {}),
            }
            for tp in angelic[:5]
        ]
            
    def _determine_ignore_count(self, file, line):
        try:
            debugger_clear_breakpoints()
            results = debugger_set_breakpoint_with_ids(file, line)
            bkpt_id = results[0][1] if results else -1
            if bkpt_id != -1:
                debugger_run()
                hit_count = debugger_get_breakpoint_hit_count(bkpt_id)
                return max(0, hit_count - 1)
        except Exception:
            pass
        return 0

    def _prepare_debugger_state(self, file, line, ignore_count):
        return self._ensure_debugger_harness().prepare(file, line, ignore_count)

    def _resolve_primary_handle(self, suspect_object: dict) -> InterventionHandle | None:
        handles = self._intervention_handles or infer_intervention_handles(suspect_object)
        return choose_primary_handle(handles)

    def _resolve_handle_for_target(self, suspect_object: dict, target: str) -> InterventionHandle | None:
        handles = self._intervention_handles or infer_intervention_handles(suspect_object)
        return find_handle(handles, target)

    def _assign_via_handle(self, target: str, value: Any, suspect_object: dict) -> tuple[bool, str]:
        handle = self._resolve_handle_for_target(suspect_object, target)
        if handle is None:
            return False, "missing_handle"
        assign_value = self._format_assign_value(value, handle.declared_type or suspect_object.get("debugger_reported_type") or suspect_object.get("llm_inferred_type") or "unknown")
        return debugger_assign(handle.name, assign_value)

    def _can_use_slot_assignment(self, target: str) -> bool:
        return self._is_assignable_target(target) and "->" not in target and "." not in target and not target.startswith("*")

    def _apply_mutation(self, value, suspect_object):
        # 1. 处理“逻辑动作”指令 (例如: LOGIC:IF(*n < 4) THEN RETURN(-1))
        if isinstance(value, str) and value.startswith("LOGIC:"):
            return self._handle_logic_mutation(value)

        if isinstance(value, dict):
            for lhs, rhs in value.items():
                if self._can_use_slot_assignment(str(lhs).strip()):
                    success, msg = self._assign_via_handle(str(lhs).strip(), rhs, suspect_object)
                else:
                    success, msg = debugger_assign_expression(f"{lhs} = {rhs}")
                if not success:
                    self._last_apply_error_msg = msg
                    return False
            return True

        # 2. 处理常规数值变异
        primary_handle = self._resolve_primary_handle(suspect_object)
        var_name = primary_handle.name if primary_handle is not None else suspect_object["variable_names"][0]
        var_type = (
            (primary_handle.declared_type if primary_handle is not None else "")
            or suspect_object.get("debugger_reported_type")
            or suspect_object.get("llm_inferred_type")
            or "unknown"
        )
        
        # 兼容性增强：如果 value 包含 '='，说明 Agent 试图直接写表达式（例如 "*n=3"）
        if isinstance(value, str) and "=" in value and not value.startswith("LOGIC:"):
            self.logger.info(f"Agent provided raw assignment expression: {value}")
            simple_match = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+?)\s*$", value)
            if simple_match and self._can_use_slot_assignment(simple_match.group(1)):
                success, msg = self._assign_via_handle(simple_match.group(1), simple_match.group(2), suspect_object)
            else:
                success, msg = debugger_assign_expression(value)
            if not success:
                 self._last_apply_error_msg = msg
                 return self._handle_assign_failure(value, var_name, var_type, value, msg, suspect_object)
            return True

        if self._can_use_slot_assignment(var_name):
            success, msg = self._assign_via_handle(var_name, value, suspect_object)
        else:
            assign_value = self._format_assign_value(value, var_type)
            success, msg = debugger_assign(var_name, assign_value)
        
        if not success:
            # 智能检测：Agent 是否错误地将函数调用写成了字符串？
            if isinstance(value, str) and ("add_guard" in value or "logic_return" in value):
                self.logger.warning(f"Detected potential Agent Hallucination: '{value}' looks like a function call wrapped in a string. It should be a direct function call.")
            self._last_apply_error_msg = msg
            assign_value = self._format_assign_value(value, var_type)
            return self._handle_assign_failure(value, var_name, var_type, assign_value, msg, suspect_object)
        return True

    def _handle_logic_mutation(self, logic_str: str) -> bool:
        """解析并执行逻辑级变异指令。"""
        self.logger.info(f"Applying logic mutation: {logic_str}")
        try:
            # Branch -1: Relocate execution to another source location, then execute an action there.
            # Format: LOGIC:AT(file:line) THEN <action>
            # Where <action> can be:
            #   - a raw assignment expression like "pe_offset=60" or "*p=0"
            #   - another LOGIC:... directive (e.g., LOGIC:IF(...) THEN RETURN(...))
            if logic_str.startswith("LOGIC:AT("):
                m = re.search(r'^LOGIC:AT\((.*?):(\d+)\)\s+THEN\s+(.*)$', logic_str, re.DOTALL)
                if not m:
                    self.logger.warning(f"Failed to parse AT string: {logic_str}")
                    self._last_apply_error_msg = "Failed to parse LOGIC:AT(...)"
                    return False
                at_file, at_line, action = m.groups()
                at_line_i = int(at_line)

                self.logger.info(f"Relocating to {at_file}:{at_line_i} before executing action...")
                lldb_out, _ = debugger_run_to_line(at_file, at_line_i)
                if lldb_out.get("reason") != "breakpoint-hit":
                    self.logger.warning(f"Failed to run to {at_file}:{at_line_i}. Stop reason: {lldb_out.get('reason')}")
                    self._last_apply_error_msg = f"Failed to run_to_line: {lldb_out.get('reason')}"
                    return False

                action = action.strip()
                if action.startswith("LOGIC:"):
                    return self._handle_logic_mutation(action)

                normalized, why = self._normalize_at_action(action)
                if not normalized:
                    self.logger.warning(f"AT action rejected by normalizer: {why}")
                    self._last_apply_error_msg = why or "AT action rejected"
                    return False

                # The normalizer may rewrite a `return`-style snippet into LOGIC:IF...
                if normalized.startswith("LOGIC:"):
                    return self._handle_logic_mutation(normalized)

                # Otherwise treat as raw assignment expression
                success, msg = debugger_assign_expression(normalized)
                if not success:
                    self.logger.warning(f"AT action assignment failed: {msg}")
                    self._last_apply_error_msg = msg
                return success

            # 分支 0: 持续性 Guard (add_guard)
            # 格式: LOGIC:GUARD(file:line) IF(condition) THEN RETURN(val)
            # 优化正则：允许文件路径包含非冒号字符，或者处理 Windows 盘符
            if logic_str.startswith("LOGIC:GUARD"):
                # 使用非贪婪匹配 .*? 来获取文件路径，直到遇到最后的 :数字
                match = re.search(r'GUARD\((.*?):(\d+)\) IF\((.*)\) THEN RETURN\((.*)\)', logic_str)
                if match:
                    file, line, cond, ret = match.groups()
                    self.logger.info(f"Adding persistent functional guard at {file}:{line}")
                    success, msg = debugger_add_functional_guard(file, int(line), cond, ret)
                    if not success:
                        self.logger.error(f"Failed to add guard: {msg}")
                        self._last_apply_error_msg = msg
                    return success
                else:
                    self.logger.warning(f"Failed to parse GUARD string: {logic_str}")
                    self._last_apply_error_msg = "Failed to parse LOGIC:GUARD(...)"
                    return False

            # 解析格式: LOGIC:IF(condition) THEN RETURN(val) 或 LOGIC:IF(condition) THEN ASSIGN(var=val)
            match = re.search(r'IF\((.*)\) THEN (?:RETURN|ASSIGN)\((.*)\)', logic_str)
            if not match:
                self._last_apply_error_msg = "Failed to parse LOGIC:IF(...)"
                return False
            
            condition = match.group(1)
            
            # 检查条件是否满足
            eval_res = debugger_print(f"(int)({condition})")
            if self._is_unavailable_eval(eval_res):
                self._last_apply_error_msg = f"Condition eval failed: {eval_res}"
                return False
            if " = 1" in eval_res or " = true" in eval_res.lower():
                self.logger.info(f"Condition '{condition}' is MET.")
                
                # 分支 1: 强制返回
                if "RETURN(" in logic_str:
                    ret_val = match.group(2)
                    self.logger.info(f"Forcing thread return {ret_val}...")
                    msg = debugger_execute(f"expr (void)printf(\"[JIT-GUARD] condition met, forcing return {ret_val}\\n\")")
                    if self._is_unavailable_eval(msg):
                        self._last_apply_error_msg = msg
                        return False
                    msg = debugger_execute(f"thread return {ret_val}")
                    if self._is_unavailable_eval(msg):
                        self._last_apply_error_msg = msg
                        return False
                    return True
                
                # 分支 2: 条件赋值
                elif "ASSIGN(" in logic_str:
                    assign_expr = match.group(2) # e.g., "len=1024"
                    self.logger.info(f"Applying conditional assignment: {assign_expr}")
                    msg = debugger_execute(f"expr (void)printf(\"[JIT-GUARD] condition met, applying assignment {assign_expr}\\n\")")
                    if self._is_unavailable_eval(msg):
                        self._last_apply_error_msg = msg
                        return False
                    success, msg = debugger_assign_expression(assign_expr)
                    if not success:
                        self._last_apply_error_msg = msg
                    return success
            else:
                self.logger.info(f"Condition '{condition}' is NOT met. Skipping logic action (treated as successful execution).")
                # 调试增强：打印条件中可能涉及的变量，帮助定位为什么没命中
                # 简单的正则提取变量名 (字母下划线开头，包含数字下划线)
                try:
                    vars_in_cond = set(re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', condition))
                    # 过滤掉 C 语言关键字和常用函数名
                    keywords = {'if', 'else', 'return', 'int', 'char', 'void', 'NULL', 'true', 'false', 'sizeof'}
                    vars_to_print = [v for v in vars_in_cond if v not in keywords]
                    
                    if vars_to_print:
                        self.logger.info(f"  [DEBUG] Inspecting variables in condition: {vars_to_print}")
                        for v in vars_to_print:
                            val = debugger_print(v)
                            self.logger.info(f"    {v} = {val.strip()}")
                except Exception:
                    pass

                # 即使条件不满足，也视为变异执行成功（只是没触发副作用）
                # 这样可以继续运行程序，观察是否 Crash
                return True
        except Exception as e:
            self.logger.error(f"Error executing logic mutation: {e}")
            self._last_apply_error_msg = str(e)
            return False

    def _format_assign_value(self, value, var_type):
        if '*' in var_type.replace(' ', ''):
            return f"({var_type}){value}"
        if var_type != "unknown":
            return f"({var_type})({value})"
        return str(value)

    def _handle_assign_failure(self, value, var_name, var_type, assign_value, msg, suspect_object):
        # Simplistic const_cast attempt
        if "const" in msg.lower() or "cannot assign" in msg.lower():
            base_type = extract_base_type_for_const_cast(var_type)
            expr = f"const_cast<{base_type}>({var_name}) = {assign_value}"
            success, _ = debugger_assign_expression(expr)
            if success:
                suspect_object["variable_names"] = [f"const_cast<{base_type}>({var_name})"]
                return True
        return False

    def _analyze_mutation_result(self, value, angelic_values, demonic_values) -> tuple[str, str]:
        try:
            lldb_out, target_out = debugger_continue()
            reason = lldb_out.get("reason")
            has_asan, asan_msg = check_asan_error_in_output(target_out, lldb_out)
            
            # 详细记录程序输出
            if target_out:
                clean_out = target_out.strip()[:500].replace("\n", " ")
                self.logger.info(f"  [OUTPUT] {clean_out}...")
            
            if has_asan:
                self.logger.warning(f"  [RESULT] DEMONIC (ASan Error: {asan_msg})")
                demonic_values.append(value)
                return "demonic", f"asan: {asan_msg}"
            elif reason == "signal-received":
                sig_name = lldb_out.get("signal_name", "SIG??")
                self.logger.warning(f"  [RESULT] DEMONIC (Signal: {sig_name})")
                demonic_values.append(value)
                return "demonic", f"signal: {sig_name}"
            elif reason == "exited-normally" or reason == "breakpoint-hit":
                self.logger.info(f"  [RESULT] ANGELIC (Stop Reason: {reason})")
                angelic_values.append(value)
                return "angelic", f"stop: {reason}"
            else:
                self.logger.info(f"  [RESULT] UNKNOWN (Stop Reason: {reason})")
                demonic_values.append(value)
                return "demonic", f"stop: {reason}"
        except Exception as e:
            self.logger.error(f"  [ERROR] Exception during mutation analysis: {e}")
            demonic_values.append(value)
            return "demonic", f"exception: {e}"
