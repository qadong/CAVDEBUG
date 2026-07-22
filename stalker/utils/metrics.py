from __future__ import annotations

import os
from collections import Counter
from datetime import datetime, timezone
from typing import Any

from utils.files import dump_json, load_json


def _status_counts(items: list[Any], extractor) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for item in items or []:
        status = str(extractor(item) or "unknown").strip() or "unknown"
        counts[status] += 1
    return dict(sorted(counts.items()))


def _sum_ints(values: list[Any]) -> int:
    total = 0
    for value in values:
        try:
            total += int(value or 0)
        except (TypeError, ValueError):
            continue
    return total


def _empty_usage_costs() -> dict[str, Any]:
    return {
        "total_cost": 0.0,
        "prompt_tokens": 0,
        "completion_tokens": 0,
        "total_tokens": 0,
        "cached_tokens": 0,
        "model_costs": {},
    }


def _add_usage_costs(target: dict[str, Any], usage: Any) -> None:
    if isinstance(usage, (int, float)):
        target["total_cost"] += float(usage)
        return
    if not isinstance(usage, dict):
        return

    try:
        target["total_cost"] += float(usage.get("total_cost", 0.0) or 0.0)
    except (TypeError, ValueError):
        pass

    for model_name, model_usage in usage.items():
        if model_name == "total_cost" or not isinstance(model_usage, dict):
            continue
        model_costs = target["model_costs"].setdefault(
            str(model_name),
            {
                "cost": 0.0,
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_tokens": 0,
                "cached_tokens": 0,
            },
        )
        for field in ("prompt_tokens", "completion_tokens", "total_tokens", "cached_tokens"):
            try:
                value = int(model_usage.get(field, 0) or 0)
            except (TypeError, ValueError):
                value = 0
            target[field] += value
            model_costs[field] += value
        try:
            model_costs["cost"] += float(model_usage.get("cost", 0.0) or 0.0)
        except (TypeError, ValueError):
            pass


def _iter_chat_costs(result_dir: str) -> list[Any]:
    chat_dir = os.path.join(result_dir, "chat")
    try:
        names = sorted(os.listdir(chat_dir))
    except OSError:
        return []

    costs: list[Any] = []
    for name in names:
        if not name.endswith(".json"):
            continue
        path = os.path.join(chat_dir, name)
        try:
            payload = load_json(path)
        except Exception:
            continue
        if isinstance(payload, dict) and "cost" in payload:
            costs.append(payload.get("cost"))
    return costs


def _llm_cost_metrics(result_dir: str) -> dict[str, Any]:
    costs = _iter_chat_costs(result_dir) if result_dir else []
    including_cached = _empty_usage_costs()
    excluding_cached = _empty_usage_costs()
    available_count = 0
    unavailable_count = 0

    for cost in costs:
        if isinstance(cost, dict):
            available_count += 1
            _add_usage_costs(including_cached, cost.get("usage_including_cached_inference"))
            _add_usage_costs(excluding_cached, cost.get("usage_excluding_cached_inference"))
        elif isinstance(cost, (int, float)):
            available_count += 1
            _add_usage_costs(including_cached, cost)
            _add_usage_costs(excluding_cached, cost)
        else:
            unavailable_count += 1

    return {
        "chat_file_count": len(costs),
        "available_cost_count": available_count,
        "unavailable_cost_count": unavailable_count,
        "usage_including_cached_inference": including_cached,
        "usage_excluding_cached_inference": excluding_cached,
    }


def _fuzz_cost_metrics(fuzz_result: dict[str, Any] | None) -> dict[str, Any]:
    fuzz_result = fuzz_result or {}
    cost_stats = fuzz_result.get("cost_stats") if isinstance(fuzz_result.get("cost_stats"), dict) else {}
    budgets = cost_stats.get("budgets") if isinstance(cost_stats.get("budgets"), dict) else {}
    candidate_stats = cost_stats.get("candidate_stats") if isinstance(cost_stats.get("candidate_stats"), dict) else {}
    snapshot_stats = cost_stats.get("snapshot_stats") if isinstance(cost_stats.get("snapshot_stats"), dict) else {}
    debugger_stats = cost_stats.get("debugger_stats") if isinstance(cost_stats.get("debugger_stats"), dict) else {}
    debugger_runtime = cost_stats.get("debugger_runtime") if isinstance(cost_stats.get("debugger_runtime"), dict) else {}
    lldb_runtime = debugger_runtime.get("lldb") if isinstance(debugger_runtime.get("lldb"), dict) else {}
    return {
        "budget_exhausted": bool(cost_stats.get("budget_exhausted", False)),
        "exhausted_budget": str(cost_stats.get("exhausted_budget", "") or ""),
        "candidate_budget": int(budgets.get("candidate_budget", 0) or 0),
        "snapshot_expression_budget": int(budgets.get("snapshot_expression_budget", 0) or 0),
        "respawn_budget": int(budgets.get("respawn_budget", 0) or 0),
        "state_prepare_retry_budget": int(budgets.get("state_prepare_retry_budget", 0) or 0),
        "force_respawn_every_n_candidates": int(budgets.get("force_respawn_every_n_candidates", 0) or 0),
        "candidate_seen": int(candidate_stats.get("seen", 0) or 0),
        "candidate_tested": int(candidate_stats.get("tested", 0) or 0),
        "duplicate_skips": int(candidate_stats.get("duplicate_skips", 0) or 0),
        "pruned_skips": int(candidate_stats.get("pruned_skips", 0) or 0),
        "budget_skips": int(candidate_stats.get("budget_skips", 0) or 0),
        "apply_failures": int(candidate_stats.get("apply_failures", 0) or 0),
        "snapshot_count": int(snapshot_stats.get("snapshots", 0) or 0),
        "snapshot_expression_evals": int(snapshot_stats.get("expression_evals", 0) or 0),
        "snapshot_budget_exhaustions": int(snapshot_stats.get("budget_exhaustions", 0) or 0),
        "prepare_calls": int(debugger_stats.get("prepare_calls", 0) or 0),
        "prepare_failures": int(debugger_stats.get("prepare_failures", 0) or 0),
        "respawns": int(debugger_stats.get("respawns", 0) or 0),
        "pruning_reasons": dict(sorted((cost_stats.get("pruning_reasons") or {}).items())),
        "debugger_print_requests": int(debugger_runtime.get("print_requests", 0) or 0),
        "debugger_print_cache_hits": int(debugger_runtime.get("print_cache_hits", 0) or 0),
        "debugger_print_cache_misses": int(debugger_runtime.get("print_cache_misses", 0) or 0),
        "debugger_cache_invalidations": int(debugger_runtime.get("cache_invalidations", 0) or 0),
        "debugger_state_epoch": int(debugger_runtime.get("state_epoch", 0) or 0),
        "lldb_eval_requests": int(lldb_runtime.get("eval_requests", 0) or 0),
        "lldb_eval_timeouts": int(lldb_runtime.get("eval_timeouts", 0) or 0),
        "lldb_eval_retries": int(lldb_runtime.get("eval_retries", 0) or 0),
        "lldb_eval_errors": int(lldb_runtime.get("eval_errors", 0) or 0),
        "lldb_assign_requests": int(lldb_runtime.get("assign_requests", 0) or 0),
        "lldb_slow_evals": int(lldb_runtime.get("slow_evals", 0) or 0),
        "lldb_total_eval_seconds": float(lldb_runtime.get("total_eval_seconds", 0.0) or 0.0),
    }


def _round_metrics_entry(round_no: int, actor: str, message: dict[str, Any] | None, route: dict[str, Any] | None) -> dict[str, Any]:
    message = message or {}
    artifacts = message.get("artifacts") if isinstance(message.get("artifacts"), dict) else {}
    metrics = artifacts.get("round_metrics") if isinstance(artifacts.get("round_metrics"), dict) else {}
    return {
        "round": int(round_no or 0),
        "actor": actor or message.get("actor", "unknown"),
        "recommended_next_actor": message.get("recommended_next_actor") or metrics.get("recommended_next_actor"),
        "hypothesis_id": (route or {}).get("hypothesis_id") or metrics.get("hypothesis_id", ""),
        "claims": list(message.get("claims", []) or [])[:2],
        "metrics": metrics,
    }


def debug_round_metrics(
    analysis: list[dict[str, Any]] | None,
    suspects: list[dict[str, Any]] | None,
    active_hypothesis_id: str,
    recommended_next_actor: str | None,
    bug_type_profile: dict[str, Any] | None = None,
    surface_bug_type_profile: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "actor": "debug",
        "analysis_count": len(analysis or []),
        "suspect_count": len(suspects or []),
        "active_hypothesis_id": active_hypothesis_id or "",
        "recommended_next_actor": recommended_next_actor,
        "root_cause_bug_type": str((bug_type_profile or {}).get("bug_type", "unknown")),
        "surface_bug_type": str((surface_bug_type_profile or {}).get("bug_type", "unknown")),
    }


def fuzz_round_metrics(fuzz_result: dict[str, Any] | None, hypothesis_id: str, recommended_next_actor: str | None) -> dict[str, Any]:
    fuzz_result = fuzz_result or {}
    typed = fuzz_result.get("typed_angelic_evidence") if isinstance(fuzz_result.get("typed_angelic_evidence"), dict) else {}
    demonic_summary = fuzz_result.get("demonic_trace_summary") if isinstance(fuzz_result.get("demonic_trace_summary"), dict) else {}
    return {
        "actor": "fuzz",
        "hypothesis_id": hypothesis_id or "",
        "recommended_next_actor": recommended_next_actor,
        "angelic_count": len(fuzz_result.get("angelic_values", []) or []),
        "demonic_count": len(fuzz_result.get("demonic_values", []) or []),
        "trace_pair_count": len(fuzz_result.get("trace_pairs", []) or []),
        "minimal_delta_count": len(fuzz_result.get("minimal_deltas", []) or []),
        "typed_bug_type": str(typed.get("bug_type", "unknown")),
        "validation_obligation_count": len(typed.get("validation_obligations", []) or []),
        "demonic_trace_pair_count": int(demonic_summary.get("trace_pair_count", 0) or 0),
        "costs": _fuzz_cost_metrics(fuzz_result),
    }


def constraint_round_metrics(candidates: list[Any] | None, recommended_next_actor: str | None) -> dict[str, Any]:
    candidates = candidates or []
    usable_statuses = {"supported_and_executable", "supported_but_proxy_like", "weakly_supported"}
    support_stats = [getattr(candidate, "support_stats", {}) or {} for candidate in candidates]
    challenge_results = [getattr(candidate, "challenge_result", {}) or {} for candidate in candidates]
    return {
        "actor": "constraint",
        "recommended_next_actor": recommended_next_actor,
        "candidate_count": len(candidates),
        "usable_candidate_count": sum(1 for candidate in candidates if getattr(candidate, "constraint_status", "") in usable_statuses),
        "constraint_status_counts": _status_counts(candidates, lambda item: getattr(item, "constraint_status", "unknown")),
        "challenge_status_counts": _status_counts(challenge_results, lambda item: item.get("status", "unknown")),
        "challenger_supported_count": _sum_ints(stats.get("challenger_support_count", 0) for stats in support_stats),
        "challenger_counterexample_count": _sum_ints(stats.get("challenger_counterexample_count", 0) for stats in support_stats),
        "eval_failure_count": _sum_ints(stats.get("eval_failures", 0) for stats in support_stats),
        "positive_examples_seen": _sum_ints(stats.get("positive_examples_seen", 0) for stats in support_stats),
        "negative_examples_seen": _sum_ints(stats.get("negative_examples_seen", 0) for stats in support_stats),
        "positive_examples_skipped": _sum_ints(stats.get("positive_examples_skipped", 0) for stats in support_stats),
        "negative_examples_skipped": _sum_ints(stats.get("negative_examples_skipped", 0) for stats in support_stats),
    }


def counterfactual_round_metrics(contract: Any | None, recommended_next_actor: str | None) -> dict[str, Any]:
    if contract is None:
        return {
            "actor": "counterfactual",
            "recommended_next_actor": recommended_next_actor,
            "contract_present": False,
        }
    angelic = list(getattr(contract, "angelic_observations", []) or [])
    demonic = list(getattr(contract, "demonic_observations", []) or [])
    observations = angelic + demonic
    return {
        "actor": "counterfactual",
        "recommended_next_actor": recommended_next_actor,
        "contract_present": True,
        "contract_id": getattr(contract, "contract_id", ""),
        "hypothesis_id": getattr(contract, "hypothesis_id", ""),
        "bug_type": getattr(contract, "bug_type", "unknown"),
        "boundary_kind": getattr(contract, "boundary_kind", "unknown"),
        "has_boundary_predicate": bool(getattr(contract, "boundary_predicate", "")),
        "enforcement_priority": getattr(contract, "enforcement_priority", "unknown"),
        "angelic_observation_count": len(angelic),
        "demonic_observation_count": len(demonic),
        "target_crash_status_counts": _status_counts(observations, lambda item: item.get("target_crash_status", "unknown")),
        "outcome_counts": _status_counts(observations, lambda item: item.get("outcome", "unknown")),
        "validation_obligation_count": len(getattr(contract, "validation_obligations", []) or []),
    }


def patch_round_metrics(generated: list[Any] | None, recommended_next_actor: str | None) -> dict[str, Any]:
    generated = generated or []
    return {
        "actor": "patch",
        "recommended_next_actor": recommended_next_actor,
        "generated_count": len(generated),
        "heuristic_count": sum(1 for candidate in generated if bool((getattr(candidate, "metadata", {}) or {}).get("heuristic"))),
        "strategy_counts": _status_counts(generated, lambda item: getattr(item, "strategy", "unknown")),
        "location_type_counts": _status_counts(generated, lambda item: getattr(item, "location_type", "unknown")),
    }


def verification_round_metrics(feedback: dict[str, Any] | None, candidate: Any = None) -> dict[str, Any]:
    feedback = feedback or {}
    details = feedback.get("details") if isinstance(feedback.get("details"), dict) else {}
    tiers = details.get("tiers") if isinstance(details.get("tiers"), dict) else {}
    direct_patch_assessment = feedback.get("direct_patch_assessment") if isinstance(feedback.get("direct_patch_assessment"), dict) else {}
    return {
        "actor": "verify",
        "recommended_next_actor": feedback.get("recommended_next_actor"),
        "status": feedback.get("status", "unknown"),
        "layer1_verdict": feedback.get("layer1_verdict", ""),
        "constraint": getattr(candidate, "constraint", "") if candidate is not None else "",
        "strategy": getattr(candidate, "strategy", "") if candidate is not None else "",
        "location_type": getattr(candidate, "location_type", "") if candidate is not None else "",
        "verification_confidence": details.get("verification_confidence"),
        "direct_patch_risk": direct_patch_assessment.get("direct_patch_risk", ""),
        "tier1_status": (tiers.get("tier1_original_poc") or {}).get("status"),
        "tier2_status": (tiers.get("tier2_variants") or {}).get("status"),
        "tier2_inputs": (tiers.get("tier2_variants") or {}).get("input_count", 0),
        "tier3_status": (tiers.get("tier3_regression") or {}).get("status"),
        "tier3_inputs": (tiers.get("tier3_regression") or {}).get("input_count", 0),
    }


def build_case_summary(meta: dict[str, Any] | None, interaction_state: dict[str, Any] | None, profile: dict[str, Any] | None = None) -> dict[str, Any]:
    meta = meta or {}
    interaction_state = interaction_state or {}
    profile = profile or {}

    effective_profile = meta.get("profile") if isinstance(meta.get("profile"), dict) else profile
    messages = interaction_state.get("messages") if isinstance(interaction_state.get("messages"), list) else []
    routing = interaction_state.get("route_history") if isinstance(interaction_state.get("route_history"), list) else meta.get("routing", []) or []
    constraints = meta.get("constraints") if isinstance(meta.get("constraints"), list) else interaction_state.get("constraint_candidates", []) or []
    counterfactual_contracts_raw = (
        meta.get("counterfactual_contracts")
        if isinstance(meta.get("counterfactual_contracts"), dict)
        else interaction_state.get("counterfactual_contracts", {})
    )
    counterfactual_contracts = list(counterfactual_contracts_raw.values()) if isinstance(counterfactual_contracts_raw, dict) else []
    verification = meta.get("verification_feedback") if isinstance(meta.get("verification_feedback"), list) else interaction_state.get("verification_feedback", []) or []
    patch_candidates = meta.get("patch_candidates") if isinstance(meta.get("patch_candidates"), list) else interaction_state.get("patch_candidates", []) or []

    route_sequence = [str(item.get("actor", "unknown")) for item in routing]
    round_summaries = []
    for index, route in enumerate(routing):
        message = messages[index] if index < len(messages) and isinstance(messages[index], dict) else {}
        round_summaries.append(
            _round_metrics_entry(
                round_no=int(route.get("round", index + 1) or index + 1),
                actor=str(route.get("actor", message.get("actor", "unknown"))),
                message=message,
                route=route,
            )
        )

    constraint_support_stats = [
        item.get("support_stats", {}) for item in constraints
        if isinstance(item, dict) and isinstance(item.get("support_stats"), dict)
    ]
    verification_status_counts = _status_counts(verification, lambda item: item.get("status", "unknown"))
    layer1_verdict_counts = _status_counts(verification, lambda item: item.get("layer1_verdict", "") or "not_layer1")
    accepted_patch_count = sum(
        1 for item in verification
        if item.get("status") == "pass" and str(item.get("layer1_verdict", "") or "") not in {"weak", "suspicious"}
    )
    fuzz_result = interaction_state.get("fuzz_result") if isinstance(interaction_state.get("fuzz_result"), dict) else {}
    result_dir = str(effective_profile.get("result_dir", profile.get("result_dir", "")) or "")
    counterfactual_observations = [
        observation
        for contract in counterfactual_contracts
        if isinstance(contract, dict)
        for observation in (contract.get("angelic_observations", []) or []) + (contract.get("demonic_observations", []) or [])
        if isinstance(observation, dict)
    ]

    return {
        "artifact_version": "case_observability.v1",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project_id": effective_profile.get("id", profile.get("id", "")),
        "result_dir": result_dir,
        "pipeline": {
            "round_count": len(routing),
            "max_rounds": int(interaction_state.get("max_rounds", effective_profile.get("interaction_max_rounds", 0)) or 0),
            "route_sequence": route_sequence,
            "actor_counts": dict(sorted(Counter(route_sequence).items())),
            "final_next_actor": interaction_state.get("next_actor"),
            "rounds_without_progress": int(interaction_state.get("rounds_without_progress", 0) or 0),
            "champion_patch_found": bool(meta.get("patch")),
            "failure": meta.get("failure") if isinstance(meta.get("failure"), dict) else {},
        },
        "rounds": round_summaries,
        "constraints": {
            "candidate_count": len(constraints),
            "status_counts": _status_counts(constraints, lambda item: item.get("constraint_status", "unknown")),
            "challenge_status_counts": _status_counts(
                [item.get("challenge_result", {}) for item in constraints if isinstance(item, dict)],
                lambda item: item.get("status", "unknown"),
            ),
            "challenger_supported_count": _sum_ints(stats.get("challenger_support_count", 0) for stats in constraint_support_stats),
            "challenger_counterexample_count": _sum_ints(stats.get("challenger_counterexample_count", 0) for stats in constraint_support_stats),
            "eval_failure_count": _sum_ints(stats.get("eval_failures", 0) for stats in constraint_support_stats),
        },
        "counterfactual": {
            "contract_count": len(counterfactual_contracts),
            "boundary_kind_counts": _status_counts(counterfactual_contracts, lambda item: item.get("boundary_kind", "unknown")),
            "enforcement_priority_counts": _status_counts(counterfactual_contracts, lambda item: item.get("enforcement_priority", "unknown")),
            "target_crash_status_counts": _status_counts(counterfactual_observations, lambda item: item.get("target_crash_status", "unknown")),
            "outcome_counts": _status_counts(counterfactual_observations, lambda item: item.get("outcome", "unknown")),
            "disappeared_count": sum(1 for item in counterfactual_observations if item.get("target_crash_status") == "disappeared"),
            "persisted_count": sum(1 for item in counterfactual_observations if item.get("target_crash_status") == "persisted"),
            "changed_count": sum(1 for item in counterfactual_observations if item.get("target_crash_status") == "changed"),
            "inconclusive_count": sum(1 for item in counterfactual_observations if item.get("target_crash_status") == "inconclusive"),
        },
        "verification": {
            "attempt_count": len(verification),
            "status_counts": verification_status_counts,
            "layer1_verdict_counts": layer1_verdict_counts,
            "final_status": verification[-1].get("status") if verification else None,
            "verified_patch_count": accepted_patch_count,
            "rejected_patch_count": len(verification) - accepted_patch_count,
        },
        "costs": {
            "debug": {
                "analysis_count": len(interaction_state.get("analysis", []) or []),
                "suspect_count": len(interaction_state.get("suspects", []) or []),
                "hypothesis_pool_size": len(interaction_state.get("hypothesis_pool", []) or []),
            },
            "fuzz": {
                "angelic_count": len((fuzz_result.get("angelic_values", []) or [])),
                "demonic_count": len((fuzz_result.get("demonic_values", []) or [])),
                "trace_pair_count": len((fuzz_result.get("trace_pairs", []) or [])),
                "minimal_delta_count": len((fuzz_result.get("minimal_deltas", []) or [])),
                **_fuzz_cost_metrics(fuzz_result),
            },
            "patch": {
                "candidate_count": len(patch_candidates),
                "verified_candidate_count": sum(1 for item in patch_candidates if str(item.get("status", "")) == "validated"),
            },
            "llm": _llm_cost_metrics(result_dir),
        },
    }


def write_case_summary(profile: dict[str, Any], logger=None) -> dict[str, Any] | None:
    meta_path = str(profile.get("meta_output", "")).strip()
    result_dir = str(profile.get("result_dir", "")).strip()
    if not result_dir:
        return None

    interaction_state_path = os.path.join(result_dir, "interaction_state.json")
    meta = load_json(meta_path) if meta_path and os.path.exists(meta_path) else {}
    interaction_state = load_json(interaction_state_path) if os.path.exists(interaction_state_path) else {}
    if not meta and not interaction_state:
        return None

    summary = build_case_summary(meta=meta, interaction_state=interaction_state, profile=profile)
    output_path = os.path.join(result_dir, "case_summary.json")
    dump_json(summary, output_path)
    if logger is not None:
        logger.info("Wrote case summary to %s", output_path)
    return summary
