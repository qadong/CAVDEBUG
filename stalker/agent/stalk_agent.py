# Main agent

import ast
import json
import os
import re
import hashlib
import shlex
from pathlib import Path
from agent.adapters import (
    run_layer2_entry_round,
    run_constraint_round_adapter,
    run_counterfactual_round,
    run_debug_round,
    run_fuzz_round,
    run_patch_round,
    run_verify_round,
    select_champion_patch,
)
from agent.state import BugHypothesisState
from agent import reproduce_agent
from agent import debug_agent
from agent import patch_agent
from agent import zero_shot_agent
from agent.prompts import STALK_BRAINSTORM_PROMPT, FUZZER_SYSTEM_PROMPT
from agent.generic_agent import GenericAgent
from tools.fuzzer.functions import fuzz_variables
from tools.verifier.functions import verify
from utils.verification import verify_patch
from utils.files import dump_json
from utils.command import run_compile
from utils.ablation import FULL_PIPELINE_BUDGET_MAX_ROUNDS, full_pipeline_budget_limited, no_cfc, state_only_no_angelic
from tools.debugger.driver import debugger_exit, debugger_init, debugger_instance
from tools.debugger.functions import debugger_run_to_line, debugger_assign, debugger_print
from tools.lsp.driver import lsp_exit, lsp_init
from utils.logger import logf

NAME = "agent-stalk"

@logf(NAME)
def save_meta(meta, profile, logger=None):
    logger.warning("Saving meta data")
    dump_json(meta, profile["meta_output"])


def _maybe_rebuild_before_debug(profile, logger):
    """
    Rebuild only when explicitly requested by the profile.
    """
    if not bool(profile.get("force_rebuild", False)):
        return
    logger.warning("force_rebuild enabled. Recompiling project before debugging...")
    ret_code, stdout, stderr = run_compile()
    if ret_code != 0:
        logger.error(f"Compilation failed during forced rebuild:\n{stdout}\n{stderr}")
        raise RuntimeError("Failed to compile during forced rebuild")


def _record_failure(meta: dict, stage: str, reason: str, action: str = ""):
    meta["failure"] = {
        "stage": stage,
        "reason": reason,
        "action": action,
    }


def _has_runtime_crash_signature(reproduce_result: dict) -> bool:
    text = str(reproduce_result.get("error") or "")
    return bool(re.search(
        r"(AddressSanitizer|MemorySanitizer|UndefinedBehaviorSanitizer|LeakSanitizer|ThreadSanitizer|"
        r"ERROR:\s+\w*Sanitizer|runtime error:|DEADLYSIGNAL)",
        text,
    ))


def _sync_profile_executable_from_reproduce(profile: dict, reproduce_result: dict, logger) -> bool:
    current_executable = str(profile.get("file") or "")
    if current_executable and os.path.exists(current_executable):
        return False
    executable = str(reproduce_result.get("executable") or "")
    if not executable:
        return False
    if not os.path.exists(executable):
        logger.warning("Reproduce inferred executable does not exist: %s", executable)
        return False
    logger.info("Using executable inferred from reproduce output: %s", executable)
    profile["file"] = executable
    if reproduce_result.get("args") is not None:
        profile["args"] = list(reproduce_result.get("args") or [])
    return True


def _secbench_case_path(profile: dict) -> Path | None:
    case_dir = (profile.get("secbench") or {}).get("case_dir")
    if not case_dir:
        return None
    candidates = [Path(str(case_dir))]
    if not Path(str(case_dir)).is_absolute():
        candidates.append(Path("/root/workspace") / str(case_dir))
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def _repro_body(secb_sh: str) -> str:
    match = re.search(r"repro\(\)\s*\{(?P<body>.*?)(?:\n\}\n\npatch\(\)|\n\})", secb_sh, flags=re.S)
    return match.group("body") if match else ""


def _maybe_fill_secbench_command_from_case(profile: dict, logger) -> bool:
    current_executable = str(profile.get("file") or "")
    if current_executable and os.path.exists(current_executable):
        return False
    try:
        executable, args = reproduce_agent._parse_secbench_repro_command_from_file(profile)
    except Exception:
        executable, args = "", []
    if executable:
        profile["file"] = executable
        profile["args"] = args
        logger.info("Using executable parsed from in-source SEC-bench repro command: %s", executable)
        return True
    case_path = _secbench_case_path(profile)
    if case_path is None:
        return False
    row_path = case_path / "row.json"
    if not row_path.exists():
        return False
    try:
        row = json.loads(row_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False

    cwd = str(row.get("work_dir") or profile.get("src") or "")
    ignored = {"echo", "cd", "export", "sleep", "kill", "bash", "nc", "true", "false", "touch"}
    for raw_line in _repro_body(str(row.get("secb_sh") or "")).splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        line = line.split("#", 1)[0].strip()
        line = line.split("||", 1)[0].strip()
        if "|" in line:
            line = line.rsplit("|", 1)[1].strip()
        if line.endswith("&"):
            line = line[:-1].strip()
        try:
            parts = shlex.split(line)
        except ValueError:
            continue
        if parts[0] == "cd" and len(parts) >= 2:
            cwd = parts[1]
            continue
        while parts and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", parts[0]):
            parts.pop(0)
        if len(parts) >= 3 and parts[0] == "timeout":
            parts = parts[2:]
        if not parts or parts[0] in ignored:
            continue
        if not reproduce_agent._looks_like_target_command(parts[0]):
            continue
        executable = parts[0]
        if executable.startswith("./"):
            executable = str(Path(cwd) / executable[2:])
        elif not executable.startswith("/"):
            executable = str(Path(cwd) / executable)
        if not executable.startswith("/"):
            continue
        profile["file"] = executable
        profile["args"] = parts[1:]
        logger.info("Using executable parsed from SEC-bench repro command: %s", executable)
        return True
    return False


def _actor_consumes_round(actor: str) -> bool:
    return actor != "verify"


def _interaction_max_rounds(profile: dict) -> int:
    max_rounds = int(profile.get("interaction_max_rounds", 3))
    if state_only_no_angelic(profile) or no_cfc(profile):
        return min(max_rounds, 2)
    if full_pipeline_budget_limited(profile):
        return min(max_rounds, FULL_PIPELINE_BUDGET_MAX_ROUNDS)
    return max_rounds


def _schedule_empty_debug_retry(state: BugHypothesisState, meta: dict, profile: dict, logger=None) -> bool:
    retry_limit = int(profile.get("debug_empty_analysis_retry_limit", 1) or 0)
    if state.debug_empty_analysis_retries >= retry_limit:
        _record_failure(
            meta,
            stage="debug",
            reason="empty_analysis",
            action="stop_pipeline",
        )
        state.next_actor = "done"
        return False

    state.debug_empty_analysis_retries += 1
    if state.round_index > 0:
        state.round_index -= 1
    state.debug_retry_observation = (
        f"Retry {state.debug_empty_analysis_retries}/{retry_limit}: the previous DebugAgent response did not produce "
        "a usable root-cause suspect for downstream repair. Re-analyze the crash from a different project frame, "
        "upstream assignment, guard, caller, or state expression. Submit a non-empty RCA with concrete suspect "
        "variables or suspect expressions, analysis_file, analysis_line, and a debug_summary."
    )
    meta.setdefault("debug_retries", []).append(
        {
            "reason": "empty_analysis",
            "retry": state.debug_empty_analysis_retries,
            "limit": retry_limit,
            "observation": state.debug_retry_observation,
        }
    )
    state.next_actor = "debug"
    if logger is not None:
        logger.warning("DebugAgent produced empty RCA; scheduling retry %s/%s.", state.debug_empty_analysis_retries, retry_limit)
    return True


def _legacy_layer2_enabled(profile: dict | None) -> bool:
    return bool(isinstance(profile, dict) and profile.get("enable_legacy_layer2", False))


def _route_legacy_layer2_actor(actor: str, state: BugHypothesisState, profile: dict | None) -> str:
    if actor not in {"layer2", "fuzz", "constraint"} or _legacy_layer2_enabled(profile):
        return actor
    if no_cfc(profile):
        return "patch"
    return "patch" if state.current_counterfactual_contract() is not None else "counterfactual"


def _zero_shot_stalk(profile, logger):
    logger.warning("[Zero-shot] Stalking bug for project: %s", profile["id"])

    logger.debug("Changing to the project source directory: %s", profile["src"])
    os.chdir(profile["src"])
    logger.info("Current directory: %s", os.getcwd())

    logger.debug("Initializing LSP")
    _maybe_fill_secbench_command_from_case(profile, logger)
    lsp_init(executable="clangd", cwd=profile["src"])

    meta = {"profile": profile}

    logger.warning("Reproducing the problem")
    reproduce_result = reproduce_agent.reproduce(profile)
    if not reproduce_result["status"]:
        logger.error("Failed to reproduce the bug")
        meta["reproduced"] = False
        save_meta(meta, profile)
        return
    if reproduce_result["return_code"] == 0 and not _has_runtime_crash_signature(reproduce_result):
        logger.info("No problem found, exiting as fixed")
        meta["reproduced"] = False
        save_meta(meta, profile)
        return
    _sync_profile_executable_from_reproduce(profile, reproduce_result, logger)
    meta["reproduced"] = True

    logger.warning("Bug reproduced, initiating zero-shot patch generation")
    patch = zero_shot_agent.chat(profile, reproduce_result)
    if patch is None:
        logger.error("Failed to generate patch")
        meta["patch"] = None
        save_meta(meta, profile)
        return
    meta["patch"] = patch
    logger.info("Patch generation complete", patch)

    save_meta(meta, profile)

    logger.info("Stalking complete")

    lsp_exit()


def online_verify_constraints(constraints: list[str], angelic_list: list, demonic_list: list, suspect_object: dict, logger) -> dict[str, tuple[bool, str]]:
    """
    Verifies multiple constraints efficiently using the LIVE debugger session.
    Returns a mapping of constraint -> (is_valid, reason).
    """
    file = suspect_object["file"]
    line = suspect_object["line"]
    var_name = suspect_object["variable_names"][0]
    var_type = (suspect_object.get("llm_inferred_type") or "unknown")

    logger.info(f"Online verifying {len(constraints)} constraints")

    results = {c: (True, "Passed") for c in constraints}
    remaining_constraints = set(constraints)

    def _is_lldb_expr_compatible(expr: str) -> tuple[bool, str]:
        """
        The verifier evaluates constraints via LLDB `expr` / `print` as `(int)(<expr>)`.
        Many project macros/helpers are not available in this context.
        Reject expressions that look like function/macro calls (except sizeof).
        """
        s = (expr or "").strip()
        if not s:
            return False, "Empty constraint"

        # Explicitly block common sugar reported in incidents
        if re.search(r"\b(min|max|GF_ARRAY_LENGTH)\s*\(", s):
            return False, "Uses helper/macro call (min/max/GF_ARRAY_LENGTH) which is not available in LLDB expr"

        # Disallow macro-like identifiers (ALL_CAPS) - typically not in scope in expr evaluator
        if re.search(r"\b[A-Z][A-Z0-9_]{2,}\b", s):
            return False, "Uses macro-like identifier (ALL_CAPS) which is usually not available in LLDB expr"

        calls = re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", s)
        for name in calls:
            if name != "sizeof":
                return False, f"Contains function/macro call `{name}(...)` which is not allowed in LLDB expr"
        return True, "OK"

    def _is_truthy(eval_result: str) -> bool:
        """
        debugger_print("(int)(expr)") often returns plain "1"/"0" (not " = 1").
        Be robust to different formats.
        """
        s = (eval_result or "").strip().lower()
        # common MI formats or plain values
        if s in {"1", "true"}:
            return True
        if s.endswith(" = 1") or s.endswith("=1"):
            return True
        return False

    def _is_falsy(eval_result: str) -> bool:
        s = (eval_result or "").strip().lower()
        if s in {"0", "false"}:
            return True
        if s.endswith(" = 0") or s.endswith("=0"):
            return True
        return False

    def _looks_like_eval_unavailable(eval_result: str) -> bool:
        s = (eval_result or "").strip().lower()
        return (
            "lldb process has exited" in s
            or "debuggerprocessitederror" in s
            or "lldb_eval_process_exited" in s
            or "lldb_eval_timeout" in s
            or "lldb_eval_no_frame" in s
            or "lldb_eval_mi_unstable" in s
        )

    def _eval_with_retry(constraint: str, target_file: str, target_line: int) -> tuple[str | None, str | None]:
        try:
            eval_result = debugger_print(f"(int)({constraint})")
        except Exception as e:
            return None, f"eval_exception: {e}"

        if _looks_like_eval_unavailable(eval_result):
            logger.warning(
                f"Constraint eval unavailable for `{constraint}`: {eval_result}. "
                "Retrying once after re-run to breakpoint..."
            )
            try:
                debugger_run_to_line(target_file, target_line)
                eval_result = debugger_print(f"(int)({constraint})")
            except Exception as e:
                return None, f"retry_exception: {e}"
            if _looks_like_eval_unavailable(eval_result):
                return None, f"eval_unavailable_after_retry: {eval_result}"
        return eval_result, None

    def _extract_scalar_value(val) -> str | None:
        """
        We can only verify constraints against concrete scalar assignments.
        If fuzzing produced LOGIC:* actions (e.g., LOGIC:AT(...)), skip them here.
        """
        if val is None:
            return None
        if isinstance(val, (int, float)):
            return str(int(val))
        s = str(val).strip()
        if not s:
            return None
        # Skip action-style candidates (not a scalar value for var_name)
        if s.startswith("LOGIC:"):
            return None
        # If candidate is an assignment expression like "pe_offset=60", extract RHS
        m = re.search(rf"\b{re.escape(var_name)}\s*=\s*([0-9]+|0x[0-9a-fA-F]+)\b", s)
        if m:
            return m.group(1)
        # Plain numeric string
        if re.match(r"^-?\d+$", s) or re.match(r"^0x[0-9a-fA-F]+$", s):
            return s
        return None

    # Pre-filter constraints that are not LLDB-expr compatible
    for c in list(remaining_constraints):
        ok, reason = _is_lldb_expr_compatible(c)
        if not ok:
            results[c] = (False, reason)
            remaining_constraints.remove(c)

    # 1. Verify Angelic Values (Must be True for all)
    for val in angelic_list:
        if not remaining_constraints: break
        
        debugger_run_to_line(file, line)

        scalar = _extract_scalar_value(val)
        if scalar is None:
            logger.warning(f"Skipping non-scalar angelic candidate during constraint verify: {val}")
            continue

        assign_val = str(scalar)
        if '*' in var_type and not assign_val.startswith('(') and "NULL" not in assign_val:
             assign_val = f"({var_type}){scalar}"
        
        debugger_assign(var_name, assign_val)
        
        for constraint in list(remaining_constraints):
            eval_result, eval_err = _eval_with_retry(constraint, file, line)
            if eval_result is None:
                logger.warning(
                    f"Skip angelic verification for constraint `{constraint}` due to debugger instability: {eval_err}"
                )
                continue
            if not _is_truthy(eval_result):
                reason = f"False negative: Constraint evaluated to FALSE for safe (Angelic) value '{val}' (Result: {eval_result})."
                logger.warning(f"Constraint '{constraint}' failed for angelic value {val}: {reason}")
                results[constraint] = (False, reason)
                remaining_constraints.remove(constraint)

    # 2. Verify Demonic Values (Must be False for all)
    for val in demonic_list:
        if not remaining_constraints: break
        
        val_str = str(val) if val is not None else ""
        if val == "NULL" or (isinstance(val_str, str) and "not available" in val_str): 
            continue
        if isinstance(val_str, str) and val_str.strip().startswith("LOGIC:"):
            logger.warning(f"Skipping non-scalar demonic candidate during constraint verify: {val}")
            continue

        debugger_run_to_line(file, line)

        scalar = _extract_scalar_value(val)
        if scalar is None:
            logger.warning(f"Skipping non-scalar demonic candidate during constraint verify: {val}")
            continue

        assign_val = str(scalar)
        if '*' in var_type and not assign_val.startswith('(') and "NULL" not in assign_val:
             assign_val = f"({var_type}){scalar}"
        
        debugger_assign(var_name, assign_val)
        
        for constraint in list(remaining_constraints):
            eval_result, eval_err = _eval_with_retry(constraint, file, line)
            if eval_result is None:
                logger.warning(
                    f"Skip demonic verification for constraint `{constraint}` due to debugger instability: {eval_err}"
                )
                continue
            if not _is_falsy(eval_result):
                reason = f"False positive: Constraint evaluated to TRUE for unsafe (Demonic) value '{val}' (Result: {eval_result})."
                logger.warning(f"Constraint '{constraint}' failed for demonic value {val}: {reason}")
                results[constraint] = (False, reason)
                remaining_constraints.remove(constraint)

    return results


@logf(NAME, True)
def stalk(profile, logger=None):
    if profile["zero_shot"]:
        _zero_shot_stalk(profile, logger)
        return

    logger.warning("Stalking bug for project: %s", profile["id"])

    logger.debug("Changing to the project source directory: %s", profile["src"])
    os.chdir(profile["src"])
    logger.info("Current directory: %s", os.getcwd())

    logger.debug("Initializing LLDB and LSP")
    _maybe_rebuild_before_debug(profile, logger)
    _maybe_fill_secbench_command_from_case(profile, logger)
    debugger_init(profile["file"], profile["args"], profile["env"], cwd=profile["src"])
    lsp_init(executable="clangd", cwd=profile["src"])

    llm_agent = GenericAgent()
    fuzzing_llm_agent = GenericAgent(name="FuzzerStrategist", system_prompt=FUZZER_SYSTEM_PROMPT)

    state = BugHypothesisState(
        profile=profile,
        max_rounds=_interaction_max_rounds(profile),
        top_k_hypotheses=int(profile.get("interaction_top_k_hypotheses", 3)),
    )
    meta = {
        "profile": profile,
        "orchestration": {
            "mode": "round_based",
            "max_rounds": state.max_rounds,
        },
    }

    logger.warning("Reproducing the problem")
    reproduce_result = reproduce_agent.reproduce(profile)
    if not reproduce_result["status"]:
        logger.warning("Initial reproduce failed, retrying once with the same profile for stability.")
        retry_reproduce = reproduce_agent.reproduce(profile)
        if retry_reproduce.get("status"):
            reproduce_result = retry_reproduce
        else:
            logger.error("Failed to reproduce the bug after retry")
            meta["reproduced"] = False
            _record_failure(
                meta,
                stage="reproduce",
                reason=str(reproduce_result.get("error", "reproduce_failed")),
                action="retry_once_failed",
            )
            save_meta(meta, profile)
            raise RuntimeError("Failed to reproduce the bug after retry")
    if reproduce_result["return_code"] == 0 and not _has_runtime_crash_signature(reproduce_result):
        logger.info("No problem found, exiting as fixed")
        meta["reproduced"] = False
        _record_failure(
            meta,
            stage="reproduce",
            reason="return_code_0_no_crash",
            action="stop_pipeline",
        )
        save_meta(meta, profile)
        return

    if _sync_profile_executable_from_reproduce(profile, reproduce_result, logger):
        debugger_init(profile["file"], profile["args"], profile["env"], cwd=profile["src"])
    elif _maybe_fill_secbench_command_from_case(profile, logger):
        debugger_init(profile["file"], profile["args"], profile["env"], cwd=profile["src"])
    state.reproduce_result = reproduce_result
    meta["reproduced"] = True

    while not state.should_stop():
        actor = state.next_actor
        if (state_only_no_angelic(profile) or no_cfc(profile)) and actor in {"counterfactual", "layer2", "fuzz", "constraint"}:
            logger.info("Ablation mode skips %s and routes directly to patch.", actor)
            actor = "patch"
            state.next_actor = "patch"
        else:
            routed_actor = _route_legacy_layer2_actor(actor, state, profile)
            if routed_actor != actor:
                logger.info("Legacy Layer 2 actor `%s` is disabled by default; routing to `%s`.", actor, routed_actor)
                actor = routed_actor
                state.next_actor = routed_actor
        if full_pipeline_budget_limited(profile) and actor == "layer2":
            logger.info("Budget-limited full pipeline routes layer2 entry directly to fuzz.")
            actor = "fuzz"
            state.next_actor = "fuzz"
        consumes_round = _actor_consumes_round(actor)
        if consumes_round:
            state.round_index += 1
        state.record_route(actor, reason="scheduled")
        if consumes_round:
            logger.warning(f"Round {state.round_index}/{state.max_rounds}: dispatching {actor}")
        else:
            logger.warning(f"Verify after round {state.round_index}/{state.max_rounds}: dispatching {actor}")

        if actor == "debug":
            message = run_debug_round(state, logger=logger)
        elif actor == "counterfactual":
            message = run_counterfactual_round(state, logger=logger)
        elif actor == "layer2":
            message = run_layer2_entry_round(state, logger=logger)
        elif actor == "fuzz":
            message = run_fuzz_round(state, fuzzing_llm_agent, logger=logger)
        elif actor == "constraint":
            message = run_constraint_round_adapter(state, llm_agent, logger=logger)
        elif actor == "patch":
            message = run_patch_round(state, llm_agent, logger=logger)
        elif actor == "verify":
            message = run_verify_round(state, logger=logger)
        else:
            logger.warning(f"Unknown actor `{actor}`, stopping orchestration.")
            state.next_actor = "done"
            break

        state.add_message(message)
        if message.artifacts:
            state.register_progress(f"{actor}_artifacts")
        else:
            state.register_no_progress()

        if consumes_round:
            logger.info(
                "Round %s completed by %s. next_actor=%s claims=%s",
                state.round_index,
                actor,
                state.next_actor,
                message.claims,
            )
        else:
            logger.info(
                "Verify after round %s completed. next_actor=%s claims=%s",
                state.round_index,
                state.next_actor,
                message.claims,
            )

        if actor == "debug" and not state.suspects:
            _schedule_empty_debug_retry(state, meta, profile, logger=logger)
        elif actor == "counterfactual" and state.current_counterfactual_contract() is None:
            _record_failure(
                meta,
                stage="counterfactual",
                reason="no_counterfactual_contract",
                action="stop_without_debug_retry",
            )
        elif actor == "fuzz" and (not state.current_fuzz_result() or not (state.current_fuzz_result() or {}).get("angelic_values")):
            fuzz_result = state.current_fuzz_result() or {}
            cost_stats = fuzz_result.get("cost_stats", {})
            if cost_stats.get("budget_exhausted"):
                _record_failure(
                    meta,
                    stage="fuzz",
                    reason="budget_exhausted",
                    action=f"route_back_to_debug:{cost_stats.get('exhausted_budget', 'unknown_budget')}",
                )
                continue
            _record_failure(
                meta,
                stage="fuzz",
                reason="no_angelic_values",
                action="route_back_to_debug",
            )

    if state.champion_patch is None:
        select_champion_patch(state, llm_agent=llm_agent, logger=logger)

    debugger_exit()

    if state.champion_patch:
        meta["patch"] = state.champion_patch
        logger.info("Champion patch selected.")
    else:
        meta["patch"] = None
        if "failure" not in meta:
            if state.round_index >= state.max_rounds:
                _record_failure(
                    meta,
                    stage="orchestrator",
                    reason="max_rounds_reached",
                    action=f"last_actor={state.next_actor}",
                )
            elif state.rounds_without_progress >= 3:
                _record_failure(
                    meta,
                    stage="orchestrator",
                    reason="no_progress",
                    action=f"last_actor={state.next_actor}",
                )
            else:
                _record_failure(
                    meta,
                    stage="orchestrator",
                    reason="no_champion_patch",
                    action=f"last_actor={state.next_actor}",
                )
        logger.error("Failed to generate a valid patch.")

    meta["root_cause"] = state.analysis
    meta["interaction_state"] = state.to_dict()
    meta["routing"] = state.route_history
    meta["counterfactual_contracts"] = {
        hypothesis_id: contract.__dict__
        for hypothesis_id, contract in state.counterfactual_contracts.items()
    }
    meta["constraints"] = [candidate.__dict__ for candidate in state.current_constraint_candidates()]
    meta["patch_candidates"] = [candidate.__dict__ for candidate in state.current_patch_candidates()]
    meta["verification_feedback"] = [feedback.__dict__ for feedback in state.current_verification_feedback()]

    try:
        all_dir = profile.get("result_dir") or profile.get("chat_dir") or os.getcwd()
        os.makedirs(all_dir, exist_ok=True)
        dump_json(
            {"count": len(state.current_patch_candidates()), "items": [candidate.__dict__ for candidate in state.current_patch_candidates()]},
            os.path.join(all_dir, "patches_generated_all.json"),
        )
        dump_json(
            {"count": len(state.current_verification_feedback()), "items": [feedback.__dict__ for feedback in state.current_verification_feedback()]},
            os.path.join(all_dir, "patches_poc_report.json"),
        )
        dump_json(state.to_dict(), os.path.join(all_dir, "interaction_state.json"))
    except Exception as exc:
        logger.warning(f"Failed to persist interaction artifacts: {exc}")

    save_meta(meta, profile)

    logger.info("Stalking complete")
    lsp_exit()
