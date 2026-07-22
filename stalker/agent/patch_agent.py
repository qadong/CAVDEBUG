import json
import hashlib
import os
import re
import shutil
from typing import List, Tuple
from agent.generic_agent import GenericAgent
from utils.parsers import parse_sanitizer_output, check_sanitizer_error, parse_patch_string
from utils.files import dump_json
from utils.patch_export import export_patch_artifacts
from utils.seed_records import demonic_seed_records
from utils.ablation import PATCH_SEARCH_BUDGET_RETRIES, lldb_only, patch_search_budget_limited, state_only_no_angelic
from utils.bug_context import format_bug_context
from utils.verification import verify_patch_feedback
from tools.file.functions import (
    file_apply_patches,
    file_get_content,
    file_get_decorated_content,
    file_undo_patches,
)
from tools.lsp.functions import (
    lsp_get_function,
    lsp_get_symbol_definition,
    lsp_get_symbol_summary,
    lsp_to_abs_path,
)
from tools.debugger.driver import debugger_instance
from tools.debugger.functions import (
    debugger_assign,
    debugger_assign_expression,
    debugger_continue,
    debugger_get_tracked_breakpoint_hit_count,
    debugger_print,
    debugger_read_memory,
    debugger_run_to_line,
    debugger_backtrace,
    debugger_list_breakpoints,
)
from utils.logger import get_logger, logf


NAME = "agent-patch"
MAX_RETRIES = 5
STATE_ONLY_NO_ANGELIC_MAX_RETRIES = PATCH_SEARCH_BUDGET_RETRIES
MAX_PATCH_CHAT_SLUG = 80
LLDB_ONLY_BLOCKED_TERMS = (
    "angelic",
    "demonic",
    "counterfactual",
    "constraint",
    "challenger",
    "invariant",
    "repair_invariant",
    "preferred_edit_location",
    "active_patch_location",
    "forced_patch_strategy",
    "patchability_score",
    "preferred_repair_stage",
    "forbidden_repair_stages",
    "location_groups",
)

from agent.prompts import (
    PATCH_SYSTEM_PROMPT as SYSTEM_PROMPT,
    PATCH_INITIAL_PROMPT as INITIAL_PROMPT,
    PATCH_SYSTEM_PROMPT_LLDB_ONLY as SYSTEM_PROMPT_LLDB_ONLY,
    PATCH_INITIAL_PROMPT_LLDB_ONLY as INITIAL_PROMPT_LLDB_ONLY,
    build_debugger_session_protocol,
)
from agent.type_angelic import build_stage_prompt_overlay, infer_bug_type_profile

# =============================================================================
# Agent hooks
# =============================================================================


def _safe_patch_chat_filename(constraint: str) -> str:
    text = str(constraint or "unknown")
    digest = hashlib.sha1(text.encode("utf-8", errors="ignore")).hexdigest()[:12]
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", text).strip("._-")
    if not slug:
        slug = "constraint"
    slug = slug[:MAX_PATCH_CHAT_SLUG].rstrip("._-")
    return f"patch_{slug}_{digest}.json"


def _active_retry_limit() -> int:
    session = GLOBAL_STATE.get("session")
    profile = getattr(getattr(session, "_input", None), "profile", None)
    if patch_search_budget_limited(profile):
        return PATCH_SEARCH_BUDGET_RETRIES
    return MAX_RETRIES


def _sanitize_lldb_only_value(value):
    if isinstance(value, dict):
        out = {}
        for key, nested in value.items():
            key_text = str(key)
            key_lower = key_text.lower()
            if any(term in key_lower for term in LLDB_ONLY_BLOCKED_TERMS):
                continue
            out[key_text] = _sanitize_lldb_only_value(nested)
        return out
    if isinstance(value, list):
        return [_sanitize_lldb_only_value(item) for item in value]
    if isinstance(value, tuple):
        return [_sanitize_lldb_only_value(item) for item in value]
    text = str(value)
    lower = text.lower()
    if any(term in lower for term in LLDB_ONLY_BLOCKED_TERMS):
        return "[filtered non-LLDB-only label]"
    return value

# For the agent hook, only one debug session at a time.
# Global state
GLOBAL_STATE = {
    "session": None,
    "patches": None,
    "resign": False,
    "retry": 0,
    "valid": False,
    "strategy": None,
}


def reset_global_state():
    global GLOBAL_STATE
    GLOBAL_STATE = {
        "session": None,
        "patches": None,
        "resign": False,
        "retry": 0,
        "valid": False,
        "strategy": None,
    }


# @logf(NAME, True)
def definition(file: str, line: int, symbol: str) -> str:
    """
    Get the definition of a symbol in the code.
    """
    get_logger(NAME).info(f"Invoking definition({file}, {line}, {symbol})")

    file = lsp_to_abs_path(str(file))
    line = int(line)
    symbol = str(symbol)

    response = lsp_get_symbol_definition(file, line, symbol)
    get_logger(NAME).debug(response)

    return response


# @logf(NAME, True)
def summary(file: str, line: int, symbol: str) -> str:
    """
    Get the hover information of a symbol at a given position.
    """
    get_logger(NAME).info(f"Invoking summary({file}, {line}, {symbol})")

    file = lsp_to_abs_path(str(file))
    line = int(line)
    symbol = str(symbol)

    response = lsp_get_symbol_summary(file, line, symbol)
    get_logger(NAME).debug(response)

    return response


# @logf(NAME, True)
def function_body(file: str, function: str) -> str:
    """
    Get the complete definition of a function.
    """
    get_logger(NAME).info(f"Invoking function_body({file}, {function})")

    file = lsp_to_abs_path(str(file))
    function = str(function)

    response = lsp_get_function(file, function)
    get_logger(NAME).debug(response)

    return response


# @logf(NAME, True)
def file_content(file: str, start_line: int, end_line: int) -> str:
    """
    Get the content of a file.
    """
    get_logger(NAME).info(f"Invoking file_content({file}, {start_line}, {end_line})")

    file = lsp_to_abs_path(str(file))
    start_line = int(start_line)
    end_line = int(end_line)

    response = file_get_decorated_content(file, start_line, end_line)
    get_logger(NAME).debug(response)

    return response


def search_in_repo(pattern: str, path: str = None, max_hits: int = 20, context: int = 2) -> str:
    """
    Search for a symbol/pattern in a file or directory and return matching lines with small context.
    Use this to find a necessary companion edit after checking the preferred edit location first.
    """
    logger = get_logger(NAME)
    logger.info(f"Invoking search_in_repo({pattern}, {path}, {max_hits}, {context})")

    search_root = lsp_to_abs_path(str(path)) if path else os.path.dirname(GLOBAL_STATE["session"]._input.suspect_object.get("file", ""))
    if not search_root or not os.path.exists(search_root):
        return f"Error: Path not found for search: {path} (resolved to: {search_root})"

    try:
        max_hits_i = max(1, int(max_hits))
    except Exception:
        max_hits_i = 20
    try:
        ctx_i = max(0, int(context))
    except Exception:
        ctx_i = 2

    source_exts = {
        ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx",
        ".inl", ".inc", ".ipp", ".m", ".mm", ".s", ".S",
    }

    def iter_candidate_files(root: str):
        if os.path.isfile(root):
            yield root
            return
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [
                dirname for dirname in dirnames
                if dirname not in {".git", "build", "cmake-build-debug", "cmake-build-release", "__pycache__"}
            ]
            for filename in sorted(filenames):
                file_path = os.path.join(dirpath, filename)
                _, ext = os.path.splitext(filename)
                if ext in source_exts or filename in {"Makefile", "CMakeLists.txt"}:
                    yield file_path

    try:
        try:
            rx = re.compile(str(pattern))
        except re.error:
            rx = re.compile(re.escape(str(pattern)))

        out = [f"Search path: {search_root}", f"Pattern: {pattern}", f"Showing up to {max_hits_i} matches", ""]
        total_hits = 0
        for file_path in iter_candidate_files(search_root):
            try:
                with open(file_path, "r", errors="ignore") as f:
                    lines = f.readlines()
            except Exception:
                continue

            hits = []
            for idx, line in enumerate(lines, start=1):
                if rx.search(line):
                    hits.append(idx)
                    total_hits += 1
                    if total_hits >= max_hits_i:
                        break

            for h in hits:
                start = max(1, h - ctx_i)
                end = min(len(lines), h + ctx_i)
                out.append(f"--- {file_path}:{h} ---")
                for ln in range(start, end + 1):
                    prefix = ">>" if ln == h else "  "
                    out.append(f"{prefix} L{ln}: {lines[ln - 1].rstrip()}")
                out.append("")

            if total_hits >= max_hits_i:
                break

        if total_hits == 0:
            return f"No matches for pattern '{pattern}' under {search_root}"

        out.insert(2, f"Hits: {total_hits}")
        response = "\n".join(out).strip()
        logger.debug(response)
        return response
    except Exception as exc:
        logger.error(f"search_in_repo failed: {exc}")
        return f"Error during search_in_repo: {exc}"


def _tail_lines(text: str, max_lines: int = 50, max_chars: int = 5000) -> str:
    if not text or not str(text).strip():
        return "(no runtime output captured)"
    lines = [line for line in str(text).strip().splitlines() if line.strip()]
    out = "\n".join(lines[-max_lines:])
    if len(out) > max_chars:
        out = "..." + out[-max_chars:]
    return out


def _first_failed_replay(details: dict) -> tuple[str, dict]:
    tiers = details.get("tiers") if isinstance(details.get("tiers"), dict) else {}
    for name in ("tier3_regression", "tier2_variants", "tier1_primary"):
        report = tiers.get(name)
        if not isinstance(report, dict):
            continue
        if name == "tier1_primary" and report.get("return_code") not in (None, 0):
            return name, report
        for item in report.get("items", []) or []:
            if isinstance(item, dict) and item.get("status") != "pass":
                return name, item
    return "", {}


def _format_patch_feedback_for_retry(feedback: dict) -> str:
    message = str(feedback.get("message", "") or "Patch verification failed.")
    details = feedback.get("details") if isinstance(feedback.get("details"), dict) else {}
    replay_failure = feedback.get("replay_failure") if isinstance(feedback.get("replay_failure"), dict) else {}
    tier_name = ""
    if not replay_failure:
        tier_name, replay_failure = _first_failed_replay(details)

    runtime_output = (
        feedback.get("runtime_output")
        or replay_failure.get("runtime_output")
        or replay_failure.get("error")
        or ""
    )
    if not replay_failure and not runtime_output:
        return message

    parts = [message, "\nVerification failure context for the next patch attempt:"]
    if tier_name:
        parts.append(f"- Failed replay tier: {tier_name}")
    status = feedback.get("status") or replay_failure.get("status")
    if status:
        parts.append(f"- Verification status: {status}")
    if feedback.get("blame_hint"):
        parts.append(f"- Blame hint: {feedback.get('blame_hint')}")
    if replay_failure.get("args"):
        parts.append(f"- Failing replay args: {replay_failure.get('args')}")
    if replay_failure.get("command"):
        parts.append(f"- Failing command: {replay_failure.get('command')}")
    if replay_failure.get("return_code") is not None:
        parts.append(f"- Return code: {replay_failure.get('return_code')}")
    if replay_failure.get("file") or replay_failure.get("line"):
        parts.append(f"- Failure location: {replay_failure.get('file', 'N/A')}:{replay_failure.get('line', 'N/A')}")
    if runtime_output:
        parts.append("\nLast 50 lines of failing replay output:\n```\n" + _tail_lines(str(runtime_output), max_lines=50) + "\n```")
    return "\n".join(parts)


def check_patch() -> Tuple[bool, str]:
    """
    Apply the patches, compile, and run reproduction.
    Returns (success, message).
    """
    logger = get_logger(NAME)
    global GLOBAL_STATE
    patches = GLOBAL_STATE["patches"]
    session_input = GLOBAL_STATE["session"]._input
    suspect = session_input.suspect_object or {}
    strategy = GLOBAL_STATE["strategy"] or _infer_patch_strategy(
        session_input.constraint,
        suspect,
    )

    patch_contract = {
        "patches": patches,
        "profile": session_input.profile,
        "constraint": session_input.constraint,
        "hypothesis_summary": suspect.get("debug_summary", ""),
        "suspect_file": suspect.get("file", ""),
        "suspect_line": suspect.get("line", -1),
        "function_name": suspect.get("function_name", ""),
        "bug_type_profile": suspect.get("bug_type_profile", {}) or {},
        "typed_angelic_evidence": suspect.get("typed_angelic_evidence", {}) or {},
        "counterfactual_contract": suspect.get("counterfactual_contract", {}) or {},
        "root_cause_report": suspect.get("root_cause_report", {}) or {},
        "llm_verifier_enabled": session_input.profile.get("llm_verifier_enabled", True),
        "repair_layer": "layer1",
    }
    patch_contract.update(strategy)

    try:
        logger.info("Running patch verification...")
        feedback = verify_patch_feedback(
            patch_contract,
            expected_file=patch_contract.get("suspect_file"),
            expected_line=patch_contract.get("suspect_line"),
            logger=logger,
        )
        return feedback.get("status") == "pass", _format_patch_feedback_for_retry(feedback)
    except Exception as e:
        logger.error(f"Exception during patch check: {e}")
        return False, str(e)


# @logf(NAME, True)
def submit(patches: List[str]) -> str:
    """
    Submit the analysis.
    """
    logger = get_logger(NAME)

    logger.info(f"Invoking submit({patches})")

    global GLOBAL_STATE
    if GLOBAL_STATE["valid"] and GLOBAL_STATE["patches"] is not None:
        return (
            "A patch has already passed verification in this patch session. "
            "Your task is complete. You MUST reply with TERMINATE."
        )

    MSG_INVALID_RESPONSE = (
        "Invalid patch format, "
        "please provide the patch in the format of <filename>:<start line>-<end line>\\n<patch content>. "
        "It means to replace the content from the start line to the end line (both inclusive) with the patch content."
    )

    parsed_patches = []
    for raw_patch in patches:
        file, start_line, end_line, patch = parse_patch_string(raw_patch)
        if file is None:
            logger.error(f"Invalid patch format: {raw_patch}")
            return MSG_INVALID_RESPONSE
        parsed_patches.append(
            {
                "file": file,
                "start_line": start_line,
                "end_line": end_line,
                "patch": patch,
            }
        )

    GLOBAL_STATE["patches"] = parsed_patches

    status, message = check_patch()
    if status:
        logger.info("Patch successfully fixed the crash")
        GLOBAL_STATE["valid"] = True
        GLOBAL_STATE["resign"] = False
        return (
            "Patch successfully fixed the crash. "
            f"Verifier message: {message}\n"
            "Your task is complete. You MUST reply with TERMINATE."
        )

    retry_limit = _active_retry_limit()
    GLOBAL_STATE["valid"] = False
    GLOBAL_STATE["retry"] += 1
    if GLOBAL_STATE["retry"] < retry_limit:
        logger.warning(f"Invalid patch, retry {GLOBAL_STATE['retry']}/{retry_limit} scheduled")
        return (
            "Patch failed to fix the crash. The failed patch has already been reverted, so the source tree is back to the pre-submit state. "
            "Do NOT resign. Stay in the current analysis context and refine the previous patch idea instead of restarting diagnosis from scratch. "
            "If you need to inspect code again, remember the file content on disk no longer contains the failed patch. "
            "The error message is as follows:\n"
            f"{message}"
        )

    # Failed after retry_limit retries - set resign flag and return failure message
    logger.error(f"Failed to fix the crash after {retry_limit} retries. Setting resign flag.")
    GLOBAL_STATE["resign"] = True
    return (
        f"Patch failed to fix the crash after {retry_limit} attempts. "
        f"Unable to provide a working patch. Only now may you call `resign` to skip this constraint. "
        f"The error message from the last attempt:\n{message}"
    )


# @logf(NAME, True)
def resign() -> None:
    """
    Resign from the current round.
    """
    get_logger(NAME).info(f"Invoking resign")
    global GLOBAL_STATE
    if GLOBAL_STATE["valid"] and GLOBAL_STATE["patches"] is not None:
        get_logger(NAME).info("Ignoring resign because a patch already passed verification")
        return
    GLOBAL_STATE["resign"] = True


def _infer_patch_strategy(constraint: str, suspect_object: dict) -> dict:
    forced_strategy = suspect_object.get("forced_patch_strategy")
    if isinstance(forced_strategy, dict) and forced_strategy.get("strategy"):
        strategy = str(forced_strategy.get("strategy"))
        location_type = str(forced_strategy.get("location_type", "same_site"))
        semantic_risk = str(forced_strategy.get("semantic_risk", "medium"))
        return {
            "strategy": strategy,
            "location_type": location_type,
            "rationale": str(forced_strategy.get("rationale", "Forced strategy override from orchestrator.")),
            "semantic_risk": semantic_risk,
            "requires_regression_check": semantic_risk == "high",
        }
    text = " ".join(
        [
            str(constraint),
            str(suspect_object.get("debug_summary", "")),
            str(suspect_object.get("repair_intent", "")),
            str(suspect_object.get("mechanism_hint", "")),
        ]
    ).lower()
    previous_failure = str(suspect_object.get("last_verification_status", "")).lower()
    strategy = "bounds_check_before_access"
    location_type = "same_site"
    semantic_risk = "medium"
    if any(word in text for word in ("alloc", "malloc", "calloc", "realloc")):
        strategy = "allocation_size_fix"
        location_type = "upstream"
    elif any(word in text for word in ("loop", "while", "for ", "infinite")):
        strategy = "loop_bound_fix"
    elif any(word in text for word in ("null", "lifetime", "free", "dangling")):
        strategy = "null_or_lifetime_guard"
    elif any(word in text for word in ("offset", "len", "length", "size", "count", "end", "base")):
        strategy = "fix_upstream_invariant"
        location_type = "upstream"
    elif any(word in text for word in ("invalid input", "malformed", "parse", "format")):
        strategy = "reject_invalid_input"
    if previous_failure in {"semantic_regression", "overfit_poc"}:
        if strategy in {"bounds_check_before_access", "reject_invalid_input", "null_or_lifetime_guard"}:
            strategy = "fix_upstream_invariant" if any(
                word in text for word in ("offset", "len", "length", "size", "count", "end", "base")
            ) else "clamp_or_normalize"
        location_type = "upstream"
        semantic_risk = "low"
    if "return" in text and strategy in {"reject_invalid_input", "bounds_check_before_access"}:
        semantic_risk = "high"
    if strategy in {"fix_upstream_invariant", "allocation_size_fix", "loop_bound_fix"}:
        semantic_risk = "low"
    return {
        "strategy": strategy,
        "location_type": location_type,
        "rationale": (
            "Shifted toward lower-risk upstream repair after replay failure."
            if previous_failure in {"semantic_regression", "overfit_poc"}
            else "Inferred from constraint/root-cause terms."
        ),
        "semantic_risk": semantic_risk,
        "requires_regression_check": semantic_risk == "high",
    }


def _rank_patch_strategies(constraint: str, suspect_object: dict) -> list[dict]:
    text = " ".join(
        [
            str(constraint),
            str(suspect_object.get("debug_summary", "")),
            str(suspect_object.get("repair_intent", "")),
            str(suspect_object.get("mechanism_hint", "")),
            " ".join(str(v) for v in suspect_object.get("top_angelic_examples", [])[:3]),
        ]
    ).lower()
    previous_failure = str(suspect_object.get("last_verification_status", "")).lower()
    constraint_status = str(suspect_object.get("constraint_status", "")).lower()
    mechanism_hint = str(suspect_object.get("mechanism_hint", "")).lower()
    bug_type = str((suspect_object.get("bug_type_profile") or {}).get("bug_type", "unknown")).lower()
    scored: list[tuple[int, dict]] = []

    def add(strategy: str, location_type: str, rationale: str, semantic_risk: str, score: int) -> None:
        scored.append(
            (
                score,
                {
                    "strategy": strategy,
                    "location_type": location_type,
                    "rationale": rationale,
                    "semantic_risk": semantic_risk,
                    "requires_regression_check": semantic_risk == "high",
                },
            )
        )

    add("bounds_check_before_access", "same_site", "Default local repair around the dereference/use site.", "medium", 40)
    if any(word in text for word in ("offset", "len", "length", "size", "count", "end", "base")):
        add("fix_upstream_invariant", "upstream", "Constraint looks relational; prefer repairing the invariant before the crash site.", "low", 90)
        add("clamp_or_normalize", "upstream", "Size/offset constraint can often be normalized before use.", "low", 75)
    if any(word in text for word in ("invalid input", "malformed", "parse", "format")):
        add("reject_invalid_input", "upstream", "Parser-style failures often map to explicit input rejection.", "medium", 70)
    if any(word in text for word in ("alloc", "malloc", "calloc", "realloc")):
        add("allocation_size_fix", "upstream", "Allocation/use mismatch suggests repairing allocation sizing.", "low", 85)
    if any(word in text for word in ("loop", "while", "for ", "infinite")):
        add("loop_bound_fix", "upstream", "Loop-related crash suggests bound correction earlier in control flow.", "low", 80)
    if any(word in text for word in ("null", "dangling", "lifetime", "free")):
        add("null_or_lifetime_guard", "upstream", "Pointer/lifetime failures often need validity checks before use.", "medium", 72)
    if mechanism_hint == "memory_init":
        add("fix_upstream_invariant", "upstream", "Angelic evidence points to restoring initialization coverage before use.", "low", 96)
        add("allocation_size_fix", "upstream", "Initialization-focused evidence can indicate partial clearing or sizing mismatch.", "low", 88)
    elif mechanism_hint == "ownership_reset":
        add("null_or_lifetime_guard", "upstream", "Evidence suggests resetting ownership or preventing repeated release.", "low", 94)
        add("fix_upstream_invariant", "upstream", "Ownership evidence often maps to upstream transfer or release invariants.", "low", 84)
    elif mechanism_hint == "bounds_normalization":
        add("fix_upstream_invariant", "upstream", "Evidence suggests restoring the upstream bound invariant.", "low", 94)
        add("clamp_or_normalize", "upstream", "Bounds-normalization evidence supports constrained normalization.", "low", 86)
    elif mechanism_hint == "branch_suppression":
        add("reject_invalid_input", "upstream", "Evidence suggests the unsafe branch should be rejected earlier.", "medium", 82)

    if bug_type == "out_of_bounds":
        add("fix_upstream_invariant", "upstream", "Out-of-bounds bugs usually require restoring a bound relation earlier than the crash access.", "low", 97)
        add("loop_bound_fix", "upstream", "Out-of-bounds accesses often come from loop or iteration boundary mistakes.", "low", 90)
        add("reject_invalid_input", "upstream", "Malformed lengths or indexes are often best rejected where parsed.", "medium", 84)
    elif bug_type == "integer_overflow":
        add("allocation_size_fix", "upstream", "Overflow bugs often need allocation-size or arithmetic-precondition repair before use.", "low", 98)
        add("fix_upstream_invariant", "upstream", "Arithmetic preconditions should be restored before the overflowing computation is consumed.", "low", 92)
    elif bug_type == "null_dereference":
        add("null_or_lifetime_guard", "upstream", "Null dereference bugs often need caller/callee contract or initialization repair around pointer validity.", "medium", 90)
        add("fix_upstream_invariant", "upstream", "If NULL is illegal, earlier initialization or state restoration is usually better than a crash-site guard.", "low", 88)
        add("reject_invalid_input", "upstream", "If the API forbids NULL, invalid input or call-path rejection may be correct.", "medium", 78)
    elif bug_type == "invalid_pointer":
        add("fix_upstream_invariant", "upstream", "Invalid pointers often require repairing provenance, offset, or source state before dereference.", "low", 96)
        add("clamp_or_normalize", "upstream", "If the pointer comes from pointer arithmetic, normalize the offset/base relation earlier.", "low", 82)
    elif bug_type == "use_after_free":
        add("fix_upstream_invariant", "upstream", "Use-after-free bugs usually need ownership or lifetime restoration before the stale use.", "low", 99)
        add("null_or_lifetime_guard", "upstream", "Lifetime-aware guards can be useful when they encode a real released-state contract.", "medium", 85)
    elif bug_type == "double_free":
        add("fix_upstream_invariant", "upstream", "Double free bugs usually come from ownership/cleanup policy mistakes, not just one local guard.", "low", 98)
        add("null_or_lifetime_guard", "upstream", "Pointer-state cleanup may help if it reflects the actual ownership contract.", "medium", 80)
    elif bug_type == "invalid_free":
        add("fix_upstream_invariant", "upstream", "Invalid free bugs usually require repairing ownership or allocation-origin semantics.", "low", 97)
        add("null_or_lifetime_guard", "upstream", "A guard may help if it distinguishes owned base pointers from borrowed or offset pointers.", "medium", 76)
    elif bug_type == "uninitialized_use":
        add("fix_upstream_invariant", "upstream", "Uninitialized-use bugs usually require restoring initialization coverage or object invariants before use.", "low", 99)
        add("allocation_size_fix", "upstream", "Partial clearing can also be a sizing or coverage mistake in initialization logic.", "low", 86)
    elif bug_type == "assertion_failure":
        add("fix_upstream_invariant", "upstream", "Assertion failures usually indicate a broken state-machine or contract invariant earlier in the path.", "low", 95)
        add("reject_invalid_input", "upstream", "If malformed input drives the bad state, reject it before violating the invariant.", "medium", 82)
    elif bug_type == "divide_by_zero":
        add("reject_invalid_input", "upstream", "Divide-by-zero often maps to rejecting or guarding illegal arithmetic inputs before the operation.", "low", 94)
        add("clamp_or_normalize", "upstream", "If the denominator is derived from user data, normalize it before arithmetic.", "medium", 78)
    elif bug_type == "stack_overflow":
        add("loop_bound_fix", "upstream", "Stack-overflow bugs usually require recursion/loop termination repair earlier in control flow.", "low", 96)
        add("reject_invalid_input", "upstream", "Input depth or recursion drivers may need upstream limitation.", "medium", 80)
    elif bug_type == "heap_corruption_later_crash":
        add("fix_upstream_invariant", "upstream", "Later allocator crashes usually come from an earlier corrupting write or lifetime bug.", "low", 99)
        add("allocation_size_fix", "upstream", "Corrupting writes often stem from mismatched allocation extent or bounds earlier.", "low", 88)
    elif bug_type == "data_race":
        add("fix_upstream_invariant", "upstream", "Race bugs usually require restoring synchronization or ordering invariants, not local crash guards.", "low", 97)
        add("semantic_noop_reject", "upstream", "If a path must not run concurrently, the repair may enforce a semantic no-op under contested state.", "high", 60)
    elif bug_type == "resource_leak":
        add("fix_upstream_invariant", "upstream", "Leak failures usually require lifecycle or cleanup-path repair, not crash-site logic.", "low", 94)
        add("null_or_lifetime_guard", "upstream", "Ownership-aware cleanup guards can help if they encode eventual-release semantics.", "medium", 74)

    if constraint_status == "supported_but_proxy_like":
        boosted: list[tuple[int, dict]] = []
        for score, candidate in scored:
            if candidate["strategy"] in {"clamp_or_normalize", "bounds_check_before_access"}:
                score -= 18
            if candidate["strategy"] in {"fix_upstream_invariant", "allocation_size_fix"}:
                score += 10
            if bug_type in {"uninitialized_use", "use_after_free", "double_free", "heap_corruption_later_crash"} and candidate["strategy"] == "null_or_lifetime_guard":
                score -= 12
            boosted.append((score, candidate))
        scored = boosted
    elif constraint_status == "weakly_supported":
        boosted = []
        for score, candidate in scored:
            if candidate["semantic_risk"] != "low":
                score -= 10
            boosted.append((score, candidate))
        scored = boosted

    if previous_failure in {"semantic_regression", "overfit_poc"}:
        boosted: list[tuple[int, dict]] = []
        for score, candidate in scored:
            penalty = 0
            if candidate["strategy"] in {"bounds_check_before_access", "reject_invalid_input", "null_or_lifetime_guard"}:
                penalty = 20
            bonus = 15 if candidate["location_type"] == "upstream" else 0
            if candidate["semantic_risk"] == "low":
                bonus += 10
            if bug_type in {"use_after_free", "double_free", "invalid_free", "resource_leak"} and candidate["strategy"] == "fix_upstream_invariant":
                bonus += 8
            boosted.append((score - penalty + bonus, candidate))
        scored = boosted

    scored.sort(key=lambda item: item[0], reverse=True)
    out: list[dict] = []
    for _, candidate in scored:
        if candidate not in out:
            out.append(candidate)
    return out


def submit_strategy(strategy: str, location_type: str, rationale: str, semantic_risk: str = "medium") -> str:
    """
    Record the patch strategy before submitting source edits.
    """
    logger = get_logger(NAME)
    allowed_strategy = {
        "reject_invalid_input",
        "clamp_or_normalize",
        "fix_upstream_invariant",
        "bounds_check_before_access",
        "null_or_lifetime_guard",
        "allocation_size_fix",
        "loop_bound_fix",
        "semantic_noop_reject",
    }
    allowed_location = {"upstream", "same_site", "downstream"}
    allowed_risk = {"low", "medium", "high"}
    if strategy not in allowed_strategy:
        return f"Invalid strategy `{strategy}`. Choose one of: {sorted(allowed_strategy)}"
    if location_type not in allowed_location:
        return f"Invalid location_type `{location_type}`. Choose one of: {sorted(allowed_location)}"
    if semantic_risk not in allowed_risk:
        return f"Invalid semantic_risk `{semantic_risk}`. Choose one of: {sorted(allowed_risk)}"
    GLOBAL_STATE["strategy"] = {
        "strategy": strategy,
        "location_type": location_type,
        "rationale": rationale,
        "semantic_risk": semantic_risk,
        "requires_regression_check": semantic_risk == "high",
    }
    logger.info("Patch strategy selected: %s", GLOBAL_STATE["strategy"])
    return "Patch strategy recorded. Now generate and submit the source patch."


# Debugger tool wrappers for patch agent
@logf(NAME, True)
def patch_print_value(expression: str) -> str:
    """Print the value of an expression at the current debugger stop."""
    logger = get_logger(NAME)
    try:
        result = debugger_print(expression)
        return result
    except Exception as e:
        logger.error(f"Error printing value: {e}")
        return f"Error: {str(e)}"


@logf(NAME, True)
def patch_read_memory(address: str, size: int = 1, count: int = 16, fmt: str = "x") -> str:
    """Read raw target memory at the current debugger stop."""
    logger = get_logger(NAME)
    try:
        return debugger_read_memory(str(address), size=int(size), count=int(count), fmt=str(fmt))
    except Exception as e:
        logger.error(f"Error reading memory: {e}")
        return f"Error: {str(e)}"


@logf(NAME, True)
def patch_debugger_assign(variable: str, value: str) -> Tuple[bool, str]:
    """Assign a new value to a variable in the debugger. Returns (success, message)."""
    logger = get_logger(NAME)
    try:
        success, message = debugger_assign(variable, value)
        return success, message
    except Exception as e:
        logger.error(f"Error assigning value: {e}")
        return False, f"Error: {str(e)}"


@logf(NAME, True)
def patch_debugger_assign_expression(expression: str) -> Tuple[bool, str]:
    """Execute a complete assignment expression in the debugger. Returns (success, message)."""
    logger = get_logger(NAME)
    try:
        success, message = debugger_assign_expression(expression)
        return success, message
    except Exception as e:
        logger.error(f"Error executing expression: {e}")
        return False, f"Error: {str(e)}"


def _format_debugger_stop(lldb_output: dict) -> str:
    parts = []
    stop_file = lldb_output.get("file")
    stop_line = lldb_output.get("line")
    stop_func = lldb_output.get("func")
    if stop_file and stop_line:
        parts.append(f"stopped at {stop_file}:{stop_line}")
    elif stop_line:
        parts.append(f"stopped at line {stop_line}")
    if stop_func:
        parts.append(f"function {stop_func}")
    hit_count = debugger_get_tracked_breakpoint_hit_count(lldb_output.get("breakpoint_id"))
    if hit_count is not None:
        parts.append(f"hit_count={hit_count}")
    return ", ".join(parts) if parts else "stop location unavailable"


@logf(NAME, True)
def patch_debugger_continue() -> str:
    """Continue program execution to see if the program still crashes after a state modification."""
    logger = get_logger(NAME)
    try:
        # Note: debugger_continue returns (lldb_output: dict, target_output: str)
        lldb_output, target_output = debugger_continue()
        crash_reason = lldb_output.get("reason", "unknown")
        
        # Use central sanitizer check
        is_sanitizer_crash, sanitizer_msg = check_sanitizer_error(target_output, lldb_output)
        
        # Determine result based on crash reason and sanitizer output
        if is_sanitizer_crash:
            return f"Experiment failed: {sanitizer_msg}. Your fix did not prevent the crash."
        elif crash_reason == "exited-normally":
            return "Experiment successful: The program exited normally (Exit Code 0). Your fix appears to work! You can now generate a code patch that implements the same fix."
        elif crash_reason == "breakpoint-hit":
            return (
                f"Program hit a breakpoint ({_format_debugger_stop(lldb_output)}). "
                "This is not enough to conclude the fix works; inspect the state or continue again."
            )
        elif crash_reason == "signal-received":
            signal_name = lldb_output.get("signal_name", "unknown")
            signal_meaning = lldb_output.get("signal_meaning", "")
            signal_info = f" ({signal_name})" if signal_name != "unknown" else ""
            if signal_meaning:
                signal_info += f" - {signal_meaning}"
            return f"Experiment failed: The program still crashed with signal-received{signal_info}. Your fix did not prevent the crash. Try a different value or approach."
        else:
            return f"Execution completed. Result: {crash_reason}. Check the output to determine if your fix worked."
    except Exception as e:
        logger.error(f"Error continuing execution: {e}")
        return f"Error: {str(e)}"


@logf(NAME, True)
def patch_debugger_run_to_line(line: int) -> str:
    """Run the program until it reaches the specified line (sets a breakpoint and continues)."""
    logger = get_logger(NAME)
    try:
        # First, we need to get the file from suspect_object
        global GLOBAL_STATE
        session = GLOBAL_STATE.get("session")
        if session is None:
            return "Error: No session available. Cannot determine file path."
        
        suspect_object = session._input.suspect_object
        file = suspect_object.get("file")
        if not file:
            return "Error: File path not available in suspect_object."
        
        lldb_output, target_output = debugger_run_to_line(file, line)
        crash_reason = lldb_output.get("reason", "unknown")

        if crash_reason == "breakpoint-hit":
            return f"Program stopped at requested breakpoint ({_format_debugger_stop(lldb_output)})."

        is_sanitizer_crash, sanitizer_msg = check_sanitizer_error(target_output, lldb_output)
        if is_sanitizer_crash:
            return (
                f"Program crashed before reaching {file}:{line}. "
                f"{sanitizer_msg}"
            )

        if crash_reason == "exited-normally":
            return f"Program exited normally before reaching {file}:{line}; this line is likely not on the current PoC path."

        if crash_reason == "signal-received":
            signal_name = lldb_output.get("signal_name", "unknown")
            signal_meaning = lldb_output.get("signal_meaning", "")
            signal_info = f"{signal_name}" if signal_name != "unknown" else "a fatal signal"
            if signal_meaning:
                signal_info += f" ({signal_meaning})"
            return f"Program received {signal_info} before reaching {file}:{line}."

        return f"Failed to reach {file}:{line}. Stop reason: {crash_reason}."
    except Exception as e:
        logger.error(f"Error running to line: {e}")
        return f"Error: {str(e)}"


@logf(NAME, True)
def patch_debugger_backtrace() -> List[str]:
    """Get the call stack (backtrace) showing the current function and all calling functions."""
    logger = get_logger(NAME)
    try:
        frames = debugger_backtrace()
        return frames if frames else ["No backtrace available."]
    except Exception as e:
        logger.error(f"Error getting backtrace: {e}")
        return [f"Error: {str(e)}"]


def patch_debugger_list_breakpoints() -> str:
    """List debugger breakpoints tracked by the wrapper."""
    return json.dumps(debugger_list_breakpoints(), indent=2, sort_keys=True)


def get_generic_agent(bug_type_profile=None, profile=None):
    lldb_only_mode = lldb_only(profile)
    system_prompt = SYSTEM_PROMPT_LLDB_ONLY if lldb_only_mode else SYSTEM_PROMPT
    state_only_mode = state_only_no_angelic(profile)
    system_prompt += build_debugger_session_protocol(
        role="PatchAgent",
        initial_process_state="may be stopped or reset; use `debugger_run_to_line` for a fresh validation run",
        allow_mutation=not state_only_mode,
    )
    if bug_type_profile and not lldb_only_mode:
        system_prompt += build_stage_prompt_overlay("patch", bug_type_profile)
    if state_only_mode and not lldb_only_mode:
        system_prompt += (
            "\n\n**Ablation Mode: State-Only, No Angelic Counterfactuals**\n"
            "- You may inspect source code and debugger-observed state.\n"
            "- Do not mutate runtime state or continue execution to test a hypothetical mutation.\n"
            "- Generate the patch from the observation-only root-cause hypothesis and normal final verification only.\n"
            f"- This branch allows at most {STATE_ONLY_NO_ANGELIC_MAX_RETRIES} failed patch submissions inside one patch session.\n"
        )
    agent = GenericAgent("Tech", system_prompt)
    
    # Code analysis tools
    agent.register_hook(
        definition, "Get the definition of a symbol in at a given position"
    )
    agent.register_hook(
        summary,
        "Get the comments and document information of a symbol at a given position",
    )
    agent.register_hook(function_body, "Get the complete definition of a function")
    agent.register_hook(file_content, "Get the content of a file")
    agent.register_hook(search_in_repo, "Search for a symbol/pattern in a file or directory with small context. Use this only after checking the preferred edit location, to find a necessary upstream/downstream companion edit.")
    
    # Debugger tools for testing fixes
    # Backward-compatible tool names (patch_debugger_*) are kept, but we also expose
    # standard names (debugger_*) to match PATCH_SYSTEM_PROMPT.
    agent.register_hook(patch_debugger_backtrace, "Get the call stack (backtrace) showing the current function and all calling functions.")
    agent.register_hook(patch_debugger_backtrace, "Alias of patch_debugger_backtrace.", name="debugger_backtrace")
    agent.register_hook(patch_debugger_list_breakpoints, "List currently tracked debugger breakpoints for this session.")
    agent.register_hook(patch_debugger_list_breakpoints, "Alias of patch_debugger_list_breakpoints.", name="debugger_list_breakpoints")

    agent.register_hook(patch_print_value, "Print the value of an expression at the current debugger stop (if available).")
    agent.register_hook(patch_print_value, "Alias of patch_print_value.", name="print_value")
    agent.register_hook(patch_read_memory, "Read target memory at a concrete address at the current debugger stop.")
    agent.register_hook(patch_read_memory, "Alias of patch_read_memory.", name="read_memory")

    agent.register_hook(patch_debugger_run_to_line, "Start a fresh program run and stop at the specified line if reachable. The tool returns the actual stop location or explains whether the program exited/crashed first.")
    agent.register_hook(patch_debugger_run_to_line, "Alias of patch_debugger_run_to_line.", name="debugger_run_to_line")

    if not state_only_mode:
        agent.register_hook(patch_debugger_assign, "Assign a new value to a variable in the debugger. Use this to test if modifying a variable prevents the crash. Returns (success: bool, message: str).")
        agent.register_hook(patch_debugger_assign, "Alias of patch_debugger_assign.", name="debugger_assign")

        agent.register_hook(patch_debugger_assign_expression, "Execute a complete assignment expression in the debugger. Use this for complex assignments like const_cast or type casts. Returns (success: bool, message: str).")
        agent.register_hook(patch_debugger_assign_expression, "Alias of patch_debugger_assign_expression.", name="debugger_assign_expression")

        agent.register_hook(patch_debugger_continue, "Continue program execution after assigning a value to see if it still crashes. After calling this, the debugger state will reset, so plan your experiments accordingly.")
        agent.register_hook(patch_debugger_continue, "Alias of patch_debugger_continue.", name="debugger_continue")

    # Patch submission
    agent.register_hook(submit, "Submit the patch for final verification (compile + run)")
    agent.register_hook(resign, "Resign from the current round")
    agent.register_hook(
        submit_strategy,
        "Submit the patch strategy before source patch submission. "
        "Arguments: strategy, location_type, rationale, semantic_risk.",
    )

    return agent


# =============================================================================
# Patch agent
# =============================================================================


class PatchInput:
    def __init__(self, profile, constraint, suspect_object):
        self.profile = profile
        self.constraint = constraint
        self.suspect_object = suspect_object


class PatchSession:
    def __init__(self, i: PatchInput):
        self._input = i

    @logf(NAME, True)
    def run(self, logger=None):
        global GLOBAL_STATE

        reset_global_state()
        GLOBAL_STATE["session"] = self

        initaial_prompt = self._get_initial_prompt()
        bug_type_profile = (
            self._input.suspect_object.get("bug_type_profile")
            or infer_bug_type_profile(profile=self._input.profile, suspect_object=self._input.suspect_object)
        )
        agent = get_generic_agent(bug_type_profile=bug_type_profile, profile=self._input.profile)
        chat = agent.initiate(initaial_prompt)
        self._save_chat(chat)

        patch = None
        if GLOBAL_STATE["resign"]:
            logger.error("Patch agent resigned")
        elif GLOBAL_STATE["patches"] is None:
            logger.error("Incomplete patch")
        else:
            patch = {"patches": GLOBAL_STATE["patches"]}
            logger.info("Patch generated")

        if patch is not None:
            strategy = GLOBAL_STATE["strategy"] or _infer_patch_strategy(
                self._input.constraint,
                self._input.suspect_object,
            )
            patch["retry"] = GLOBAL_STATE["retry"]
            patch["valid"] = GLOBAL_STATE["valid"]
            patch["resign"] = GLOBAL_STATE["resign"]
            # Tag the patch with the constraint that generated it
            patch["constraint"] = self._input.constraint
            patch["hypothesis_summary"] = self._input.suspect_object.get("debug_summary", "")
            patch["suspect_file"] = self._input.suspect_object.get("file", "")
            patch["suspect_line"] = self._input.suspect_object.get("line", -1)
            patch["function_name"] = self._input.suspect_object.get("function_name", "")
            patch.update(strategy)

        self._save_patch(patch)

        logger.warning("Patch generation completed")
        logger.info(
            "Patch session summary: resign=%s submitted=%s retry_count=%s valid=%s",
            GLOBAL_STATE["resign"],
            GLOBAL_STATE["patches"] is not None,
            GLOBAL_STATE["retry"],
            GLOBAL_STATE["valid"],
        )

        return patch

    def _get_initial_prompt(self):
        suspect_object = self._input.suspect_object
        lldb_only_mode = lldb_only(self._input.profile)
        state_only_mode = state_only_no_angelic(self._input.profile)
        active_patch_location = suspect_object.get("active_patch_location") or {}
        prompt_file = active_patch_location.get("file") or suspect_object["file"]
        prompt_line = active_patch_location.get("line") or suspect_object["line"]
        bug_type_profile = suspect_object.get("bug_type_profile") or infer_bug_type_profile(
            profile=self._input.profile,
            suspect_object=suspect_object,
            debug_summary=suspect_object.get("debug_summary", ""),
        )
        contract = suspect_object.get("angelic_consumption_contract") or {}
        visibility = str(contract.get("raw_angelic_visibility", "show"))
        supporting_angelic_evidence = (
            suspect_object.get("top_angelic_examples", [])[:3]
            if visibility == "show"
            else [str(contract.get("observed_effect", "Angelic intervention effects were abstracted upstream."))]
        )
        counterfactual_invariant = (
            suspect_object.get("counterfactual_invariant")
            or suspect_object.get("counterfactual_contract")
            or {}
        )
        if state_only_mode:
            counterfactual_invariant = {}
        elif not counterfactual_invariant:
            counterfactual_invariant = {
                "repair_invariant": self._input.constraint,
                "invariant_scope": suspect_object.get("contract_scope", ""),
                "validation_obligations": suspect_object.get("validation_obligations", []),
                "semantic_repair_status": suspect_object.get("semantic_repair_status", "unknown"),
                "boundary_audit": suspect_object.get("boundary_audit", {}),
            }
        counterfactual_mode = bool(counterfactual_invariant.get("type") == "counterfactual_invariant")
        source_hints = {
            "active_patch_location": active_patch_location,
            "preferred_edit_location": suspect_object.get("preferred_edit_location", {}),
            "candidate_edit_locations": suspect_object.get("candidate_edit_locations", [])[:4],
            "crash_site": suspect_object.get("crash_site", {}),
            "root_cause_site": suspect_object.get("root_cause_site", {}),
            "suspect_file": suspect_object.get("file", ""),
            "suspect_line": suspect_object.get("line", -1),
            "suspect_function": suspect_object.get("function_name", ""),
        }
        evidence_summary = {
            "constraint_role": suspect_object.get("constraint_role", "generalized_hypothesis"),
            "repair_intent": suspect_object.get("repair_intent", ""),
        }
        if not state_only_mode:
            evidence_summary["counterfactual_summary"] = counterfactual_invariant.get("counterfactual_summary", {})
        if not counterfactual_mode and not state_only_mode:
            evidence_summary.update(
                {
                    "supporting_angelic_evidence": supporting_angelic_evidence,
                    "demonic_summary": suspect_object.get("demonic_summary", "Unsafe execution reaches the current crash state."),
                    "typed_angelic_evidence": suspect_object.get("typed_angelic_evidence", {}),
                }
            )
        typed_repair_policy = dict(bug_type_profile or {})
        typed_repair_policy.pop("classification_basis", None)
        if state_only_mode:
            for key in ("angelic_shape", "debug_hint", "constraint_hint", "generalization_target", "evidence_family", "evidence_kind"):
                typed_repair_policy.pop(key, None)
        available_tools = {
            "source_tools": ["file_content", "function_body", "definition", "summary", "search_in_repo"],
            "debugger_tools": [
                "debugger_backtrace",
                "debugger_run_to_line",
                "print_value",
                "debugger_assign",
                "debugger_assign_expression",
                "debugger_continue",
            ],
            "patch_tools": ["submit_strategy", "submit", "resign"],
        }
        if state_only_mode:
            available_tools["debugger_tools"] = ["debugger_backtrace", "debugger_run_to_line", "print_value", "read_memory"]
        if lldb_only_mode:
            observed_runtime_facts = _sanitize_lldb_only_value({
                "observed_failure": {
                    "file": suspect_object.get("file", ""),
                    "line": suspect_object.get("line", -1),
                    "function": suspect_object.get("function_name", ""),
                },
                "suspect_variables": suspect_object.get("variable_names", []),
                "suspect_expressions": suspect_object.get("suspect_expressions", []),
                "context_variables": suspect_object.get("context_variables", {}),
                "crash_log_excerpt": suspect_object.get("crash_log_excerpt", ""),
            })
            source_starting_points = _sanitize_lldb_only_value({
                "crash_site": {
                    "file": suspect_object.get("file", ""),
                    "line": suspect_object.get("line", -1),
                    "function": suspect_object.get("function_name", ""),
                },
                "suspect_file": suspect_object.get("file", ""),
                "suspect_function": suspect_object.get("function_name", ""),
                "mentioned_variables": suspect_object.get("variable_names", []),
            })
            return INITIAL_PROMPT_LLDB_ONLY.format(
                available_tools=json.dumps(available_tools, indent=2, sort_keys=True),
                debug_rca_summary=suspect_object.get("debug_summary", ""),
                observed_runtime_facts=json.dumps(observed_runtime_facts, indent=2, default=str, sort_keys=True),
                source_starting_points=json.dumps(source_starting_points, indent=2, default=str, sort_keys=True),
            )
        base = INITIAL_PROMPT.format(
            available_tools=json.dumps(available_tools, indent=2, sort_keys=True),
            debug_rca_summary=suspect_object.get("debug_summary", ""),
            counterfactual_invariant=json.dumps(counterfactual_invariant, indent=2, default=str, sort_keys=True),
            typed_repair_policy=json.dumps(typed_repair_policy, indent=2, default=str, sort_keys=True),
            source_hints=json.dumps(source_hints, indent=2, default=str, sort_keys=True),
            evidence_summary=json.dumps(evidence_summary, indent=2, default=str, sort_keys=True),
        )
        bug_context = format_bug_context(self._input.profile)
        if bug_context:
            base += "\n\n---\n\n" + bug_context
        if state_only_mode:
            base = re.sub(
                r"\n---\n\n## CounterfactualInvariant\n\n```json\n.*?Generalize them into source logic instead of copying them literally\.\n",
                "\n",
                base,
                flags=re.S,
            )
        ranked_strategies = _rank_patch_strategies(self._input.constraint, suspect_object)[:3]
        # Provide already-known debug context to avoid redundant debugger probing.
        extra_parts = []
        debug_summary = suspect_object.get("debug_summary")
        if debug_summary:
            extra_parts.append(f"[Debug Summary (from debug agent)]: {debug_summary}")
        ctx_vars = suspect_object.get("context_variables")
        if ctx_vars:
            extra_parts.append(f"[Context Variables Snapshot]: {ctx_vars}")
        demonic = demonic_seed_records(suspect_object)
        if demonic:
            extra_parts.append(f"[Demonic Seed Records]: {demonic}")
        last_status = suspect_object.get("last_verification_status")
        if last_status:
            extra_parts.append(f"[Previous Verification Status]: {last_status}")
        last_hint = suspect_object.get("last_verification_blame_hint")
        if last_hint:
            extra_parts.append(f"[Previous Verification Hint]: {last_hint}")
        if ranked_strategies:
            extra_parts.append(f"[Recommended Patch Strategies]: {ranked_strategies}")
        forced_strategy = suspect_object.get("forced_patch_strategy")
        if forced_strategy:
            extra_parts.append(f"[Forced Patch Strategy]: {forced_strategy}")
        if active_patch_location:
            extra_parts.append(f"[Active Patch Attempt Location]: {active_patch_location}")
        preferred_edit_location = suspect_object.get("preferred_edit_location")
        if preferred_edit_location:
            extra_parts.append(f"[Preferred Edit Location]: {preferred_edit_location}")
        candidate_edit_locations = suspect_object.get("candidate_edit_locations")
        if candidate_edit_locations:
            extra_parts.append(f"[Candidate Edit Locations]: {candidate_edit_locations[:4]}")
        location_groups = suspect_object.get("location_groups")
        if location_groups:
            extra_parts.append(f"[Location Groups]: {location_groups[:2]}")
        repair_topology = suspect_object.get("repair_topology")
        if repair_topology:
            extra_parts.append(f"[Repair Topology]: {repair_topology}")
        allowed_edit_scope = suspect_object.get("allowed_edit_scope")
        if allowed_edit_scope:
            extra_parts.append(f"[Allowed Edit Scope]: {allowed_edit_scope}")
        forbidden_fix_patterns = suspect_object.get("forbidden_fix_patterns")
        if forbidden_fix_patterns:
            extra_parts.append(f"[Forbidden Fix Patterns]: {forbidden_fix_patterns}")
        causal_chain_summary = suspect_object.get("causal_chain_summary")
        if causal_chain_summary:
            extra_parts.append(f"[Causal Chain Summary]: {causal_chain_summary}")
        crash_site = suspect_object.get("crash_site")
        if crash_site:
            extra_parts.append(f"[Crash Site]: {crash_site}")
        root_cause_site = suspect_object.get("root_cause_site")
        if root_cause_site:
            extra_parts.append(f"[Root Cause Site]: {root_cause_site}")
        preferred_repair_stage = suspect_object.get("preferred_repair_stage")
        if preferred_repair_stage:
            extra_parts.append(f"[Preferred Repair Stage]: {preferred_repair_stage}")
        forbidden_repair_stages = suspect_object.get("forbidden_repair_stages")
        if forbidden_repair_stages:
            extra_parts.append(f"[Forbidden Repair Stages]: {forbidden_repair_stages}")
        if contract and not counterfactual_mode and not state_only_mode:
            extra_parts.append(f"[Angelic Consumption Contract]: {contract}")
        angelic_observations = suspect_object.get("angelic_observations")
        if angelic_observations and not counterfactual_mode and not state_only_mode:
            extra_parts.append(f"[Angelic Observations]: {angelic_observations[:4]}")
        validation_obligations = suspect_object.get("validation_obligations")
        if validation_obligations and not counterfactual_mode:
            extra_parts.append(f"[Validation Obligations]: {validation_obligations[:6]}")
        typed_angelic_evidence = suspect_object.get("typed_angelic_evidence")
        if typed_angelic_evidence and not counterfactual_mode and not state_only_mode:
            extra_parts.append(f"[Typed Angelic Evidence]: {typed_angelic_evidence}")
        demonic_trace_summary = suspect_object.get("demonic_trace_summary")
        if demonic_trace_summary and not counterfactual_mode:
            extra_parts.append(f"[Demonic Trace Summary]: {demonic_trace_summary}")
        challenge_result = suspect_object.get("challenge_result")
        if challenge_result and not counterfactual_mode and not state_only_mode:
            challenge_summary = {
                "status": challenge_result.get("status"),
                "support_score": challenge_result.get("support_score"),
                "falsification_score": challenge_result.get("falsification_score"),
                "explanatory_score": challenge_result.get("explanatory_score"),
                "patchability_score": challenge_result.get("patchability_score"),
                "recommended_next_actor": challenge_result.get("recommended_next_actor"),
                "notes": challenge_result.get("notes", [])[:6],
            }
            extra_parts.append(f"[Constraint Challenger Summary]: {challenge_summary}")
            counterexamples = challenge_result.get("counterexample_interventions") or []
            if counterexamples:
                extra_parts.append(f"[Known Challenger Counterexamples]: {counterexamples[:4]}")
            supporting = challenge_result.get("supporting_interventions") or []
            if supporting:
                extra_parts.append(f"[Supporting Challenger Interventions]: {supporting[:4]}")
            if float(challenge_result.get('patchability_score', 1.0) or 1.0) < 0.45:
                extra_parts.append(
                    "[Low Patchability Notice]: Challenger support is weak for same-site or high-risk repairs. Prefer a low-risk upstream invariant repair."
                )
        patch_expansion_policy = suspect_object.get("patch_expansion_policy")
        if patch_expansion_policy:
            extra_parts.append(f"[Patch Expansion Policy]: {patch_expansion_policy}")
        if bug_type_profile and not counterfactual_mode and not state_only_mode:
            extra_parts.append(f"[Typed Angelic Evidence Profile]: {typed_repair_policy}")
        if extra_parts:
            base += (
                "\n\nNOTE: The following context has already been collected. "
                "You do NOT need to re-run `print_value` unless you need to confirm something:\n"
                + "\n".join(f"- {p}" for p in extra_parts)
            )
        base += (
            "\n\nExecution policy for this patch round:\n"
            "- Your task is to repair the underlying bug/contract violation, not merely suppress the observed crash.\n"
            "- A patch that only prevents the current PoC from reaching the crash site is NOT sufficient unless it restores the intended product/library contract.\n"
            "- Root cause diagnosis is already complete. Do NOT restart debugger-style diagnosis from scratch.\n"
            "- Treat `Crash Site` as the first visible failure point unless `Causal Chain Summary` clearly says otherwise; prefer `Root Cause Site` and `Preferred Repair Stage`.\n"
            "- This attempt must start from `Active Patch Attempt Location` when present; only move to another candidate location if that starting point is clearly insufficient.\n"
            "- Phase 1: attempt a local-first repair at `Preferred Edit Location` or within `Location Groups`.\n"
            "- Phase 2: only if single-site repair is clearly insufficient, expand to a companion edit along the call chain or a nearby helper according to `Patch Expansion Policy`.\n"
            "- Do not choose a repair that lives only in a forbidden stage listed under `Forbidden Repair Stages` unless you explicitly justify why the causal chain cannot be repaired earlier.\n"
            "- If you expand beyond the preferred location, explain why single-site repair is insufficient and why the extra location is necessary.\n"
            "- Avoid any pattern listed under `Forbidden Fix Patterns` unless you explicitly justify why it is unavoidable.\n"
            "- If you need multiple edits, keep them within the declared `Allowed Edit Scope` unless the evidence clearly requires a cross-file repair.\n"
            "- If `Constraint Challenger Summary` reports low patchability, do not default to same-site guards or high-risk rejection patches; prefer a low-risk upstream invariant repair.\n"
            "- If `Known Challenger Counterexamples` exists, your patch must not repeat the local fix shape that already crashed despite satisfying the constraint.\n"
            "- Prefer product/library/runtime code over fuzz harnesses, tests, scripts, and examples.\n"
            "- Do NOT patch fuzz/test/support files merely to sanitize the PoC input or bypass the crash unless the bug is explicitly in that harness/support code.\n"
            "- Reject symptom-only fixes such as crash-site guards, input clamps in test harnesses, or benign defaulting that hides corrupted state without repairing the earlier cause.\n"
        )
        if state_only_mode:
            base += (
                "- No counterfactual invariant, angelic observation, fuzz result, or constraint challenger evidence is available in this ablation.\n"
                "- Do not infer that a hypothetical runtime mutation was tested; use only observed crash state and source reasoning.\n"
            )
        else:
            base += (
                "- If a `CounterfactualInvariant` exists, implement its `repair_invariant` within `invariant_scope`; use `enforcement_role_preference` to search for the right source role.\n"
                "- Do not copy raw counterfactual values into source unless they are semantic constants; use the short counterfactual summary as evidence for the invariant.\n"
            )
        if not counterfactual_mode and not state_only_mode:
            base += build_stage_prompt_overlay("patch", bug_type_profile)
        return base

    def _save_chat(self, chat):
        filename = os.path.join(
            self._input.profile["chat_dir"],
            _safe_patch_chat_filename(self._input.constraint),
        )
        dump_json(chat, filename)

    @logf(NAME)
    def _save_patch(self, patch, logger=None):
        logger.info("Saving patch to %s", self._input.profile["patch_output"])
        if patch is None:
            dump_json({"failed": True}, self._input.profile["patch_output"])
            return
        patch.update(export_patch_artifacts(self._input.profile, patch, logger=logger))
        dump_json(patch, self._input.profile["patch_output"])

        # save file to result
        for p in patch["patches"]:
            filename = os.path.basename(p["file"])
            shutil.copyfile(
                p["file"],
                os.path.join(self._input.profile["result_dir"], filename),
            )

        # save readable patch to patch.txt
        with open(
            os.path.join(self._input.profile["result_dir"], "patch.txt"), "w"
        ) as f:
            for p in patch["patches"]:
                f.write(f"File: {p['file']}\n")
                f.write(f"Affected lines: {p['start_line']}-{p['end_line']}\n")

                content = file_get_content(p["file"], p["start_line"], p["end_line"])
                f.write(f"\n--- Original content ---\n\n{content}\n")

                content = p["patch"]
                f.write(f"\n--- Patch content ---\n\n{content}\n\n")


@logf(NAME, True)
def patch(profile, constraint, suspect_object, logger=None):
    session = PatchSession(PatchInput(profile, constraint, suspect_object))
    return session.run()

    def _get_initial_prompt(self):
        suspect_object = self._input.suspect_object
        return INITIAL_PROMPT.format(
            file=suspect_object["file"],
            line=suspect_object["line"],
            variable_names=", ".join(suspect_object["variable_names"]),
            constraint=self._input.constraint
        )

    def _save_chat(self, chat):
        filename = os.path.join(
            self._input.profile["chat_dir"],
            _safe_patch_chat_filename(self._input.constraint),
        )
        dump_json(chat, filename)

    @logf(NAME)
    def _save_patch(self, patch, logger=None):
        logger.info("Saving patch to %s", self._input.profile["patch_output"])
        if patch is None:
            dump_json({"failed": True}, self._input.profile["patch_output"])
            return
        dump_json(patch, self._input.profile["patch_output"])

        # save file to result
        for p in patch["patches"]:
            filename = os.path.basename(p["file"])
            shutil.copyfile(
                p["file"],
                os.path.join(self._input.profile["result_dir"], filename),
            )

        # save readable patch to patch.txt
        with open(
            os.path.join(self._input.profile["result_dir"], "patch.txt"), "w"
        ) as f:
            for p in patch["patches"]:
                f.write(f"File: {p['file']}\n")
                f.write(f"Affected lines: {p['start_line']}-{p['end_line']}\n")

                content = file_get_content(p["file"], p["start_line"], p["end_line"])
                f.write(f"\n--- Original content ---\n\n{content}\n")

                content = p["patch"]
                f.write(f"\n--- Patch content ---\n\n{content}\n\n")


@logf(NAME, True)
def patch(profile, constraint, suspect_object, logger=None):
    session = PatchSession(PatchInput(profile, constraint, suspect_object))
    return session.run()
