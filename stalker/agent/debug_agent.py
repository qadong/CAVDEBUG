# The debug, huh?

import json
import os
import re
from typing import List, Tuple
from agent.generic_agent import GenericAgent
from utils.parsers import parse_lldb_frame, check_sanitizer_error
from agent.prompts import (
    DEBUG_SYSTEM_PROMPT as SYSTEM_PROMPT,
    DEBUG_SYSTEM_PROMPT_CRASH_LINE as SYSTEM_PROMPT_CRASH_LINE,
    DEBUG_SYSTEM_PROMPT_NO_ANGELIC as SYSTEM_PROMPT_NO_ANGELIC,
    DEBUG_INITIAL_PROMPT as INITIAL_PROMPT,
    DEBUG_INITIAL_PROMPT_CRASH_LINE as INITIAL_PROMPT_CRASH_LINE,
    DEBUG_INITIAL_PROMPT_NO_ANGELIC as INITIAL_PROMPT_NO_ANGELIC,
    build_debugger_session_protocol,
)
from agent.type_angelic import build_stage_prompt_overlay, infer_bug_type_profile
from utils.files import dump_json
from tools.file.functions import file_get_decorated_content
from tools.debugger.functions import (
    debugger_backtrace,
    debugger_clear_breakpoints,
    debugger_continue,
    debugger_frame,
    debugger_get_tracked_breakpoint_hit_count,
    debugger_print,
    debugger_get_type,
    debugger_assign,
    debugger_assign_expression,
    debugger_run,
    debugger_set_breakpoint,
    debugger_add_functional_guard,
    debugger_list_breakpoints,
    debugger_record_last_position,
    debugger_read_memory,
)
from tools.debugger.driver import debugger_respawn
from tools.lsp.functions import (
    lsp_get_function,
    lsp_get_symbol_definition,
    lsp_get_symbol_summary,
    lsp_to_abs_path,
)
from tools.lsp.driver import lsp_instance
from utils.ablation import state_only_no_angelic
from utils.bug_context import format_bug_context
from utils.logger import get_logger, logf, logm


NAME = "agent-debug"

PRIOR_ANALYSIS = "Below are the analysis results of previous frames:\n" "{}" "\n"
ACCUMULATED_ANALYSIS = ""

# =============================================================================
# Agent hooks
# =============================================================================

# For the agent hook, only one debug session at a time.
# Global state
GLOBAL_STATE = {
    "session": None,
    "file": None,
    "suspect_object": None,
    "skip": False,
}


def reset_global_state():
    global GLOBAL_STATE
    GLOBAL_STATE = {
        "session": None,
        "file": None,
        "suspect_object": None,
        "skip": False,
    }


def _is_unavailable_debugger_value(value) -> bool:
    text = str(value or "").lower()
    return any(marker in text for marker in ("error:", "timeout", "not available", "unavailable", "lldb_eval"))


def _is_process_not_launched_response(value) -> bool:
    text = str(value or "").lower()
    return "process_not_launched" in text or "process must be launched" in text


def _normalize_seed_site(site, default_site: dict) -> dict:
    normalized = dict(default_site)
    if isinstance(site, dict):
        normalized.update(site)
    normalized["file"] = str(normalized.get("file", "") or "")
    try:
        normalized["line"] = int(normalized.get("line", -1) or -1)
    except (TypeError, ValueError):
        normalized["line"] = -1
    normalized["role"] = "counterfactual_probe_site"
    return normalized


def _normalize_angelic_seed_records(known_values, variable_names: List[str], default_site: dict):
    records = []
    assignment_sets = []
    legacy_values = []

    def add_record(variable, value, site=None):
        if not variable or _is_unavailable_debugger_value(value):
            return
        variable_text = str(variable)
        value_text = str(value)
        records.append(
            {
                "site": _normalize_seed_site(site, default_site),
                "variable": variable_text,
                "value": value_text,
            }
        )
        assignment_sets.append({variable_text: value_text})

    if isinstance(known_values, dict):
        if "variable" in known_values and "value" in known_values:
            add_record(known_values.get("variable"), known_values.get("value"), known_values.get("site"))
        else:
            assignment = {}
            for variable, value in known_values.items():
                if _is_unavailable_debugger_value(value):
                    continue
                assignment[str(variable)] = str(value)
                records.append(
                    {
                        "site": _normalize_seed_site(None, default_site),
                        "variable": str(variable),
                        "value": str(value),
                    }
                )
            if assignment:
                assignment_sets.append(assignment)
    elif isinstance(known_values, list):
        if known_values and all(isinstance(item, dict) for item in known_values):
            for item in known_values:
                if "variable" in item and "value" in item:
                    add_record(item.get("variable"), item.get("value"), item.get("site"))
                    continue
                assignment = {}
                for variable, value in item.items():
                    if _is_unavailable_debugger_value(value):
                        continue
                    assignment[str(variable)] = str(value)
                    records.append(
                        {
                            "site": _normalize_seed_site(None, default_site),
                            "variable": str(variable),
                            "value": str(value),
                        }
                    )
                if assignment:
                    assignment_sets.append(assignment)
        else:
            legacy_values = [str(value) for value in known_values if not _is_unavailable_debugger_value(value)]
    elif known_values is not None and not _is_unavailable_debugger_value(known_values):
        legacy_values = [str(known_values)]

    if not records and legacy_values and variable_names:
        for value in legacy_values:
            add_record(variable_names[0], value)
    return records, assignment_sets, legacy_values


# @logf(NAME, True)
def _resolve_debug_file(file: str = None) -> str:
    if file is None:
        return GLOBAL_STATE["file"]

    file_path = lsp_to_abs_path(str(file))
    if os.path.exists(file_path):
        return file_path

    if not os.path.isabs(file_path):
        default_file_dir = os.path.dirname(GLOBAL_STATE["file"])
        potential_path = os.path.join(default_file_dir, file_path)
        if os.path.exists(potential_path):
            return potential_path
        raise FileNotFoundError(
            f"File not found: {file} (resolved to: {file_path}). Please provide a valid file path relative to the workspace or an absolute path."
        )

    raise FileNotFoundError(f"File not found: {file} (absolute path: {file_path}). Please verify the file path is correct.")


def run_to_line(line: int, file: str = None) -> str:
    """
    Run the debugger to a specific line.
    
    Args:
        line: Line number to set breakpoint at (1-indexed)
        file: Optional file path. If not provided, uses the current file from GLOBAL_STATE.
              Can be a relative path or absolute path. Relative paths are resolved using lsp_to_abs_path.
    """
    logger = get_logger(NAME)
    logger.info(f"Invoking run_to_line(line={line}, file={file})")

    try:
        file_path = _resolve_debug_file(file)
    except FileNotFoundError as e:
        logger.error(str(e))
        return str(e)
    
    line_int = int(line)

    response = GLOBAL_STATE["session"].llm_run_to_line(file_path, line_int)
    logger.debug(response)

    return response


def continue_to_line(line: int, file: str = None) -> str:
    """
    Continue the current stopped process to a specific line.

    Unlike run_to_line(), this does not restart the program. Use it when the
    current execution is already on the path you want to inspect.
    """
    logger = get_logger(NAME)
    logger.info(f"Invoking continue_to_line(line={line}, file={file})")

    try:
        file_path = _resolve_debug_file(file)
    except FileNotFoundError as e:
        logger.error(str(e))
        return str(e)

    response = GLOBAL_STATE["session"].llm_continue_to_line(file_path, int(line))
    logger.debug(response)
    return response


def list_breakpoints() -> str:
    """
    List breakpoints tracked for the current debugger session.
    """
    return json.dumps(debugger_list_breakpoints(), indent=2, sort_keys=True)


# @logf(NAME, True)
def print_value(expression: str) -> str:
    """
    Print the value of an expression.
    """
    logger = get_logger(NAME)
    logger.info(f"Tool Call: print_value(expression='{expression}')")

    expression = str(expression)

    import time
    t0 = time.monotonic()
    response = GLOBAL_STATE["session"].llm_print_value(expression)
    elapsed = time.monotonic() - t0
    if elapsed > 10:
        preview = expression[:60] + "..." if len(expression) > 60 else expression
        logger.warning(f"print_value took {elapsed:.1f}s for expression='{preview}'")
    if len(response) > 200:
        logger.warning("Value too long, only first 200 characters will be returned")
        response = response[:200] + "..."
    
    logger.info(f"Tool Output (print_value): '{response}'")
    return response


def read_memory(address: str, size: int = 1, count: int = 16, fmt: str = "x") -> str:
    """
    Read target memory at a concrete address.
    """
    logger = get_logger(NAME)
    logger.info(f"Tool Call: read_memory(address={address}, size={size}, count={count}, fmt={fmt})")
    response = debugger_read_memory(address, size=size, count=count, fmt=fmt)
    if len(response) > 1000:
        logger.warning("Memory read output too long, only first 1000 characters will be returned")
        response = response[:1000] + "..."
    logger.info(f"Tool Output (read_memory): '{response}'")
    return response


# @logf(NAME, True)
def definition(line: int, symbol: str) -> str:
    """
    Get the definition of a symbol in the code.
    """
    get_logger(NAME).info(f"Invoking definition({line}, {symbol})")

    line = int(line)
    symbol = str(symbol)

    response = lsp_get_symbol_definition(GLOBAL_STATE["file"], line, symbol)
    get_logger(NAME).debug(response)

    return response


# @logf(NAME, True)
def summary(line: int, symbol: str) -> str:
    """
    Get the hover information of a symbol at a given position.
    """
    get_logger(NAME).info(f"Invoking summary({line}, {symbol})")

    line = int(line)
    symbol = str(symbol)

    response = lsp_get_symbol_summary(GLOBAL_STATE["file"], line, symbol)
    get_logger(NAME).debug(response)

    return response


# @logf(NAME, True)
def function_body(function: str) -> str:
    """
    Get the complete definition of a function.
    """
    get_logger(NAME).info(f"Invoking function_body({function})")

    function = str(function)

    response = lsp_get_function(GLOBAL_STATE["file"], function)
    get_logger(NAME).debug(response)

    return response


# @logf(NAME, True)
def file_content(start_line: int, end_line: int, file: str = None) -> str:
    """
    Get the content of a file.
    
    Args:
        start_line: Starting line number (1-indexed)
        end_line: Ending line number (1-indexed)
        file: Optional file path. If not provided, uses the current file from GLOBAL_STATE.
              Can be a relative path or absolute path. Relative paths are resolved using lsp_to_abs_path.
    """
    logger = get_logger(NAME)
    logger.info(f"Tool Call: file_content(start_line={start_line}, end_line={end_line}, file={file})")

    # If file is not provided, use the default file from GLOBAL_STATE
    if file is None:
        file_path = GLOBAL_STATE["file"]
    else:
        # Convert to absolute path if it's a relative path
        file_path = lsp_to_abs_path(str(file))
        if not os.path.exists(file_path):
            # lsp_to_abs_path might return the original path if not found
            # Check if it's already an absolute path, or try to construct one
            if not os.path.isabs(file_path):
                # Try constructing absolute path relative to GLOBAL_STATE["file"]'s directory
                default_file_dir = os.path.dirname(GLOBAL_STATE["file"])
                potential_path = os.path.join(default_file_dir, file_path)
                if os.path.exists(potential_path):
                    file_path = potential_path
                else:
                    error_msg = f"File not found: {file} (resolved to: {file_path}). Please provide a valid file path relative to the workspace or an absolute path."
                    logger.error(error_msg)
                    return error_msg
            else:
                error_msg = f"File not found: {file} (absolute path: {file_path}). Please verify the file path is correct."
                logger.error(error_msg)
                return error_msg
    
    content = file_get_decorated_content(file_path, start_line, end_line)
    
    # Include filename in the response so the agent knows which file it's viewing
    if content:
        response = f"File: {file_path}\nLines {start_line}-{end_line}:\n{content}"
    else:
        response = f"File: {file_path}\nLines {start_line}-{end_line}: (empty or invalid range)"
    
    # Log a summary of the output to avoid flooding the log
    response_summary = response.strip().split('\n')[0] if response else ""
    logger.info(f"Tool Output (file_content): '{response_summary}... (truncated)'")
    logger.debug(f"Full file_content output:\n{response}")

    return response


def search_in_repo(pattern: str, path: str = None, max_hits: int = 20, context: int = 2) -> str:
    """
    Search for a keyword/regex pattern in a file or directory and return line numbers with small context.

    This avoids repeated paging via file_content for large files.
    """
    logger = get_logger(NAME)
    logger.info(f"Tool Call: search_in_repo(pattern={pattern}, path={path}, max_hits={max_hits}, context={context})")

    # Resolve search path
    if path is None:
        search_path = GLOBAL_STATE["file"]
    else:
        search_path = lsp_to_abs_path(str(path))
        if not os.path.exists(search_path) and not os.path.isabs(search_path):
            default_dir = os.path.dirname(GLOBAL_STATE["file"])
            candidate = os.path.join(default_dir, search_path)
            if os.path.exists(candidate):
                search_path = candidate

    if not search_path or not os.path.exists(search_path):
        return f"Error: Path not found for search: {path} (resolved to: {search_path})"

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

        out = [f"Search path: {search_path}", f"Pattern: {pattern}", f"Showing up to {max_hits_i} matches", ""]
        total_hits = 0
        for file_path in iter_candidate_files(search_path):
            try:
                with open(file_path, "r", errors="ignore") as f:
                    lines = f.readlines()
            except Exception as e:
                logger.debug(f"Skipping unreadable file during search: {file_path}: {e}")
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
                    out.append(f"{prefix} L{ln}: {lines[ln-1].rstrip()}")
                out.append("")

            if total_hits >= max_hits_i:
                break

        if total_hits == 0:
            return f"No matches for pattern '{pattern}' under {search_path}"

        out.insert(2, f"Hits: {total_hits}")
        return "\n".join(out).strip()
    except Exception as e:
        logger.error(f"search_in_repo failed: {e}", exc_info=True)
        return f"Error during search_in_repo: {e}"


# @logf(NAME, True)
def _debugger_continue() -> str:
    """
    Continue program execution to see if the program still crashes after a state modification.
    IMPORTANT: The debugger state will be automatically reset to the original breakpoint after this command.
    """
    logger = get_logger(NAME)
    logger.info("Tool Call: debugger_continue()")

    # Check if session is available
    if GLOBAL_STATE.get("session") is None:
        error_msg = "Error: Debug session is not initialized. Cannot continue execution."
        logger.error(error_msg)
        return error_msg
    
    session = GLOBAL_STATE["session"]
    
    # First, continue and get the result
    try:
        response = session.llm_continue_and_get_result()
        logger.info(f"Tool Output (debugger_continue): '{response}'")

        # When the experiment succeeded (e.g. guard made the program exit normally),
        # the execution path has changed and _reproduce() will fail (breakpoint no longer
        # hit N times). Skip _reproduce and respawn the debugger so the next command
        # (run_to_line, assign, etc.) gets a clean session instead of a dead target.
        if "Reason: exited-normally" in response:
            logger.info(
                "Experiment succeeded (program did not crash); skipping _reproduce because "
                "execution path may have changed (e.g. guard). Respawn debugger for next command."
            )
            debugger_respawn()
            return response

        if "Program stopped at breakpoint" in response:
            logger.info("Program stopped at breakpoint; keeping debugger state for inspection.")
            return response

        if _is_process_not_launched_response(response):
            logger.info(
                "Current debug process is not launchable/continuable; respawning instead of reproducing."
            )
            debugger_respawn()
            return (
                f"{response} Debugger was reset. Use run_to_line to start a fresh run, "
                "or continue_to_line only after the program is stopped again."
            )

        if response.startswith("Experiment failed:"):
            logger.info(
                "Experiment failed and the target may have crashed/exited; respawning instead of "
                "reproducing synchronously to avoid blocking the tool call in LLDB/ASan cleanup."
            )
            debugger_respawn()
            return (
                f"{response} Debugger was reset after the failed experiment. "
                "Use run_to_line to start a fresh run before inspecting state again."
            )

        # CRITICAL: After a failed experiment, reset the state for the next command.
        logger.debug("Resetting debugger state after continue.")
        session._reproduce(session._profile)

        return response
    except Exception as e:
        error_msg = f"Error during debugger_continue: {str(e)}"
        logger.error(error_msg, exc_info=True)
        return error_msg


# @logf(NAME, True)
def submit(
    suspect_variable_names: List[str], 
    context_variable_names: List[str],
    debug_summary: str,
    llm_inferred_type: str = "unknown",
    known_angelic_values=None,
    estimated_safe_range: str = "",
    size_measurement_vars: List[str] = [],
    analysis_line: int = -1,
    analysis_file: str = None
) -> str:
    """
    Submit the analysis. Call this ONLY when you have confirmed your hypothesis via experimentation.
    
    Args:
        debug_summary: **REQUIRED**. A concise summary of your debugging findings (max 2-3 sentences). 
                      Explain the root cause and why you chose these variables. 
                      Example: "The crash is caused by pe_offset being larger than buffer size. 
                      I found that modifying pe_offset to 0 prevents the immediate crash, 
                      but we might also need to check the 'len' variable."
        analysis_line: **REQUIRED**. The exact line number where you performed your analysis.
                      This should be:
                      - The upstream location (e.g., variable assignment line like 8188) if you moved there using `run_to_line()`
                      - The crash line if you analyzed directly at the crash location without moving
                      The fuzzer will use this line to set breakpoints for mutation testing.
                      **Example**: If you called `run_to_line(8188)` and confirmed angelic values work at line 8188, 
                      then specify `analysis_line=8188`.
        analysis_file: Optional file path where you performed the analysis. If you used `run_to_line(line=104, file='token.c')` 
                      to analyze in a different file, you should specify that file path here. If not provided, uses the current 
                      file from GLOBAL_STATE. The fuzzer will use this file to set breakpoints for mutation testing.
                      **Example**: If you called `run_to_line(line=104, file='src/utils/token.c')` and analyzed there,
                      then specify `analysis_file='src/utils/token.c'`.
        known_angelic_values: Counterfactual seeds. Prefer a list of records shaped as
                      {"site": {"file": str, "line": int}, "variable": str, "value": str}.
                      Legacy scalar and variable-to-value formats are accepted and receive analysis_file/analysis_line
                      as their default site.
    """
    logger = get_logger(NAME)
    logger.info(f"Invoking submit with: suspect_variable_names={suspect_variable_names}, context_variable_names={context_variable_names}, llm_inferred_type='{llm_inferred_type}', known_angelic_values={known_angelic_values}, estimated_safe_range='{estimated_safe_range}', size_measurement_vars={size_measurement_vars}, analysis_line={analysis_line}, analysis_file={analysis_file}")

    global GLOBAL_STATE
    state_only_mode = state_only_no_angelic((GLOBAL_STATE.get("session") or object())._input.profile if GLOBAL_STATE.get("session") is not None else None)
    if state_only_mode:
        known_angelic_values = None
        estimated_safe_range = ""

    # Determine the file path to use for analysis
    if analysis_file is None:
        # Use the current file from GLOBAL_STATE if not specified
        file_path = GLOBAL_STATE["file"]
        logger.info(f"Using default file from GLOBAL_STATE: {file_path}")
    else:
        # Convert to absolute path if it's a relative path
        file_path = lsp_to_abs_path(str(analysis_file))
        if not os.path.exists(file_path):
            # lsp_to_abs_path might return the original path if not found
            # Check if it's already an absolute path, or try to construct one
            if not os.path.isabs(file_path):
                # Try constructing absolute path relative to GLOBAL_STATE["file"]'s directory
                default_file_dir = os.path.dirname(GLOBAL_STATE["file"])
                potential_path = os.path.join(default_file_dir, file_path)
                if os.path.exists(potential_path):
                    file_path = potential_path
                else:
                    error_msg = f"File not found: {analysis_file} (resolved to: {file_path}). Please provide a valid file path relative to the workspace or an absolute path."
                    logger.error(error_msg)
                    return error_msg
            else:
                error_msg = f"File not found: {analysis_file} (absolute path: {file_path}). Please verify the file path is correct."
                logger.error(error_msg)
                return error_msg
        logger.info(f"Using specified analysis_file: {file_path}")

    seed_site = {
        "file": file_path,
        "line": analysis_line,
        "role": "counterfactual_probe_site",
    }

    # Get demonic seed values (the values at the time of the crash).
    demonic_seed_values = {}
    demonic_seed_records = []
    unavailable_debugger_values = {}
    for var in suspect_variable_names:
        value = GLOBAL_STATE["session"].llm_print_value(var)
        if _is_unavailable_debugger_value(value):
            unavailable_debugger_values[var] = value
        else:
            demonic_seed_values[var] = value
            demonic_seed_records.append(
                {
                    "site": _normalize_seed_site(None, seed_site),
                    "variable": str(var),
                    "value": str(value),
                }
            )

    context_variables = {}
    for var in context_variable_names:
        value = GLOBAL_STATE["session"].llm_print_value(var)
        if _is_unavailable_debugger_value(value):
            unavailable_debugger_values[var] = value
        else:
            context_variables[var] = value
    
    # Get size variable values immediately
    size_variables = {}
    for var in size_measurement_vars:
        value = GLOBAL_STATE["session"].llm_print_value(var)
        if _is_unavailable_debugger_value(value):
            unavailable_debugger_values[var] = value
        else:
            size_variables[var] = value

    # Get variable types from the debugger as a fallback
    variable_types = []
    for var in suspect_variable_names:
        var_type = debugger_get_type(var)
        variable_types.append(var_type)
    
    angelic_seed_records, known_angelic_assignments, legacy_known_angelic_values = _normalize_angelic_seed_records(
        known_angelic_values,
        suspect_variable_names,
        seed_site,
    )

    GLOBAL_STATE["suspect_object"] = {
        "variable_names": suspect_variable_names,
        "debug_summary": debug_summary,
        "debugger_reported_type": variable_types[0] if variable_types else "unknown",
        "llm_inferred_type": llm_inferred_type,
        "context_variables": context_variables,
        "demonic_seed_values": demonic_seed_values,
        "demonic_seed_records": demonic_seed_records,
        "unavailable_debugger_values": unavailable_debugger_values,
        "angelic_seed_records": angelic_seed_records,
        # Compatibility representations for legacy fuzz/constraint consumers.
        "known_angelic_values": known_angelic_assignments,
        "known_angelic_values_legacy": legacy_known_angelic_values if legacy_known_angelic_values is not None else [],
        "known_angelic_assignments": known_angelic_assignments,
        "estimated_safe_range": estimated_safe_range,
        "size_variables": size_variables,
        "file": file_path,  # Use the file specified by agent or default from GLOBAL_STATE
        "line": analysis_line,  # Use the line specified by agent (where angelic values are effective)
    }

    logger.info(f"Constructed suspect object: {GLOBAL_STATE['suspect_object']}")
    
    response = "Analysis submitted. Your task is complete. You MUST reply with TERMINATE."
    logger.info(f"Tool Output (submit): '{response}'")
    return response


# @logf(NAME, True)
def add_guard(condition: str, return_value: str, file: str = None, line: int = -1) -> str:
    """
    Adds a 'functional guard' (hot-patch) that forces a return if a condition is met.
    This effectively injects 'if (condition) return return_value;' at runtime.
    
    Args:
        condition: C boolean expression (e.g., 'len > 100', 'ptr == NULL')
        return_value: Value to return (e.g., '-1', '0', 'NULL')
        file: Optional file path. Defaults to current file.
        line: Optional line number. Defaults to current line.
    """
    logger = get_logger(NAME)
    logger.info(f"Invoking add_guard(cond={condition}, ret={return_value}, file={file}, line={line})")
    
    target_file = file if file else GLOBAL_STATE["file"]
    target_line = line if line != -1 else GLOBAL_STATE["session"]._profile.line
    
    success, msg = debugger_add_functional_guard(target_file, int(target_line), condition, return_value)
    return msg


# @logf(NAME, True)
def skip() -> None:
    """
    Skip current conversation.
    """
    get_logger(NAME).info(f"Tool Call: skip()")

    global GLOBAL_STATE
    GLOBAL_STATE["skip"] = True
    get_logger(NAME).info(f"Tool Output (skip): Frame analysis will be skipped.")


def get_generic_agent(use_constraint, use_crash_line_mode=False, bug_type_profile=None, profile=None):
    """
    Create a generic agent for debug analysis.
    
    Args:
        use_constraint: Whether to use constraint-based analysis (legacy parameter, kept for compatibility)
        use_crash_line_mode: If True, use crash line analysis mode (no upstream movement).
                             If False, use upstream interception mode (default).
    """
    state_only_mode = state_only_no_angelic(profile)
    if state_only_mode:
        system_prompt = SYSTEM_PROMPT_NO_ANGELIC
        submit_description = (
            "Submit the final observation-only crash analysis. Provide suspect variables, context variables, "
            "a root-cause summary, and the analysis_line/analysis_file where the observed state supports the hypothesis. "
            "Do not provide known_angelic_values."
        )
    elif use_crash_line_mode:
        system_prompt = SYSTEM_PROMPT_CRASH_LINE
        submit_description = "Submit the final analysis after confirming the suspect variables. **REQUIRED**: You MUST specify the `analysis_line` parameter to indicate the exact line number where you performed your analysis. Since you are analyzing at the crash line, specify `analysis_line={crash_line}` (the crash line number). **IMPORTANT**: If you used `run_to_line(line=104, file='token.c')` or `continue_to_line(line=104, file='token.c')` to analyze in a different file, you MUST also specify the `analysis_file` parameter to indicate which file you analyzed. Example: `submit(..., analysis_line=104, analysis_file='src/utils/token.c')`. These parameters will be used by the fuzzer for mutation testing."
    else:
        system_prompt = SYSTEM_PROMPT
        submit_description = "Submit the final analysis after confirming the suspect variables. **REQUIRED**: You MUST specify the `analysis_line` parameter to indicate the exact line number where you performed your analysis and where angelic values are effective. This should be the upstream location (e.g., variable assignment line) where you moved using `run_to_line()` or `continue_to_line()`, or the crash line if you did not move. **IMPORTANT**: If you used `run_to_line(line=104, file='token.c')` or `continue_to_line(line=104, file='token.c')` to analyze in a different file, you MUST also specify the `analysis_file` parameter to indicate which file you analyzed. Examples: `submit(..., analysis_line=8188)` if you analyzed at line 8188 in the current file, or `submit(..., analysis_line=104, analysis_file='src/utils/token.c')` if you analyzed at line 104 in token.c. These parameters will be used by the fuzzer to set breakpoints for mutation testing."
    system_prompt += build_debugger_session_protocol(
        role="DebugAgent",
        initial_process_state="stopped at the reported crash site",
        allow_mutation=not state_only_mode,
    )
    if bug_type_profile and not state_only_mode:
        system_prompt += build_stage_prompt_overlay("debug", bug_type_profile)

    agent = GenericAgent(
        "Crosshair", system_prompt
    )
    agent.register_hook(run_to_line, "Start a fresh program run, stop at a specific line, and return the function containing that line, truncated to 100 lines if needed. Use this when you want to inspect the state from program start. You can specify an optional 'file' parameter to set the breakpoint in a different file. If 'file' is not provided, it defaults to the current file. Example: run_to_line(line=104, file='src/utils/token.c') to set breakpoint in a different file.")
    agent.register_hook(continue_to_line, "Continue the current stopped process to a specific line without restarting, and return the function containing that line, truncated to 100 lines if needed. Use this after you are already stopped on the relevant execution path and want to inspect a downstream line in the same run. If the current process is not stopped or has exited, use run_to_line instead.")
    agent.register_hook(list_breakpoints, "List currently tracked debugger breakpoints for this session. Use this when you are unsure whether you are continuing an existing stopped process, starting a fresh run, or recovering after debugger instability.")
    agent.register_hook(
        print_value,
        "Print the value of an expression at the current stop. Prefer simple subexpressions first; if a complex expression "
        "like obj->field[i] fails with Invalid expression, MI_UNSTABLE, or timeout, split it into simpler steps instead of "
        "assuming the variable was optimized out."
    )
    agent.register_hook(
        read_memory,
        "Read raw target memory at a concrete address. Use this when print_value times out on array/struct expressions. "
        "This tool only accepts concrete addresses such as 0x7fffffffcb98, not C expressions like r->arr[0]. "
        "Example: print_value('r') -> '0x7fffffffcb00', then read_memory(address='0x7fffffffcb00', size=2, count=16, fmt='x'). "
        "Use size=2 for int16_t/mz_int16 data and size=4 for int/uint32_t data."
    )
    agent.register_hook(file_content, "Get the content of a file. You can specify an optional 'file' parameter to view a different file. If 'file' is not provided, it defaults to the crash file. Example: file_content(start_line=100, end_line=120, file='src/token.c') to view a different file.")
    agent.register_hook(search_in_repo, "Search for a keyword/regex under a file or directory path and return matching line numbers with small context. Use this to find symbols, assignments, guards, and function references before paging large files with file_content.")
    agent.register_hook(debugger_backtrace, "Get the call stack (backtrace) showing the current function and all calling functions. Use this to analyze the call chain and identify upstream locations where you can set breakpoints.")
    if not state_only_mode:
        agent.register_hook(debugger_assign, "Assign a new value to a variable. Use this to test a hypothesis.")
        agent.register_hook(debugger_assign_expression, "Execute a complete assignment expression. Use this for complex assignments like const_cast, type casts, or dereferencing. Examples: 'const_cast<uint32_t&>(pe_offset) = 0', '*(&variable) = value'.")
        agent.register_hook(add_guard, "Adds a 'functional guard' (hot-patch) that forces a return if a condition is met. This effectively injects 'if (condition) return return_value;' at runtime at the specified location.")
        agent.register_hook(_debugger_continue, "Continue program execution after assigning a value to see if it still crashes.", name="debugger_continue")

    agent.register_hook(submit, submit_description)
    agent.register_hook(skip, "Skip the current conversation if no suspects can be found.")

    return agent

def get_generic_agent_crash_line(use_constraint=None):
    """
    Convenience function to get an agent configured for crash line analysis mode.
    This is equivalent to calling get_generic_agent(use_constraint, use_crash_line_mode=True).
    """
    return get_generic_agent(use_constraint or True, use_crash_line_mode=True)


def _read_source_line(file_path: str, line: int) -> str:
    if not file_path or not os.path.exists(file_path) or line < 1:
        return ""
    try:
        with open(file_path, "r", errors="replace") as f:
            for idx, text in enumerate(f, start=1):
                if idx == line:
                    return text.rstrip("\n")
    except OSError:
        return ""
    return ""


def _extract_crash_variable_list(file_path: str, line: int) -> str:
    source_line = _read_source_line(file_path, line)
    if not source_line:
        return "variables used by the crash expression"

    tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*(?:\s*(?:->|\.)\s*[A-Za-z_][A-Za-z0-9_]*)*", source_line)
    keywords = {
        "if", "else", "for", "while", "switch", "case", "return", "sizeof",
        "true", "false", "NULL", "nullptr", "static", "const", "struct",
        "class", "int", "char", "short", "long", "float", "double", "void",
        "unsigned", "signed", "size_t", "ssize_t",
    }
    out = []
    seen = set()
    for token in tokens:
        compact = re.sub(r"\s+", "", token)
        base = compact.split("->", 1)[0].split(".", 1)[0]
        if base in keywords or compact in keywords or compact in seen:
            continue
        seen.add(compact)
        out.append(compact)
        if len(out) >= 8:
            break
    return "\n".join(out) if out else "variables used by the crash expression"


def _profile_bug_description(profile: dict | None) -> str:
    if not isinstance(profile, dict):
        return ""
    description = str(profile.get("bug_description") or "").strip()
    if not description and profile.get("secbench"):
        # Backward compatibility for profiles generated before bug_description
        # was separated from the legacy constraint field.
        description = str(profile.get("constraint") or "").strip()
    return description


def _format_bug_description(profile: dict | None) -> str:
    return format_bug_context(profile)


# =============================================================================
# Debug agent
# =============================================================================


class DebugInput:
    def __init__(self, profile, error, func, file, line, retry_observation: str = ""):
        self.profile = profile
        self.error = error
        self.func = func
        self.file = file
        self.line = line
        self.retry_observation = retry_observation


class DebugOutput:
    def __init__(self):
        # { "root_cause": "", "location": "" }
        self.analysis = []


class DebugProfile:
    def __init__(
        self,
        file: str,
        line: int,
        count: int,
        is_fallback: bool = False,
        already_stopped: bool = False,
    ):
        self.file = file
        self.line = line
        self.count = count
        self.is_fallback = is_fallback
        self.already_stopped = already_stopped


class DebugSession:
    def __init__(self, i: DebugInput):
        self._input = i
        self.logger = get_logger(NAME)
        try:
            input_line = int(i.line)
        except (TypeError, ValueError):
            input_line = -1
        if (
            not i.file
            or i.file == "N/A"
            or input_line <= 0
        ):
            raise RuntimeError(
                f"Cannot start debug session without a valid reproduce frame: {i.file}:{i.line}"
            )

        # profile to reproduce the crash
        self._profile = self._get_debug_profile(i.file, i.line)
        if self._profile is None:
            self.logger.warning(
                "Failed to get crash debug profile at %s:%s; falling back to "
                "the crash frame parsed during reproduction.",
                i.file,
                i.line,
            )
            self._profile = DebugProfile(i.file, i.line, 0, is_fallback=True)

        self._use_constraint = self._input.profile.get("use_constraint", True)
        # Option to use crash line analysis mode (direct analysis at crash line, no upstream movement)
        self._use_crash_line_mode = self._input.profile.get("use_crash_line_mode", False) or self._profile.is_fallback

    @logm(NAME, True)
    def run(self, logger=None) -> DebugOutput:
        output = DebugOutput()

        logger.warning("Fetching backtrace")
        if self._profile.is_fallback:
            logger.warning(
                "Using fallback debug profile without `_reproduce()`. "
                "Analyzing synthetic crash frame derived from reproduce output."
            )
            frames = [(0, self._input.func, self._input.file, self._input.line)]
        else:
            try:
                self._reproduce(self._profile)
                frames = self._get_frames()
            except RuntimeError as exc:
                logger.warning(
                    "Failed to reproduce the selected debug breakpoint; "
                    "falling back to the crash frame parsed during reproduction. "
                    "Details: %s",
                    exc,
                )
                self._profile = DebugProfile(
                    self._input.file,
                    self._input.line,
                    0,
                    is_fallback=True,
                )
                self._use_crash_line_mode = True
                frames = [(0, self._input.func, self._input.file, self._input.line)]
        logger.debug("Frames: %s", frames)

        if len(frames) == 0:
            logger.error("No frames to analyze")
            return output

        logger.warning("Analyzing frames")
        for frame in frames:
            analysis = self._analyze_frame(frame)
            if analysis is not None:
                output.analysis.append(analysis)

        logger.info(
            "Saving root cause analysis to %s", self._input.profile["root_cause_output"]
        )
        # Log each suspect_object's line before saving
        for idx, suspect_obj in enumerate(output.analysis):
            if suspect_obj:
                logger.info(f"Suspect object {idx} line before saving: {suspect_obj.get('line')}")
        dump_json(output.analysis, self._input.profile["root_cause_output"])

        logger.warning("Root cause analsis completed")

        return output

    @logm(NAME, True)
    def _get_debug_profile(self, file: str, line: int, logger=None) -> DebugProfile:
        """
        Some breakpoints may be triggered multiple times till
        the crash, so we try to find the last breakpoint hit.
        """
        debugger_clear_breakpoints() # Ensure clean state before profiling
        
        # Save original file and line parameters for error messages
        original_file = file
        original_line = line
        
        result = debugger_set_breakpoint(file, line)[0]
        if "Invalid breakpoint" in result:
            logger.error("Invalid breakpoint: %s", result)
            debugger_clear_breakpoints()
            return None

        hit_file = None
        hit_line = None

        dbg_out, target_output = debugger_run()
        logger.info(f"Initial debugger run result: reason={dbg_out.get('reason')}, file={dbg_out.get('file')}, line={dbg_out.get('line')}")
        
        count = 0  # one less than the actual count
        max_breakpoint_hits = int(os.environ.get("STALKER_MAX_BP_HITS", "500"))
        while dbg_out["reason"] == "breakpoint-hit":
            if count >= max_breakpoint_hits:
                logger.warning(
                    f"Breakpoint hit {count} times (limit {max_breakpoint_hits}). "
                    "Likely in hot loop; using current state to avoid infinite loop."
                )
                break
            hit_file = dbg_out["file"] if dbg_out["file"] is not None else hit_file
            hit_line = dbg_out["line"] if dbg_out["line"] is not None else hit_line
            dbg_out, target_output = debugger_continue()
            count += 1
        
        # Log the final stop reason
        final_reason = dbg_out.get("reason")
        logger.info(f"Program stopped with reason: {final_reason}")

        if hit_file is None and final_reason == "signal-received":
            signal_file = dbg_out.get("file")
            signal_line = dbg_out.get("line")
            try:
                same_line = int(signal_line) == int(original_line)
            except (TypeError, ValueError):
                same_line = False
            same_file = (
                signal_file
                and original_file
                and os.path.basename(str(signal_file)) == os.path.basename(str(original_file))
            )
            if same_file and same_line:
                profile_file = original_file if os.path.exists(str(original_file)) else signal_file
                logger.info(
                    "Signal received at requested crash location %s:%s; using it as debug profile.",
                    profile_file,
                    signal_line,
                )
                return DebugProfile(
                    profile_file,
                    int(signal_line),
                    1,
                    already_stopped=True,
                )
        
        debugger_clear_breakpoints()

        if hit_file is None:
            # Check for ASan errors in target_output first, even if program exited normally
            # ASan errors may cause program to exit normally (via exit handlers) but still indicate a crash
            has_asan_error = False
            asan_error_msg = None
            
            # Log target_output for debugging
            logger.debug(f"[DEBUG] Checking for ASan errors in target_output (length: {len(target_output) if target_output else 0})")
            if target_output:
                logger.debug(f"[DEBUG] First 500 chars of target_output: {target_output[:500]}")
            
            if target_output:
                # Check for ASan errors (real crashes, not just report breakpoint)
                # Pattern: ==PID==ERROR: AddressSanitizer
                asan_error_pattern = re.compile(r"==\d+==ERROR:\s*AddressSanitizer", re.IGNORECASE)
                asan_match = asan_error_pattern.search(target_output)
                if asan_match:
                    has_asan_error = True
                    # Extract a snippet of the ASan error for context
                    error_start = asan_match.start()
                    error_snippet = target_output[error_start:error_start+200]
                    asan_error_msg = f"ASan error detected: {error_snippet}..."
                    logger.warning(f"ASan error detected in target_output even though program exited normally: {asan_error_msg}")
                else:
                    logger.debug(f"[DEBUG] No ASan error pattern found in target_output")
            else:
                logger.debug(f"[DEBUG] target_output is None or empty")
            
            # If we have an ASan error, we should still consider this a crash and use the original breakpoint location
            if has_asan_error:
                logger.warning(f"Breakpoint at {original_file}:{original_line} was not hit, but ASan error was detected in output.")
                logger.warning("Using original breakpoint location as fallback since ASan error indicates a crash occurred.")
                # Use the original file and line as a fallback
                try:
                    line_int = int(original_line) if original_line is not None else None
                    if line_int is None:
                        logger.error(f"Cannot use original line as fallback: line is None")
                    else:
                        profile = DebugProfile(original_file, line_int, 0, is_fallback=True)
                        logger.info(f"Debug profile (fallback): {profile.file}:{profile.line} (count: {profile.count})")
                        return profile
                except (ValueError, TypeError) as e:
                    logger.error(f"Failed to convert original line to integer: {original_line}, error: {e}")
            
            # Provide detailed error information
            error_details = []
            error_details.append(f"Breakpoint at {original_file}:{original_line} was not hit.")
            error_details.append(f"Program stopped with reason: {final_reason}")
            
            if final_reason == "signal-received":
                signal_name = dbg_out.get("signal_name", "unknown")
                signal_meaning = dbg_out.get("signal_meaning", "")
                signal_info = f" ({signal_name})" if signal_name != "unknown" else ""
                if signal_meaning:
                    signal_info += f" - {signal_meaning}"
                error_details.append(f"Signal: {signal_info}")
                error_details.append("The program crashed before reaching the breakpoint. This usually means:")
                error_details.append("1. The breakpoint location is after the crash point, or")
                error_details.append("2. The breakpoint is in a code path that was not executed.")
            elif final_reason == "exited-normally":
                error_details.append("The program exited normally before reaching the breakpoint.")
                error_details.append("This usually means:")
                error_details.append("1. The breakpoint is in unreachable code or after program termination,")
                error_details.append("2. The breakpoint location is not in the execution path,")
                error_details.append("3. Or the program terminated early due to ASan or other errors.")
                # Check if ASan report breakpoint was hit
                if target_output and "AddressSanitizer report breakpoint hit" in target_output:
                    error_details.append("\nNOTE: An AddressSanitizer report breakpoint was encountered and automatically continued.")
                    error_details.append("This may have caused the program to exit before reaching your breakpoint.")
                    error_details.append("Suggestions:")
                    error_details.append("- Verify the breakpoint is in the correct file and line number")
                    error_details.append("- Check if the breakpoint is in the execution path (not in unreachable code)")
                    error_details.append("- Consider setting the breakpoint at an earlier location in the execution flow")
            elif final_reason == "error":
                error_msg = dbg_out.get("error", "Unknown error")
                error_details.append(f"Debugger error: {error_msg}")
            
            if asan_error_msg:
                error_details.append(f"\n{asan_error_msg}")
            
            error_msg = "\n".join(error_details)
            logger.error(f"Breakpoint not hit:\n{error_msg}")
            return None

        # Ensure line is an integer (dbg_out["line"] might be a string)
        try:
            line_int = int(hit_line) if hit_line is not None else None
            if line_int is None:
                logger.error("Invalid line number: None")
                return None
        except (ValueError, TypeError) as e:
            logger.error(f"Failed to convert line to integer: {hit_line} (type: {type(hit_line)}), error: {e}")
            return None

        profile_file = hit_file
        if (
            original_file
            and hit_file
            and os.path.basename(str(original_file)) == os.path.basename(str(hit_file))
            and os.path.exists(str(original_file))
        ):
            profile_file = original_file
            logger.info(
                "Using reproduce crash file %s instead of LLDB basename %s",
                original_file,
                hit_file,
            )

        profile = DebugProfile(profile_file, line_int, count)
        logger.info(
            "Debug profile: %s:%s (%s)", profile.file, profile.line, profile.count
        )

        return profile

    @logm(NAME, True)
    def _reproduce(self, profile: DebugProfile, logger=None):
        """
        Reset the debugger to a certain breakpoint.
        """
        if getattr(profile, "already_stopped", False):
            debugger_record_last_position(profile.file, profile.line)
            return

        # Re-arming the same location without clearing first accumulates duplicate
        # breakpoints over repeated experiments, which slows execution and skews
        # later hit counts. Start each reproduction from a clean breakpoint set.
        debugger_clear_breakpoints()
        debugger_set_breakpoint(profile.file, profile.line)
        dbg_output, _ = debugger_run()
        count = 1
        while count < profile.count:
            dbg_output, _ = debugger_continue()
            count += 1
        # debugger_clear_breakpoints() - Removed to keep breakpoint active for experimentation

        if dbg_output["reason"] == "breakpoint-hit":
            debugger_record_last_position(profile.file, profile.line)
        elif dbg_output.get("reason") == "signal-received":
            signal_file = dbg_output.get("file")
            signal_line = dbg_output.get("line")
            try:
                same_line = int(signal_line) == int(profile.line)
            except (TypeError, ValueError):
                same_line = False
            same_file = (
                signal_file
                and profile.file
                and os.path.basename(str(signal_file)) == os.path.basename(str(profile.file))
            )
            if same_file and same_line:
                debugger_record_last_position(profile.file, profile.line)
                return
            raise RuntimeError(
                "Failed to reproduce profile:\n"
                f"Profile: {profile.__dict__}\n"
                f"Reason: signal-received\n"
                f"Signal location: {signal_file}:{signal_line}"
            )
        else:
            # Provide more detailed error message
            reason = dbg_output.get("reason", "unknown")
            note = dbg_output.get("note", "")
            error_type = dbg_output.get("error", "")
            
            error_msg = (
                "Failed to reproduce profile:\n"
                f"Profile: {profile.__dict__}\n"
                f"Reason: {reason}"
            )
            if note:
                error_msg += f"\nNote: {note}"
            if error_type:
                error_msg += f"\nError type: {error_type}"
            
            # Add helpful suggestions based on reason
            if reason == "error" and error_type == "timeout":
                error_msg += (
                    "\n\nThis appears to be a timeout error. Possible causes:"
                    "\n1. The breakpoint location may be unreachable or in dead code"
                    "\n2. The program may not be executing the code path containing the breakpoint"
                    "\n3. LLDB may be in an inconsistent state (try restarting)"
                    "\n4. The breakpoint file/line may be incorrect"
                )
            elif reason == "exited-normally":
                error_msg += (
                    "\n\nThe program exited normally before reaching the breakpoint."
                    "\nThis usually means the breakpoint is not in the execution path."
                )
            
            raise RuntimeError(error_msg)

    @logm(NAME, True)
    def _get_frames(self, logger=None) -> List[Tuple[str, str, int]]:
        """
        Get all the stackframes. Call it after run/reproduce.
        """
        frames = []
        for frame in debugger_backtrace():
            frame_id, function, filename, line = parse_lldb_frame(frame)
            if frame_id is None:
                logger.warn("Skipping invalid frame: %s", frame)
                continue
            else:
                logger.debug("Frame: %s", frame)
            frames.append((frame_id, function, filename, line))

        source_frames = []
        skipped_frames = []
        for frame in frames:
            resolved_file = self._resolve_frame_source_file(frame, logger=logger)
            if resolved_file and os.path.exists(resolved_file):
                source_frames.append(frame)
            else:
                skipped_frames.append((frame, resolved_file))

        if source_frames:
            for frame, resolved_file in skipped_frames:
                logger.warning(
                    "Skipping non-project frame %s because source file is unavailable: %s",
                    frame,
                    resolved_file,
                )
        else:
            source_frames = frames

        # first pick selected frames
        selected_frames = []
        for frame in source_frames:
            if frame[1] in self._input.profile["functions"]:
                selected_frames.append(frame)
                logger.debug("Selected frame: %s", frame)

        if selected_frames == []:
            logger.warning("No selected frames, picking first 3 frames")
            for frame in source_frames:
                selected_frames.append(frame)

        if len(selected_frames) > 3:
            logger.warning("Pick first 3 frames")
            selected_frames = selected_frames[:3]

        return selected_frames

    def _resolve_frame_source_file(self, frame, logger=None) -> str:
        def _safe_abs_path(path: str) -> str:
            if not path:
                return ""
            try:
                return lsp_to_abs_path(path)
            except Exception as exc:
                logger.warning(
                    "Failed to resolve source path %s via LSP: %s. Falling back to raw path.",
                    path,
                    exc,
                )
                return path

        mapped_file = None
        if "function_map" in self._input.profile:
            mapped_file = self._input.profile["function_map"].get(frame[1], None)
        if mapped_file is not None:
            return _safe_abs_path(mapped_file)

        input_file = getattr(self._input, "file", None)
        frame_file = frame[2]
        if (
            input_file
            and frame_file
            and os.path.basename(str(input_file)) == os.path.basename(str(frame_file))
            and os.path.exists(str(input_file))
        ):
            logger.info(
                "Using reproduce crash file %s instead of LLDB frame file %s",
                input_file,
                frame_file,
            )
            return _safe_abs_path(input_file)

        return _safe_abs_path(frame_file)

    @logm(NAME, True)
    def _analyze_frame(self, frame, logger=None):
        """
        frame: (frame_id, function, filename, line)
        """
        global GLOBAL_STATE
        global ACCUMULATED_ANALYSIS

        logger.warning("Anayzing frame: %s", frame)

        # prepare global state
        reset_global_state()
        GLOBAL_STATE["session"] = self

        GLOBAL_STATE["file"] = self._resolve_frame_source_file(frame, logger=logger)
        if not GLOBAL_STATE["file"] or not os.path.exists(GLOBAL_STATE["file"]):
            logger.warning(
                "Skipping frame %s because source file is unavailable for LSP analysis: %s",
                frame,
                GLOBAL_STATE["file"],
            )
            return None

        # invoke LLM
        function_name = frame[1] if frame[1] not in [None, "", "N/A"] else ""
        function = lsp_get_function(GLOBAL_STATE["file"], function_name) if function_name else ""
        if function == "":
            logger.warning(
                "Failed to get function body for %s. Falling back to local code context around line %s.",
                frame[1],
                frame[3],
            )
            start_line = max(1, int(frame[3]) - 40)
            end_line = int(frame[3]) + 40
            function = file_get_decorated_content(GLOBAL_STATE["file"], start_line, end_line)

        # Choose agent and prompt based on mode
        bug_type_profile = infer_bug_type_profile(
            profile=getattr(self._profile, "__dict__", {}),
            error_text=self._input.error,
            function_body=function,
            classification_mode="surface",
        )
        agent = get_generic_agent(
            self._use_constraint,
            use_crash_line_mode=self._use_crash_line_mode,
            bug_type_profile=bug_type_profile,
            profile=self._input.profile,
        )
        
        prior_analysis = ""
        if ACCUMULATED_ANALYSIS != "":
            prior_analysis = PRIOR_ANALYSIS.format(ACCUMULATED_ANALYSIS)
        
        # The entire multi-step interaction is handled by the autogen framework within a single initiate_chat call.
        # The loop is managed internally by the agent based on tool calls and TERMINATE signals.
        # Ensure line is an integer (it might be a string from debugger output).
        # In fallback mode we synthesize the crash frame from reproduce output, so
        # prompt-driving crash_line must use frame[3] (reproduce crash line),
        # not the fallback breakpoint profile's line.
        crash_line = None
        try:
            if getattr(self._profile, "is_fallback", False):
                crash_line = int(frame[3]) if frame[3] is not None else None
            else:
                if isinstance(self._profile.line, str):
                    crash_line = int(self._profile.line)
                elif isinstance(self._profile.line, int):
                    crash_line = self._profile.line
                else:
                    logger.error(
                        f"Unexpected type for profile.line: {type(self._profile.line)}, value: {self._profile.line}"
                    )
                    # Fallback: try to use frame line number
                    crash_line = int(frame[3]) if frame[3] is not None else None
        except (ValueError, TypeError, IndexError) as e:
            logger.error(f"Failed to determine crash_line: {e}")
            crash_line = None
        
        if crash_line is None:
            logger.error("Unable to determine crash line, cannot proceed")
            return None
        
        start_line = max(1, crash_line - 20)
        
        state_only_mode = state_only_no_angelic(self._input.profile)

        # Choose the appropriate initial prompt based on mode
        if state_only_mode:
            initial_prompt = INITIAL_PROMPT_NO_ANGELIC
            logger.info("Using state-only no-angelic analysis prompt")
        elif self._use_crash_line_mode:
            initial_prompt = INITIAL_PROMPT_CRASH_LINE
            logger.info("Using crash line analysis mode (direct analysis at crash line)")
        else:
            initial_prompt = INITIAL_PROMPT
            logger.info("Using upstream interception mode (move to upstream location)")
        
        prompt_file = GLOBAL_STATE["file"] if getattr(self._profile, "is_fallback", False) else self._profile.file
        prompt_line = crash_line if getattr(self._profile, "is_fallback", False) else self._profile.line
        bug_description = _format_bug_description(self._input.profile)

        if state_only_mode:
            prompt_text = initial_prompt.format(
                crash_file=prompt_file,
                crash_line=prompt_line,
                crash_log=self._input.error,
                suspect_function_code=function,
                bug_description=bug_description,
                accumulated=prior_analysis,
                crash_function=function_name or self._input.func or "the crashing function",
                context_start_line=start_line,
                crash_variable_list=_extract_crash_variable_list(prompt_file, int(crash_line)),
            )
        else:
            prompt_text = initial_prompt.format(
                file=prompt_file,
                line=prompt_line,
                start_line=start_line,
                error=self._input.error,
                body=function,
                bug_description=bug_description,
                accumulated=prior_analysis,
            )
            prompt_text += build_stage_prompt_overlay("debug", bug_type_profile)
        retry_observation = str(getattr(self._input, "retry_observation", "") or "").strip()
        if retry_observation:
            prompt_text += (
                "\n\n## Retry Observation\n\n"
                f"{retry_observation}\n\n"
                "Your previous DebugAgent response was not usable because it did not submit a concrete root-cause suspect. "
                "Retry the analysis from a different frame, upstream location, guard, assignment, or caller context. "
                "Do not submit an empty RCA. The next submit must include a concrete `debug_summary`, "
                "`analysis_file`, `analysis_line`, and at least one suspect variable or expression that PatchAgent can act on.\n"
            )
        chat = agent.initiate(prompt_text)
        self._save_chat(frame[0], chat)

        # After the chat terminates (because the LLM called submit), we check the global state.
        if GLOBAL_STATE["skip"]:
            logger.warning("Frame analysis skipped")
            return None
        
        if GLOBAL_STATE["suspect_object"] is None:
            logger.error("Incomplete analysis, no suspect object was submitted.")
            return None

        # The process has likely terminated after a successful experiment.
        # We must NOT send any more commands to the debugger.
        # We just need to collect the data and return.
        # Use the analysis_line specified by agent in submit(), or fallback to crash line if not specified
        if GLOBAL_STATE["suspect_object"]["line"] == -1:
            logger.warning(f"Agent did not specify analysis_line in submit(). Using crash line {frame[3]} as fallback.")
            GLOBAL_STATE["suspect_object"]["line"] = frame[3]
        else:
            logger.info(f"Using agent-specified analysis line {GLOBAL_STATE['suspect_object']['line']} (crash line was {frame[3]})")
            # Ensure we use the agent-specified line, do NOT override it with frame[3]
            # The suspect_object["line"] from submit() is already correct
        # Attach debugger agent's summary to suspect_object for constraint generation
        # (History is discarded to save tokens and improve focus)
        GLOBAL_STATE["suspect_object"]["function_name"] = frame[1]
        GLOBAL_STATE["suspect_object"]["surface_bug_type_profile"] = bug_type_profile
        GLOBAL_STATE["suspect_object"]["bug_type_profile"] = infer_bug_type_profile(
            profile=getattr(self._profile, "__dict__", {}),
            reproduce_result=getattr(self._input, "reproduce_result", None),
            suspect_object=GLOBAL_STATE["suspect_object"],
            debug_summary=GLOBAL_STATE["suspect_object"].get("debug_summary", ""),
            function_body=function,
            error_text=self._input.error,
            classification_mode="root_cause",
        )
        
        # Log final suspect_object to verify line is correct
        logger.info(f"Returning suspect_object with line={GLOBAL_STATE['suspect_object']['line']}")

        return GLOBAL_STATE["suspect_object"]

    def _save_chat(self, chat_id, chat):
        filename = os.path.join(
            self._input.profile["chat_dir"], f"debug-{chat_id}.json"
        )
        dump_json(chat, filename)

    def _find_enclosing_function_range(self, file: str, line: int) -> tuple[int, int] | None:
        try:
            symbols = lsp_instance().document_symbol(file)
        except Exception:
            return None

        best_range = None
        best_size = None
        stack = list(symbols or [])
        while stack:
            symbol = stack.pop()
            stack.extend(symbol.get("children") or [])
            location = symbol.get("location") or {}
            range_info = location.get("range") or symbol.get("range") or {}
            start = range_info.get("start") or {}
            end = range_info.get("end") or {}
            start_line = start.get("line")
            end_line = end.get("line")
            if start_line is None or end_line is None:
                continue
            start_line += 1
            end_line += 1
            if start_line <= line <= end_line:
                size = end_line - start_line + 1
                if best_size is None or size < best_size:
                    best_range = (start_line, end_line)
                    best_size = size
        return best_range

    def _function_context_for_line(self, file: str, line: int, max_lines: int = 100) -> str:
        function_range = self._find_enclosing_function_range(file, line)
        if function_range is None:
            return file_get_decorated_content(file, max(1, line - 3), line + 3)

        start_line, end_line = function_range
        if end_line - start_line + 1 > max_lines:
            before = max_lines // 2
            start_line = max(start_line, line - before)
            end_line = min(end_line, start_line + max_lines - 1)
            if line > end_line:
                end_line = line
                start_line = max(function_range[0], end_line - max_lines + 1)

        return file_get_decorated_content(file, start_line, end_line)

    def _mark_breakpoint_line(self, decorated_content: str, line: int) -> str:
        marked_lines = []
        marker = " // breakpoint set here"
        for content_line in decorated_content.splitlines():
            match = re.match(r"^\s*(\d+)\s", content_line)
            if match and int(match.group(1)) == line and marker not in content_line:
                content_line = content_line.rstrip() + marker
            marked_lines.append(content_line)
        return "\n".join(marked_lines)

    def _format_stop_observation(self, file: str, line: int, hit_file: str = None, hit_line=None) -> str:
        display_file = hit_file or file
        display_line = hit_line or line
        try:
            line_int = int(display_line)
        except (TypeError, ValueError):
            line_int = int(line)

        response = f"Program stopped at {display_file}:{display_line}\n"
        response += self._mark_breakpoint_line(self._function_context_for_line(file, line_int), line_int)
        if self._use_constraint:
            response += (
                "\n"
                "Derive the constraint the program should meet at the current line based on the initial constraint at the crash point. "
                "You can get the constraint here by inspecting the code segments backward the control flow from the crash point to the current line. "
                "You can also use the commands given above. "
                "Output the constraint and continue the analysis."
            )
        return response

    def _navigate_to_line(self, file: str, line: int, logger=None) -> tuple[bool, str]:
        """
        Lightweight navigation helper for `run_to_line`.
        Semantics:
        - start from a clean process
        - set a breakpoint at the requested line
        - run once and stop there if reachable

        This intentionally avoids `_get_debug_profile() + _reproduce()` because
        `run_to_line` is meant to be a navigation tool, not a heavy profiling pass.
        """
        if logger is None:
            logger = self.logger
        logger.info("Navigating to requested analysis point %s:%s", file, line)

        debugger_clear_breakpoints()
        result = debugger_set_breakpoint(file, line)[0]
        if "Invalid breakpoint" in result:
            logger.error("Invalid breakpoint while navigating: %s", result)
            debugger_clear_breakpoints()
            return (
                False,
                "Invalid breakpoint location, "
                "perhaps the line is not executable or the file is incorrect. "
                "Choose an executable line earlier in the same control-flow path.",
            )

        try:
            dbg_output, target_output = debugger_run()
        except Exception as e:
            logger.error("Failed to navigate to %s:%s: %s", file, line, e)
            return (
                False,
                "Failed to launch the program and navigate to the requested line. "
                f"Debugger error: {e}",
            )

        reason = dbg_output.get("reason")
        hit_file = dbg_output.get("file")
        hit_line = dbg_output.get("line")

        if reason == "breakpoint-hit":
            logger.info("Navigation hit breakpoint at %s:%s", hit_file, hit_line)
            debugger_record_last_position(file, line)
            return True, self._format_stop_observation(file, line, hit_file, hit_line)

        is_sanitizer_crash, sanitizer_msg = check_sanitizer_error(target_output, dbg_output)
        if is_sanitizer_crash:
            logger.warning(
                "Navigation failed before hitting %s:%s because the program crashed first: %s",
                file,
                line,
                sanitizer_msg,
            )
            return (
                False,
                "The program crashed before reaching the requested line. "
                f"{sanitizer_msg} "
                "Choose an earlier line on the same crash path, ideally closer to the variable assignment or guard that influences the crash.",
            )

        if reason == "exited-normally":
            return (
                False,
                "The program exited normally before reaching the requested line. "
                "This usually means the line is not on the current execution path. "
                "Choose an earlier or more directly related line.",
            )

        if reason == "signal-received":
            signal_name = dbg_output.get("signal_name", "unknown")
            signal_meaning = dbg_output.get("signal_meaning", "")
            signal_info = f"{signal_name}" if signal_name != "unknown" else "a fatal signal"
            if signal_meaning:
                signal_info += f" ({signal_meaning})"
            return (
                False,
                "The program received "
                f"{signal_info} before the requested line was hit. "
                "Choose an earlier line in the same function or at the immediate upstream assignment/guard.",
            )

        if reason == "error":
            error_type = dbg_output.get("error", "unknown error")
            note = dbg_output.get("note", "")
            details = f" ({note})" if note else ""
            return (
                False,
                f"Debugger could not navigate to the requested line due to {error_type}{details}. "
                "Try a different line or restart the analysis path.",
            )

        return (
            False,
            f"Failed to stop at the requested line. Stop reason was: {reason}. "
            "Choose an earlier line or a different control-flow point.",
        )

    @logm(NAME, True)
    def llm_run_to_line(self, file, line, logger=None) -> str:
        success, response = self._navigate_to_line(file, line, logger=logger)
        if success:
            logger.info("Navigation to %s:%s succeeded", file, line)
        else:
            logger.warning("Navigation to %s:%s failed: %s", file, line, response)
        return response

    def llm_continue_to_line(self, file, line, logger=None) -> str:
        """
        Continue the current stopped process to `file:line` without restarting.
        """
        if logger is None:
            logger = self.logger
        logger.info("Continuing current process to requested analysis point %s:%s", file, line)

        debugger_clear_breakpoints()
        result = debugger_set_breakpoint(file, line)[0]
        if "Invalid breakpoint" in result:
            logger.error("Invalid breakpoint while continuing: %s", result)
            debugger_clear_breakpoints()
            return (
                "Invalid breakpoint location, "
                "perhaps the line is not executable or the file is incorrect. "
                "Choose an executable line on the current control-flow path."
            )

        try:
            dbg_output, target_output = debugger_continue()
        except Exception as e:
            logger.error("Failed to continue to %s:%s: %s", file, line, e)
            return (
                "Failed to continue the current process to the requested line. "
                f"Debugger error: {e}. If the process is not currently stopped, use run_to_line instead."
            )

        reason = dbg_output.get("reason")
        hit_file = dbg_output.get("file")
        hit_line = dbg_output.get("line")

        if reason == "breakpoint-hit":
            logger.info("Continue navigation hit breakpoint at %s:%s", hit_file, hit_line)
            debugger_record_last_position(file, line)
            return self._format_stop_observation(file, line, hit_file, hit_line)

        is_sanitizer_crash, sanitizer_msg = check_sanitizer_error(target_output, dbg_output)
        if is_sanitizer_crash:
            logger.warning(
                "Continue navigation crashed before hitting %s:%s: %s",
                file,
                line,
                sanitizer_msg,
            )
            return (
                "The program crashed before reaching the requested line on the current path. "
                f"{sanitizer_msg} "
                "Use an earlier target line or inspect the current stop state."
            )

        if reason == "exited-normally":
            return (
                "The program exited normally before reaching the requested line on the current path. "
                "This means execution from the current stop did not pass through that line. "
                "Use run_to_line if you want to test reachability from program start."
            )

        if reason == "signal-received":
            signal_name = dbg_output.get("signal_name", "unknown")
            signal_meaning = dbg_output.get("signal_meaning", "")
            signal_info = f"{signal_name}" if signal_name != "unknown" else "a fatal signal"
            if signal_meaning:
                signal_info += f" ({signal_meaning})"
            return (
                "The program received "
                f"{signal_info} before the requested line was hit on the current path. "
                "Choose an earlier line or inspect the current stop state."
            )

        return (
            f"Failed to continue to the requested line. Stop reason was: {reason}. "
            "Use run_to_line to restart from program start, or choose a closer target line on the current path."
        )

    def llm_continue_and_get_result(self):
        """
        Continues execution from the current state (after a potential `assign`)
        and captures the result. It does NOT reset the state.
        """
        # DO NOT reproduce here. Continue from the state modified by `assign`.
        try:
            dbg_output, target_output = debugger_continue()
        except Exception as e:
            error_msg = str(e)
            self.logger.error(f"Error calling debugger_continue: {error_msg}")
            # Check if the error is related to process not being launched
            if "Process must be launched" in error_msg or "process" in error_msg.lower():
                return (
                    "Error: The debugger process is not running or has already terminated. "
                    "This usually happens when the program has already completed execution. "
                    "The experiment cannot continue. Please check if you need to set a breakpoint first or if the program has already finished."
                )
            return f"Error continuing execution: {error_msg}"
        
        crash_reason = dbg_output.get("reason")
        
        # Check if the debugger returned an error (e.g., "Process must be launched")
        if crash_reason == "error":
            error_details = dbg_output.get("error_details", "")
            error_msg = dbg_output.get("error", "Unknown error")
            self.logger.error(f"Debugger returned error: {error_msg}")
            if _is_process_not_launched_response(error_msg) or _is_process_not_launched_response(error_details):
                return (
                    "Error: The debugger process is not running or has already terminated. "
                    "This usually happens when the program has already completed execution. "
                    "The experiment cannot continue. Please check if you need to set a breakpoint first or if the program has already finished."
                )
            return f"Error continuing execution: {error_msg}. Details: {error_details}"
        
        # Check if crash_reason is None (which might indicate an error)
        if crash_reason is None:
            self.logger.warning("debugger_continue returned None crash_reason, checking target_output for errors")
            # Check target_output for error messages
            if "Process must be launched" in target_output:
                return (
                    "Error: The debugger process is not running or has already terminated. "
                    "This usually happens when the program has already completed execution. "
                    "The experiment cannot continue. Please check if you need to set a breakpoint first or if the program has already finished."
                )

        # Use central sanitizer check
        is_sanitizer_crash, sanitizer_msg = check_sanitizer_error(target_output, dbg_output)

        response = ""
        # Hierarchical check: Sanitizer failure is the highest priority failure condition.
        if is_sanitizer_crash:
            response = f"Experiment failed: {sanitizer_msg}"
        else:
            # Only if there's no Sanitizer error do we check the exit reason.
            if crash_reason == "exited-normally":
                response = f"Experiment successful: The program did NOT crash (Reason: {crash_reason})."
            elif crash_reason == "breakpoint-hit":
                stop_parts = []
                stop_file = dbg_output.get("file")
                stop_line = dbg_output.get("line")
                stop_func = dbg_output.get("func")
                if stop_file and stop_line:
                    stop_parts.append(f"stopped at {stop_file}:{stop_line}")
                elif stop_line:
                    stop_parts.append(f"stopped at line {stop_line}")
                if stop_func:
                    stop_parts.append(f"function {stop_func}")
                hit_count = debugger_get_tracked_breakpoint_hit_count(dbg_output.get("breakpoint_id"))
                if hit_count is not None:
                    stop_parts.append(f"hit_count={hit_count}")
                stop_detail = f" ({', '.join(stop_parts)})" if stop_parts else ""
                response = (
                    f"Program stopped at breakpoint-hit{stop_detail} before program termination. "
                    "This is not enough to conclude the crash is fixed; inspect the state "
                    "or continue again from the current stop."
                )
            elif crash_reason == "signal-received":
                # Provide more details about the signal
                signal_name = dbg_output.get("signal_name", "unknown")
                signal_meaning = dbg_output.get("signal_meaning", "")
                signal_info = f" ({signal_name})" if signal_name != "unknown" else ""
                if signal_meaning:
                    signal_info += f" - {signal_meaning}"
                
                response = (
                    f"Experiment failed: The program still crashed with signal-received{signal_info}. "
                    f"This typically indicates a memory access violation (segmentation fault) or similar fatal error. "
                    f"Your modification did not prevent the crash. Try a different value or approach."
                )
            else:
                response = f"Experiment failed: {crash_reason}"
        
        return response

    def llm_print_value(self, expression):
        return debugger_print(expression)

@logf(NAME, True)
def debug(profile, info, logger=None) -> List[str]:
    if logger is None:
        logger = get_logger(NAME)
    logger.warning("Debugging %s", profile["file"])

    logger.info("Initializing debug session")
    try:
        session = DebugSession(
            DebugInput(
                profile,
                info["error"],
                info["func"],
                info["file"],
                info["line"],
                retry_observation=str(info.get("debug_retry_observation", "") or ""),
            )
        )
    except RuntimeError as exc:
        if "valid reproduce frame" not in str(exc):
            raise
        logger.error("%s", exc)
        return []

    return session.run().analysis
