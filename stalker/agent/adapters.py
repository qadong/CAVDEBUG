from __future__ import annotations

import ast
import hashlib
import os
import re

from agent import counterfactual_agent, debug_agent, patch_agent
from agent.layer1 import build_root_cause_report
from agent.layer_patch import plan_patch_round
from agent.layer2 import decide_layer2_entry
from agent.layer_verify import VerifyRoundDecision, classify_verification_outcome
from agent.patch_heuristic import try_heuristic_min_patch
from agent.constraint_agent import run_constraint_round
from agent.type_angelic import infer_bug_type_profile
from agent.contracts import (
    AgentMessage,
    ConstraintCandidate,
    EvidenceItem,
    HypothesisRecord,
    OpenQuestion,
    PatchCandidate,
    RootCauseHypothesis,
    VerificationFeedback,
)
from agent.prompts import OPERATIONAL_REPAIR_INTENT_PROMPT, PATCH_STRATEGY_ANALYST_PROMPT
from agent.state import BugHypothesisState
from tools.debugger.driver import debugger_instance
from tools.fuzzer.functions import fuzz_variables
from tools.file.functions import file_get_content, file_get_line_count
from utils.ablation import lldb_only, no_cfc, patch_search_budget_limited, state_only_no_angelic
from utils.metrics import (
    constraint_round_metrics,
    counterfactual_round_metrics,
    debug_round_metrics,
    fuzz_round_metrics,
    patch_round_metrics,
    verification_round_metrics,
)
from utils.verification import verify_patch_feedback


def _current_hypothesis_summary(state: BugHypothesisState) -> str:
    active = state.active_hypothesis()
    if active:
        return active.summary
    hypothesis = state.current_hypothesis()
    return hypothesis.summary if hypothesis else ""


def _attach_round_metrics(message: AgentMessage, metrics: dict) -> AgentMessage:
    if not message.artifacts:
        return message
    message.artifacts = dict(message.artifacts)
    message.artifacts["round_metrics"] = metrics
    return message


def _hypothesis_id(result: dict, index: int) -> str:
    raw = f"{result.get('file', '')}:{result.get('line', '')}:{result.get('variable_names', [])}:{index}"
    return "hyp-" + hashlib.sha1(raw.encode("utf-8", errors="ignore")).hexdigest()[:10]


def _extract_suspect_expressions(result: dict) -> list[str]:
    variables = [str(v) for v in result.get("variable_names", []) if v]
    expressions: list[str] = []
    for name in variables:
        expressions.append(name)
        if "*" in str(result.get("llm_inferred_type", "")) or name.lower().endswith(("ptr", "p")):
            expressions.extend([f"*{name}", f"{name}+1", f"{name}-1"])
    ctx = result.get("context_variables", {})
    if isinstance(ctx, dict):
        expressions.extend([str(k) for k in ctx.keys()])
    summary = str(result.get("debug_summary", ""))
    for token in ("len", "size", "count", "offset", "end", "base"):
        if token in summary and token not in expressions:
            expressions.append(token)
    return list(dict.fromkeys(expressions))[:20]


def _augment_variable_names_from_summary(result: dict) -> list[str]:
    variables = [str(v) for v in result.get("variable_names", []) if v]
    summary = str(result.get("debug_summary", "") or "")
    for expr in re.findall(r"\bsizeof\s*\(\s*([^)]+?)\s*\)", summary):
        normalized = f"sizeof({expr.strip()})"
        if normalized not in variables:
            variables.append(normalized)
    return variables


def _summary_mentions_local_companion_extent(summary: str) -> bool:
    lowered = str(summary or "").lower()
    return any(token in lowered for token in ("two bug", "both", "companion", "also", "and line"))


def _local_repair_lines_from_summary(summary: str, file: str, primary_line: int) -> list[int]:
    target_base = os.path.basename(str(file or ""))
    if not summary or primary_line <= 0:
        return [primary_line] if primary_line > 0 else []
    lines: set[int] = {primary_line}
    repair_context = re.compile(
        r"(root\s+cause|bug\s*\d*|fix|source\s+code\s+fix|change|instead\s+of|wrong|copy-paste|sizeof\s*\()",
        re.IGNORECASE,
    )
    exclude_context = re.compile(r"(correctly|proving|proof|32-bit\s+path|works\s+correctly)", re.IGNORECASE)
    for sentence in re.split(r"(?<=[.\n])\s+", summary):
        if not repair_context.search(sentence) or exclude_context.search(sentence):
            continue
        for match in re.finditer(r"\blines?\s+(\d+)(?:\s*-\s*(\d+))?", sentence, re.IGNORECASE):
            start = int(match.group(1))
            end = int(match.group(2) or start)
            if abs(start - primary_line) <= 80 or abs(end - primary_line) <= 80:
                lines.update(range(min(start, end), max(start, end) + 1))
        for match in re.finditer(r"\blines?\s+\d+(?:\s*-\s*\d+)?\s+and\s+(\d+)", sentence, re.IGNORECASE):
            found = int(match.group(1))
            if abs(found - primary_line) <= 80:
                lines.add(found)
        for match in re.finditer(r"\bline\s+(\d+)", sentence, re.IGNORECASE):
            found = int(match.group(1))
            if abs(found - primary_line) <= 80:
                lines.add(found)
        if target_base:
            for match in re.finditer(
                rf"{re.escape(target_base)}[^\n.]*?\blines?\s+(\d+)(?:\s*-\s*(\d+))?",
                sentence,
                re.IGNORECASE,
            ):
                start = int(match.group(1))
                end = int(match.group(2) or start)
                lines.update(range(min(start, end), max(start, end) + 1))
    return sorted(lines)


def _infer_repair_topology(result: dict) -> str:
    bug_type = str(((result.get("bug_type_profile") or {}).get("bug_type", ""))).lower()
    summary = str(result.get("debug_summary", "")).lower()
    file = str(result.get("file", "")).strip()
    if bug_type == "out_of_bounds" and any(
        token in summary
        for token in ("allocation", "sizeof", "read size", "read length", "buffer size", "capacity")
    ):
        if _summary_mentions_local_companion_extent(summary):
            return "local_invariant"
        return "single_site"
    if bug_type == "uninitialized_use":
        return "init_then_use"
    if bug_type in {"use_after_free", "double_free", "invalid_free", "resource_leak", "data_race", "heap_corruption_later_crash"}:
        return "cross_file_invariant"
    if bug_type in {"null_dereference", "assertion_failure", "stack_overflow"}:
        return "caller_to_callee"
    if any(token in summary for token in ("initialize", "initializ", "memset", "zero", "uninitialized")):
        return "init_then_use"
    if any(token in summary for token in ("caller", "passed as", "argument", "upstream")):
        return "caller_to_callee"
    if any(token in summary for token in ("struct", "field", "lifetime", "ownership", "free")):
        if file and file.lower() in summary:
            return "single_site"
        return "cross_file_invariant"
    return "single_site"


def _infer_repair_stage(result: dict, topology: str) -> str:
    bug_type = str(((result.get("bug_type_profile") or {}).get("bug_type", ""))).lower()
    if bug_type == "out_of_bounds":
        summary = str(result.get("debug_summary", "")).lower()
        if any(token in summary for token in ("parse", "header", "malformed", "input")):
            return "input_validation"
        return "state_update"
    if bug_type == "integer_overflow":
        return "allocation_extent"
    if bug_type == "null_dereference":
        summary = str(result.get("debug_summary", "")).lower()
        if any(token in summary for token in ("initialize", "constructor", "alloc", "null from init")):
            return "initialization"
        return "input_validation"
    if bug_type == "invalid_pointer":
        return "state_update"
    if bug_type in {"use_after_free", "double_free", "invalid_free", "resource_leak"}:
        return "ownership_lifetime"
    if bug_type == "uninitialized_use":
        return "initialization"
    if bug_type == "assertion_failure":
        return "state_update"
    if bug_type == "divide_by_zero":
        return "input_validation"
    if bug_type == "stack_overflow":
        return "state_update"
    if bug_type == "heap_corruption_later_crash":
        return "state_update"
    if bug_type == "data_race":
        return "ownership_lifetime"
    summary = str(result.get("debug_summary", "")).lower()
    if any(token in summary for token in ("free", "release", "lifetime", "ownership", "use-after-free")):
        return "ownership_lifetime"
    if any(token in summary for token in ("alloc", "malloc", "calloc", "realloc", "capacity")):
        return "allocation_extent"
    if any(token in summary for token in ("initialize", "initializ", "memset", "zero", "uninitialized")):
        return "initialization"
    if any(token in summary for token in ("invalid input", "malformed", "parse", "header", "argument")):
        return "input_validation"
    if topology in {"caller_to_callee", "cross_file_invariant", "init_then_use", "local_invariant"}:
        return "state_update"
    return "crash_guard"


def _infer_forbidden_repair_stages(preferred_stage: str, topology: str) -> list[str]:
    mapping = {
        "input_validation": ["crash_guard"],
        "state_update": ["crash_guard"],
        "initialization": ["crash_guard"],
        "allocation_extent": ["crash_guard"],
        "ownership_lifetime": ["crash_guard"],
        "crash_guard": [],
    }
    forbidden = list(mapping.get(preferred_stage, []))
    if topology in {"caller_to_callee", "cross_file_invariant", "init_then_use", "local_invariant"} and "crash_guard" not in forbidden:
        forbidden.append("crash_guard")
    return forbidden


def _build_causal_chain_summary(result: dict, topology: str, preferred_stage: str) -> str:
    summary = str(result.get("debug_summary", "")).strip()
    line = int(result.get("line", -1) or -1)
    if summary:
        first = summary.split(".")[0].strip()
        return (
            f"The crash site appears to be a downstream failure point near line {line}. "
            f"The preferred repair stage is {preferred_stage.replace('_', ' ')}, following topology {topology}. "
            f"Root-cause summary: {first}."
        )
    return (
        f"The crash site appears downstream of the root cause. "
        f"Prefer a {preferred_stage.replace('_', ' ')} repair under topology {topology}."
    )


def _extract_crash_site_from_summary(result: dict) -> dict:
    summary = str(result.get("debug_summary", "") or "")
    fallback = {
        "file": result.get("file", ""),
        "line": int(result.get("line", -1) or -1),
        "function": str(result.get("function_name", "")).strip(),
    }
    if not summary:
        return fallback
    frame_pattern = re.compile(
        r"\bin\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(\s*([A-Za-z0-9_./\\-]+\.[A-Za-z0-9_]+):(\d+)",
        re.IGNORECASE,
    )
    match = frame_pattern.search(summary)
    if match:
        return {"function": match.group(1), "file": match.group(2), "line": int(match.group(3))}
    at_pattern = re.compile(
        r"\bin\s+([A-Za-z_][A-Za-z0-9_]*)\s+at\s+([A-Za-z0-9_./\\-]+\.[A-Za-z0-9_]+):(\d+)",
        re.IGNORECASE,
    )
    match = at_pattern.search(summary)
    if match:
        return {"function": match.group(1), "file": match.group(2), "line": int(match.group(3))}
    location_pattern = re.compile(
        r"([A-Za-z0-9_./\\-]+\.[A-Za-z0-9_]+):(\d+)\)?\s+called\s+from\s+([A-Za-z_][A-Za-z0-9_]*)",
        re.IGNORECASE,
    )
    match = location_pattern.search(summary)
    if match:
        return {"file": match.group(1), "line": int(match.group(2)), "function": match.group(3)}
    if fallback.get("function") and str(fallback.get("function")) in summary:
        return {"function": fallback.get("function"), "file": "", "line": -1}
    if any(token in summary.lower() for token in ("root cause", "copy-paste bug", "source code fix")):
        return {}
    return fallback


def _extract_function_for_file_from_summary(summary: str, file: str, line: int = -1, fallback: str = "") -> str:
    target_base = os.path.basename(str(file or ""))
    if not summary or not target_base:
        return fallback
    root_cause_pattern = re.compile(
        r"\b(?:root\s+cause|bugs?|bug|copy-paste\s+bug)[^\n.]*?\bin\s+`?([A-Za-z_][A-Za-z0-9_]*)`?\s*\(\s*`?([A-Za-z0-9_./\\-]+\.[A-Za-z0-9_]+)`?\s*\)",
        re.IGNORECASE,
    )
    match = root_cause_pattern.search(summary)
    if match and os.path.basename(match.group(2)) == target_base:
        return match.group(1)
    frame_pattern = re.compile(
        r"\b(?:in|from)?\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:\(\s*|\bat\s+)([A-Za-z0-9_./\\-]+\.[A-Za-z0-9_]+):(\d+)(?:-\d+)?",
        re.IGNORECASE,
    )
    matches: list[tuple[int, str]] = []
    for match in frame_pattern.finditer(summary):
        if os.path.basename(match.group(2)) == target_base:
            frame_line = int(match.group(3)) if match.lastindex and match.lastindex >= 3 else -1
            distance = abs(frame_line - line) if line > 0 and frame_line > 0 else 0
            matches.append((distance, match.group(1)))
    if matches:
        matches.sort(key=lambda item: item[0])
        if line <= 0 or matches[0][0] <= 80:
            return matches[0][1]
    crash_site = _extract_crash_site_from_summary({"debug_summary": summary, "file": file, "line": line, "function_name": fallback})
    if fallback and crash_site.get("function") == fallback and os.path.basename(str(crash_site.get("file", ""))) != target_base:
        return ""
    return fallback


def _infer_forbidden_fix_patterns(result: dict) -> list[str]:
    bug_type = str(((result.get("bug_type_profile") or {}).get("bug_type", ""))).lower()
    summary = str(result.get("debug_summary", "")).lower()
    forbidden: list[str] = ["re-debug_root_cause_without_new_evidence"]
    if bug_type in {"out_of_bounds", "integer_overflow"}:
        forbidden.append("hardcoded_poc_specific_bound")
    if bug_type in {"null_dereference", "invalid_pointer"}:
        forbidden.append("dummy_pointer_fabrication")
    if bug_type in {"use_after_free", "double_free", "invalid_free", "resource_leak"}:
        forbidden.append("delete_release_without_ownership_reason")
        forbidden.append("single_alias_nullification_only")
    if bug_type == "uninitialized_use":
        forbidden.append("use_site_default_fill_without_init_fix")
    if bug_type == "assertion_failure":
        forbidden.append("remove_assert_without_invariant_repair")
    if bug_type == "divide_by_zero":
        forbidden.append("hardcoded_denominator_constant")
    if bug_type == "heap_corruption_later_crash":
        forbidden.append("allocator_site_guard_only")
    if bug_type == "data_race":
        forbidden.append("schedule_specific_timing_hack")
    if any(token in summary for token in ("initialize", "memset", "zero", "uninitialized")):
        forbidden.append("crash_site_guard_only")
        forbidden.append("literal_constraint_clamp_without_state_repair")
    if any(token in summary for token in ("caller", "upstream", "argument")):
        forbidden.append("callee_only_guard_if_upstream_invariant_exists")
    return forbidden


def _infer_patch_expansion_policy(result: dict, topology: str) -> dict:
    summary = str(result.get("debug_summary", "")).lower()
    allow_call_chain = topology in {"caller_to_callee", "init_then_use", "cross_file_invariant"}
    allow_cross_file = topology == "cross_file_invariant" or any(
        token in summary for token in ("helper", "wrapper", "initializer", "struct field")
    )
    return {
        "mode": "local_first",
        "allow_call_chain_expansion": allow_call_chain,
        "allow_cross_file_expansion_if_needed": allow_cross_file,
        "require_justification_for_expansion": True,
    }


def _extract_upstream_init_symbol(summary: str) -> str:
    text = str(summary or "")
    seen: set[str] = set()
    candidates: list[str] = []
    for symbol in re.findall(r"`?([A-Za-z_][A-Za-z0-9_]*)`?\s*\(\)", text):
        if symbol not in seen:
            seen.add(symbol)
            candidates.append(symbol)
    for symbol in re.findall(r"`([A-Za-z_][A-Za-z0-9_]*)`", text):
        if symbol not in seen:
            seen.add(symbol)
            candidates.append(symbol)
    for symbol in re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*(?:_init|init_[A-Za-z0-9_]*))\b", text):
        if symbol not in seen:
            seen.add(symbol)
            candidates.append(symbol)
    for symbol in candidates:
        lowered = symbol.lower()
        if lowered.endswith("_init") or lowered.startswith("init_") or "constructor" in lowered:
            return symbol
    return ""


def _extract_allocated_object_name(reproduce_result: dict | None) -> str:
    error_text = str((reproduce_result or {}).get("error", ""))
    match = re.search(r"allocation of '([^']+)'", error_text)
    return match.group(1).strip() if match else ""


def _candidate_search_roots(file: str, profile: dict | None) -> list[str]:
    roots: list[str] = []
    src_root = str((profile or {}).get("src", "")).strip()
    if src_root and os.path.isdir(src_root):
        roots.append(src_root)
    if file:
        current = os.path.abspath(os.path.dirname(file))
        stop_dirs = {os.path.abspath(path) for path in ("/", "/tmp", "/var", "/usr", "/home")}
        for _ in range(3):
            if current and os.path.isdir(current) and current not in roots:
                roots.append(current)
            parent = os.path.dirname(current)
            if not parent or parent == current or parent in stop_dirs:
                break
            current = parent
    normalized: list[str] = []
    for root in roots:
        if root not in normalized:
            normalized.append(root)
    return normalized


def _find_symbol_locations(symbol: str, file: str, current_line: int, profile: dict | None, object_name: str = "") -> list[dict]:
    if not symbol:
        return []
    def_patterns = [
        rf"^\s*#\s*define\s+{re.escape(symbol)}\b",
        rf"^\s*(?:static\s+)?(?:inline\s+)?[A-Za-z_][A-Za-z0-9_\s\*]*\b{re.escape(symbol)}\s*\(",
    ]
    call_patterns = [rf"\b{re.escape(symbol)}\s*\("]
    if object_name:
        call_patterns.insert(0, rf"\b{re.escape(symbol)}\s*\(\s*&?{re.escape(object_name)}\s*\)")
    allowed_suffixes = (".c", ".h", ".cc", ".cpp", ".hpp", ".hh")
    locations: list[dict] = []
    seen: set[tuple[str, int, str]] = set()
    for root in _candidate_search_roots(file, profile):
        for dirpath, _, filenames in os.walk(root):
            for filename in filenames:
                if not filename.endswith(allowed_suffixes):
                    continue
                fullpath = os.path.join(dirpath, filename)
                try:
                    line_count = file_get_line_count(fullpath)
                    contents = file_get_content(fullpath, 1, line_count)
                except Exception:
                    continue
                if not contents:
                    continue
                for idx, raw_line in enumerate(contents.splitlines(), start=1):
                    line = raw_line.strip()
                    for pattern in def_patterns:
                        if re.search(pattern, raw_line):
                            key = (fullpath, idx, "definition")
                            if key not in seen:
                                seen.add(key)
                                locations.append(
                                    {
                                        "file": fullpath,
                                        "line": idx,
                                        "function": symbol,
                                        "role": "constructor_init_definition",
                                        "why_here": f"Definition site for `{symbol}` that controls initialization semantics before the failing use.",
                                        "patchability_score": 0.78,
                                    }
                                )
                    if line.startswith("#define"):
                        continue
                    for pattern in call_patterns:
                        if re.search(pattern, raw_line):
                            key = (fullpath, idx, "callsite")
                            if key not in seen:
                                seen.add(key)
                                specific_object = bool(object_name and re.search(call_patterns[0], raw_line))
                                score = 0.99 if specific_object else 0.9
                                locations.append(
                                    {
                                        "file": fullpath,
                                        "line": idx,
                                        "function": symbol,
                                        "role": "constructor_init_callsite",
                                        "why_here": (
                                            f"Call site for `{symbol}` that initializes `{object_name}` before it reaches the failing path."
                                            if specific_object
                                            else f"Call site for `{symbol}` that may initialize state consumed by the failing path."
                                        ),
                                        "patchability_score": score,
                                    }
                                )
    def rank(location: dict) -> tuple:
        role = str(location.get("role", ""))
        same_file = 0 if str(location.get("file", "")) == file else 1
        object_specific = 0 if object_name and object_name in str(location.get("why_here", "")) else 1
        before_current = 0 if same_file == 0 and int(location.get("line", 0) or 0) < current_line else 1
        definition_penalty = 1 if "definition" in role else 0
        return (object_specific, same_file, before_current, definition_penalty, -float(location.get("patchability_score", 0.0) or 0.0))
    locations.sort(key=rank)
    return locations[:6]


def _build_edit_location_context(result: dict) -> dict:
    file = result.get("file", "")
    line = int(result.get("line", -1) or -1)
    debug_summary = str(result.get("debug_summary", "")).strip()
    function_name = _extract_function_for_file_from_summary(
        debug_summary,
        file,
        line,
        str(result.get("function_name", "")).strip(),
    )
    bug_type_profile = result.get("bug_type_profile") or {}
    bug_type = str(bug_type_profile.get("bug_type", "unknown"))
    topology = _infer_repair_topology(result)
    preferred_stage = _infer_repair_stage(result, topology)
    crash_site = _extract_crash_site_from_summary(result)
    local_repair_lines = _local_repair_lines_from_summary(debug_summary, file, line)
    if topology == "single_site" and len(local_repair_lines) > 1:
        topology = "local_invariant"
        preferred_stage = _infer_repair_stage(result, topology)
    preferred = {
        "file": file,
        "line": line,
        "function": function_name,
        "role": "root_cause_site" if topology in {"single_site", "local_invariant"} else "state_init_site",
        "why_here": (
            f"DebugAgent validated that this analysis location is where the effective {bug_type.replace('_', ' ')} repair should be realized."
            if bug_type and bug_type != "unknown"
            else "DebugAgent validated that this analysis location is where the effective repair should be realized."
        ),
        "patchability_score": 0.95,
    }
    nearby_candidates = [preferred]
    for repair_line in local_repair_lines:
        if repair_line == line:
            continue
        nearby_candidates.append(
            {
                "file": file,
                "line": repair_line,
                "function": function_name,
                "role": "companion_invariant_site",
                "why_here": "Companion line in the same local repair region that must preserve the same allocation/read extent invariant.",
                "patchability_score": 0.9,
            }
        )
    init_symbol = _extract_upstream_init_symbol(debug_summary)
    init_object = _extract_allocated_object_name(result.get("reproduce_result"))
    if bug_type == "uninitialized_use" and preferred_stage == "initialization" and init_symbol:
        init_locations = _find_symbol_locations(init_symbol, file, line, result.get("profile"), object_name=init_object)
        if init_locations:
            preferred = dict(init_locations[0])
            nearby_candidates = [preferred] + [item for item in init_locations[1:] if item != preferred] + nearby_candidates
    if line > 1:
        nearby_candidates.append(
            {
                "file": file,
                "line": max(1, line - 3),
                "function": function_name,
                "role": "upstream_invariant_site",
                "why_here": "Nearby upstream line in the same function in case the final patch needs to restore state slightly earlier than the breakpoint line.",
                "patchability_score": 0.72,
            }
        )
    nearby_candidates.append(
        {
            "file": file,
            "line": line,
            "function": function_name,
            "role": "same_site_guard",
            "why_here": "Fallback local repair site only if the preferred invariant-restoring edit is not implementable.",
            "patchability_score": 0.35,
        }
    )
    deduped_candidates: list[dict] = []
    seen_locations: set[tuple[str, int, str]] = set()
    for item in nearby_candidates:
        key = (str(item.get("file", "")), int(item.get("line", -1) or -1), str(item.get("role", "")))
        if key in seen_locations:
            continue
        seen_locations.add(key)
        deduped_candidates.append(item)
    nearby_candidates = deduped_candidates
    group_locations = [preferred]
    if topology == "local_invariant":
        group_locations = [
            item
            for item in nearby_candidates
            if str(item.get("role", "")) in {"root_cause_site", "companion_invariant_site"}
        ] or [preferred]
    elif topology != "single_site":
        group_locations = nearby_candidates[:2]
    min_line = min(local_repair_lines) if local_repair_lines else line
    max_line = max(local_repair_lines) if local_repair_lines else line
    return {
        "preferred_edit_location": preferred,
        "candidate_edit_locations": nearby_candidates,
        "location_groups": [
            {
                "group_id": "primary",
                "topology": topology,
                "locations": group_locations,
                "must_modify_together": topology == "local_invariant" and len(group_locations) > 1,
                "rationale": (
                    "Primary edit plan inferred from DebugAgent's effective intervention location for a local invariant spanning companion lines."
                    if topology == "local_invariant"
                    else f"Primary edit plan inferred from DebugAgent's effective intervention location for {bug_type.replace('_', ' ')}."
                    if bug_type and bug_type != "unknown"
                    else "Primary edit plan inferred from DebugAgent's effective intervention location."
                ),
            }
        ],
        "repair_topology": topology,
        "causal_chain_summary": _build_causal_chain_summary(result, topology, preferred_stage),
        "crash_site": crash_site,
        "root_cause_site": preferred,
        "preferred_repair_stage": preferred_stage,
        "forbidden_repair_stages": _infer_forbidden_repair_stages(preferred_stage, topology),
        "patch_expansion_policy": _infer_patch_expansion_policy(result, topology),
        "allowed_edit_scope": {
            "preferred_files": [file] if file else [],
            "preferred_function": function_name,
            "line_window": [max(1, min_line - 8), max_line + 8] if line > 0 else [],
        },
        "forbidden_fix_patterns": _infer_forbidden_fix_patterns(result),
    }


def _build_debug_message(state: BugHypothesisState, analysis: list[dict]) -> AgentMessage:
    state.surface_bug_type_profile = infer_bug_type_profile(
        profile=state.profile,
        reproduce_result=state.reproduce_result,
        classification_mode="surface",
    )
    state.bug_type_profile = infer_bug_type_profile(
        profile=state.profile,
        reproduce_result=state.reproduce_result,
        classification_mode="root_cause",
    )
    raw_suspects = [result for result in analysis if result and result.get("variable_names")]
    pool_limit = max(5, state.top_k_hypotheses)
    suspects: list[dict] = []
    hypotheses = [
        RootCauseHypothesis(
            summary=result.get("debug_summary", "Suspect root cause identified by DebugAgent."),
            suspect_file=result.get("file", ""),
            suspect_line=int(result.get("line", -1)),
            suspect_variables=[str(name) for name in result.get("variable_names", [])],
            confidence=0.55,
            payload=result,
        )
        for result in raw_suspects
    ]
    hypothesis_records: list[HypothesisRecord] = []
    for idx, result in enumerate(raw_suspects[:pool_limit]):
        hid = result.get("hypothesis_id") or _hypothesis_id(result, idx)
        enriched = dict(result)
        enriched["variable_names"] = _augment_variable_names_from_summary(enriched)
        enriched["profile"] = state.profile
        enriched["reproduce_result"] = state.reproduce_result
        enriched["hypothesis_id"] = hid
        enriched["suspect_expressions"] = _extract_suspect_expressions(enriched)
        enriched["surface_bug_type_profile"] = infer_bug_type_profile(
            profile=state.profile,
            reproduce_result=state.reproduce_result,
            suspect_object=enriched,
            debug_summary=enriched.get("debug_summary", ""),
            classification_mode="surface",
        )
        enriched["bug_type_profile"] = infer_bug_type_profile(
            profile=state.profile,
            reproduce_result=state.reproduce_result,
            suspect_object=enriched,
            debug_summary=enriched.get("debug_summary", ""),
            function_body=str(enriched.get("function_body", "")),
            classification_mode="root_cause",
        )
        enriched.update(_build_edit_location_context(enriched))
        suspects.append(enriched)
        debug_confidence = max(0.25, 0.65 - (0.07 * idx))
        record = HypothesisRecord(
            id=hid,
            summary=enriched.get("debug_summary", "Suspect root cause identified by DebugAgent."),
            suspect_file=enriched.get("file", ""),
            suspect_line=int(enriched.get("line", -1)),
            suspect_variables=[str(name) for name in enriched.get("variable_names", [])],
            suspect_expressions=enriched.get("suspect_expressions", []),
            score=0.0,
            evidence=[
                {
                    "event": "debug_suspect",
                    "file": enriched.get("file", ""),
                    "line": enriched.get("line", -1),
                }
            ],
            payload={**enriched, "debug_confidence": debug_confidence},
        )
        record.score = state.score_hypothesis(record)
        hypothesis_records.append(record)

    state.analysis = analysis
    state.suspects = suspects
    state.hypotheses = hypotheses
    state.hypothesis_pool = hypothesis_records
    state.current_suspect_index = 0
    if hypothesis_records:
        state.active_hypothesis_id = hypothesis_records[0].id

    if suspects:
        state.debug_retry_observation = ""
        primary = suspects[0]
        root_cause_report = build_root_cause_report(primary, state.active_hypothesis_id)
        if state_only_no_angelic(state.profile):
            root_cause_report.direct_patch_allowed = False
            root_cause_report.direct_patch_risk = "medium"
            root_cause_report.direct_patch_reason = "Ablation mode disables angelic counterfactual evidence; patch from observation-only root-cause analysis."
            root_cause_report.evidence_family = "operational"
            root_cause_report.evidence_kind = "observation_only_state"
            root_cause_report.selective_generalization = "repair_intent"
            root_cause_report.operational_repair_intent = (
                primary.get("debug_summary")
                or root_cause_report.direct_patch_contract
                or "Repair the invalid state described by the observation-only debug analysis."
            )
            root_cause_report.evidence_requirements = list(root_cause_report.evidence_requirements or [])
            root_cause_report.evidence_requirements.append(
                "Ablation: no debugger mutation, angelic value search, or counterfactual replay was used before patching."
            )
        state.set_root_cause_report(root_cause_report, hypothesis_id=state.active_hypothesis_id)
        skip_counterfactual = state_only_no_angelic(state.profile) or no_cfc(state.profile)
        next_actor = "patch" if skip_counterfactual else "counterfactual"
        message = AgentMessage(
            actor="debug",
            claims=[primary.get("debug_summary", "DebugAgent identified a suspect root cause.")],
            evidence=[
                EvidenceItem(
                    source="debug",
                    summary=f"Primary suspect at {primary.get('file')}:{primary.get('line')}",
                    kind="suspect",
                    payload={"variables": primary.get("variable_names", [])},
                )
            ],
            confidence=0.55,
            questions_for_others=[
                OpenQuestion(
                    source="debug",
                    question=(
                        "Can PatchAgent generate a patch from observation-only state evidence without angelic counterfactual validation?"
                        if state_only_no_angelic(state.profile)
                        else (
                            "Can PatchAgent generate a patch directly from DebugAgent angelic intervention evidence without CFC abstraction?"
                            if no_cfc(state.profile)
                            else "Can CounterfactualContractAgent abstract the debug evidence into a repair invariant before patch generation?"
                        )
                    ),
                    target_actor=next_actor,
                )
            ],
            recommended_next_actor=next_actor,
            artifacts={
                "analysis": analysis,
                "suspects": suspects,
                "bug_type_profile": state.bug_type_profile,
                "hypotheses": [hypothesis.__dict__ for hypothesis in hypotheses],
                "hypothesis_pool": [hypothesis.__dict__ for hypothesis in hypothesis_records],
                "root_cause_report": root_cause_report.__dict__,
            },
        )
        return _attach_round_metrics(
            message,
            debug_round_metrics(
                analysis=analysis,
                suspects=suspects,
                active_hypothesis_id=state.active_hypothesis_id,
                recommended_next_actor=message.recommended_next_actor,
                bug_type_profile=state.bug_type_profile,
                surface_bug_type_profile=state.surface_bug_type_profile,
            ),
        )

    message = AgentMessage(
        actor="debug",
        claims=["DebugAgent could not identify a usable suspect variable."],
        confidence=0.0,
        questions_for_others=[
            OpenQuestion(
                source="debug",
                question="Can DebugAgent retry with a different frame or upstream interception point?",
                target_actor="debug",
            )
        ],
        recommended_next_actor="debug",
        artifacts={"analysis": analysis, "bug_type_profile": state.bug_type_profile},
    )
    return _attach_round_metrics(
        message,
        debug_round_metrics(
            analysis=analysis,
            suspects=suspects,
            active_hypothesis_id=state.active_hypothesis_id,
            recommended_next_actor=message.recommended_next_actor,
            bug_type_profile=state.bug_type_profile,
            surface_bug_type_profile=state.surface_bug_type_profile,
        ),
    )


def hydrate_debug_state(state: BugHypothesisState, analysis: list[dict]) -> AgentMessage:
    return _build_debug_message(state, analysis)


def run_debug_round(state: BugHypothesisState, logger=None) -> AgentMessage:
    reproduce_result = dict(state.reproduce_result or {})
    if state.debug_retry_observation:
        reproduce_result["debug_retry_observation"] = state.debug_retry_observation
    analysis = debug_agent.debug(state.profile, reproduce_result, logger=logger)
    return _build_debug_message(state, analysis)


def run_counterfactual_round(state: BugHypothesisState, logger=None) -> AgentMessage:
    suspect = state.current_suspect()
    if suspect is None:
        return AgentMessage(
            actor="counterfactual",
            claims=["No suspect available for counterfactual contract generation."],
            confidence=0.0,
            recommended_next_actor="done",
        )
    report = state.current_root_cause_report()
    contract, agent_trace = counterfactual_agent.run_counterfactual_agent(
        profile=state.profile,
        suspect=suspect,
        root_cause_report=report,
        hypothesis_id=state.active_hypothesis_id,
        reproduce_result=state.reproduce_result,
        logger=logger,
    )
    if contract is None:
        rejection = agent_trace.get("contract_rejected") if isinstance(agent_trace, dict) else None
        if isinstance(rejection, dict):
            actions = [str(item) for item in rejection.get("actions", []) if str(item).strip()]
            reason = str(rejection.get("reason", "") or "contract_rejected")
            detail = f": missing {', '.join(actions)}" if actions else f": {reason}"
            claims = [f"CounterfactualContractAgent submitted a contract but it was rejected{detail}."]
        else:
            claims = ["CounterfactualContractAgent ended without submitting a contract."]
        return AgentMessage(
            actor="counterfactual",
            claims=claims,
            confidence=0.0,
            recommended_next_actor="done",
            artifacts={
                "counterfactual_agent_trace": agent_trace,
                "hypothesis_id": state.active_hypothesis_id,
            },
        )
    state.set_counterfactual_contract(contract, hypothesis_id=state.active_hypothesis_id)
    state.update_active_hypothesis(
        "counterfactual_contract_generated",
        success=True,
        details={
            "contract_id": contract.contract_id,
            "boundary_kind": contract.boundary_kind,
            "enforcement_priority": contract.enforcement_priority,
        },
    )
    artifact = counterfactual_agent.contract_to_dict(contract)
    if logger is not None:
        logger.info("Generated counterfactual contract %s for hypothesis %s", contract.contract_id, contract.hypothesis_id)
        logger.info(
            "Counterfactual agent trace: messages=%s intervention=%s:%s enforcement=%s:%s(%s) boundary=%s statuses=%s",
            len(agent_trace.get("history", []) or []),
            contract.intervention_site.get("file", ""),
            contract.intervention_site.get("line", ""),
            contract.enforcement_site.get("file", ""),
            contract.enforcement_site.get("line", ""),
            contract.enforcement_site.get("role", ""),
            contract.boundary_kind,
            [
                item.get("target_crash_status", "unknown")
                for item in contract.angelic_observations + contract.demonic_observations
            ],
        )
    message = AgentMessage(
        actor="counterfactual",
        claims=[f"CounterfactualContractAgent produced repair invariant: {contract.repair_invariant}"],
        evidence=[
            EvidenceItem(
                source="counterfactual",
                summary=f"{contract.boundary_kind}: {contract.boundary_predicate or contract.repair_intent}",
                kind="counterfactual_contract",
                payload={
                    "contract_id": contract.contract_id,
                    "target_crash_statuses": [
                        item.get("target_crash_status")
                        for item in contract.angelic_observations + contract.demonic_observations
                    ],
                    "enforcement_site": contract.enforcement_site,
                },
            )
        ],
        confidence=0.0,
        questions_for_others=[
            OpenQuestion(
                source="counterfactual",
                question="Can PatchAgent implement this repair invariant at the enforcement site instead of copying the probe value?",
                target_actor="patch",
            )
        ],
        recommended_next_actor="patch",
        artifacts={
            "counterfactual_contract": artifact,
            "counterfactual_agent_trace": agent_trace,
            "hypothesis_id": state.active_hypothesis_id,
        },
    )
    return _attach_round_metrics(
        message,
        counterfactual_round_metrics(contract, recommended_next_actor=message.recommended_next_actor),
    )


def _build_fuzz_message(state: BugHypothesisState, fuzz_result: dict) -> AgentMessage:
    state.set_fuzz_result(fuzz_result, hypothesis_id=str(fuzz_result.get("hypothesis_id", "") or state.active_hypothesis_id))
    if fuzz_result.get("bug_type_profile"):
        state.bug_type_profile = fuzz_result.get("bug_type_profile")
    hypothesis_id = fuzz_result.get("hypothesis_id") or state.active_hypothesis_id
    cost_stats = fuzz_result.get("cost_stats") if isinstance(fuzz_result.get("cost_stats"), dict) else {}
    budget_exhausted = bool(cost_stats.get("budget_exhausted", False))
    exhausted_budget = str(cost_stats.get("exhausted_budget", "") or "")

    angelic_values = fuzz_result.get("angelic_values", [])
    demonic_values = fuzz_result.get("demonic_values", [])
    if angelic_values:
        state.update_active_hypothesis(
            "angelic_found",
            success=True,
            details={"angelic_count": len(angelic_values), "hypothesis_id": hypothesis_id},
        )
        message = AgentMessage(
            actor="fuzz",
            claims=[
                "FuzzAgent found distinguishing angelic and demonic values for the current suspect."
            ],
            evidence=[
                EvidenceItem(
                    source="fuzz",
                    summary=f"deduced_constraint={fuzz_result.get('deduced_constraint', '')}",
                    kind="fuzz_result",
                    payload={
                        "hypothesis_id": hypothesis_id,
                        "angelic_values": angelic_values[:5],
                        "demonic_values": demonic_values[:5],
                        "trace_pairs": fuzz_result.get("trace_pairs", [])[:3],
                        "typed_angelic_evidence": fuzz_result.get("typed_angelic_evidence", {}),
                    },
                )
            ],
            confidence=0.65,
            questions_for_others=[
                OpenQuestion(
                    source="fuzz",
                    question="Can ConstraintAgent formalize a guard from these safe and unsafe values?",
                    target_actor="constraint",
                )
            ],
            recommended_next_actor="constraint",
            artifacts={"fuzz_result": fuzz_result, "hypothesis_id": hypothesis_id, "bug_type_profile": state.bug_type_profile},
        )
        return _attach_round_metrics(
            message,
            fuzz_round_metrics(
                fuzz_result=fuzz_result,
                hypothesis_id=hypothesis_id,
                recommended_next_actor=message.recommended_next_actor,
            ),
        )

    state.update_active_hypothesis(
        "fuzz_budget_exhausted" if budget_exhausted else "no_angelic_values",
        success=False,
        details={
            "hypothesis_id": hypothesis_id,
            "demonic_count": len(demonic_values),
            "exhausted_budget": exhausted_budget,
        },
    )
    next_actor = "debug"
    next_hypothesis = None if budget_exhausted else state.select_next_hypothesis()
    if next_hypothesis and next_hypothesis.id != hypothesis_id:
        next_actor = "fuzz"
    message = AgentMessage(
        actor="fuzz",
        claims=[
            (
                "FuzzAgent exhausted its runtime budget before finding angelic values for the current suspect."
                if budget_exhausted
                else "FuzzAgent could not find angelic values for the current suspect."
            )
        ],
        evidence=[
            EvidenceItem(
                source="fuzz",
                summary=(
                    f"Fuzz budget exhausted at {exhausted_budget or 'unknown_budget'} without angelic values."
                    if budget_exhausted
                    else "Missing angelic values means the current root-cause hypothesis is weak."
                ),
                kind="fuzz_failure",
                payload={"fuzz_result": fuzz_result},
            )
        ],
        confidence=0.2,
        questions_for_others=[
            OpenQuestion(
                source="fuzz",
                question=(
                    "Can DebugAgent refine the suspect or reduce the intervention scope before fuzzing again?"
                    if budget_exhausted
                    else "Can DebugAgent provide a different suspect or upstream line for analysis?"
                ),
                target_actor=next_actor,
            )
        ],
        recommended_next_actor=next_actor,
        artifacts={"fuzz_result": fuzz_result, "hypothesis_id": hypothesis_id, "bug_type_profile": state.bug_type_profile},
    )
    return _attach_round_metrics(
        message,
        fuzz_round_metrics(
            fuzz_result=fuzz_result,
            hypothesis_id=hypothesis_id,
            recommended_next_actor=message.recommended_next_actor,
        ),
    )


def hydrate_fuzz_state(state: BugHypothesisState, fuzz_result: dict) -> AgentMessage:
    return _build_fuzz_message(state, fuzz_result)


def run_fuzz_round(state: BugHypothesisState, llm_agent, logger=None) -> AgentMessage:
    state.select_next_hypothesis()
    suspect = state.current_suspect()
    if suspect is None:
        return AgentMessage(
            actor="fuzz",
            claims=["No suspect available for fuzzing."],
            confidence=0.0,
            recommended_next_actor="debug",
        )

    fuzz_result = fuzz_variables(
        suspect_object=suspect,
        profile=state.profile,
        debugger=debugger_instance(),
        llm_agent=llm_agent,
    )
    return _build_fuzz_message(state, fuzz_result)


def run_layer2_entry_round(state: BugHypothesisState, logger=None) -> AgentMessage:
    decision = decide_layer2_entry(state)

    message = AgentMessage(
        actor="layer2",
        claims=[decision.claim],
        confidence=0.55,
        questions_for_others=[
            OpenQuestion(
                source="layer2",
                question=decision.question,
                target_actor=decision.next_actor,
            )
        ],
        recommended_next_actor=decision.next_actor,
        artifacts={
            "layer2_entry": decision.to_artifact(state.active_hypothesis_id)
        },
    )
    return message


def run_constraint_round_adapter(state: BugHypothesisState, llm_agent, logger=None) -> AgentMessage:
    candidates, message = run_constraint_round(state, llm_agent, logger=logger)
    state.replace_constraint_candidates(candidates)
    usable = [
        c for c in candidates
        if c.constraint_status in {"supported_and_executable", "supported_but_proxy_like", "weakly_supported"}
    ]
    if usable:
        supported = [c for c in usable if str(c.challenge_result.get("status", "")).lower() == "supported"]
        falsified = [c for c in candidates if str(c.challenge_result.get("status", "")).lower() == "falsified"]
        inconclusive = [
            c for c in usable
            if str(c.challenge_result.get("status", "")).lower() in {"inconclusive", "needs_source_check"}
        ]
        state.update_active_hypothesis(
            "constraint_validated",
            success=True,
            details={"count": len(usable)},
        )
        if supported:
            state.update_active_hypothesis("constraint_supported", success=True, details={"count": len(supported)})
            if any((c.challenge_result.get("counterexample_interventions") or []) for c in supported):
                state.update_active_hypothesis("challenger_found_new_split", success=True, details={"count": len(supported)})
        if falsified:
            state.update_active_hypothesis("constraint_falsified", success=False, details={"count": len(falsified)})
        if inconclusive and not supported:
            state.update_active_hypothesis("constraint_inconclusive", success=False, details={"count": len(inconclusive)})
    else:
        state.update_active_hypothesis("weak_constraint", success=False, details={"count": len(candidates)})
    return _attach_round_metrics(
        message,
        constraint_round_metrics(candidates=candidates, recommended_next_actor=message.recommended_next_actor),
    )


def _patch_constraints_remaining(state: BugHypothesisState) -> list[ConstraintCandidate]:
    """Validated constraints we have not yet attached a patch candidate to, excluding failed LLM attempts."""
    scheduled = {c.constraint for c in state.current_patch_candidates()}
    failed = set(state.current_patch_constraints_tried())
    candidates = [
        c
        for c in state.current_valid_constraints()
        if c.constraint not in scheduled and c.constraint not in failed
    ]
    candidates = [
        c for c in candidates
        if str(c.challenge_result.get("status", "supported")) != "falsified"
    ]
    supported = [c for c in candidates if str(c.challenge_result.get("status", "")).lower() == "supported"]
    if supported:
        candidates = supported
    strong = [c for c in candidates if c.constraint_status in {"supported_and_executable", "supported_but_proxy_like"}]
    if strong:
        candidates = strong
    feedback = state.last_verification_feedback()
    if feedback and feedback.status in {"overfit_poc", "semantic_regression", "bad_patch_location", "nonlocal_invariant"}:
        high_risk_terms = ("return", "guard", "invalid", "null")
        safer = [
            c for c in candidates
            if not any(term in c.constraint.lower() for term in high_risk_terms)
        ]
        if safer:
            return safer
    candidates.sort(key=lambda c: (-float(c.overall_score or 0.0), -float(c.generalization_score or 0.0), c.attempts))
    return candidates


def _candidate_strategy_plan(candidate: ConstraintCandidate, suspect: dict, last_feedback) -> list[dict]:
    ranked = patch_agent._rank_patch_strategies(candidate.constraint, {**suspect, **candidate.__dict__})
    challenge_status = str(candidate.challenge_result.get("status", "")).lower()
    patchability_score = float(candidate.challenge_result.get("patchability_score", 1.0) or 1.0)
    low_patchability = patchability_score < 0.45
    if challenge_status in {"needs_source_check", "inconclusive"} or low_patchability:
        ranked = [item for item in ranked if item.get("location_type") == "upstream"] + [
            item for item in ranked if item.get("location_type") != "upstream"
        ]
    if challenge_status in {"needs_source_check", "inconclusive"} or low_patchability:
        ranked = [
            item for item in ranked
            if item.get("location_type") == "upstream" and item.get("semantic_risk") == "low"
        ] + [
            item for item in ranked
            if not (item.get("location_type") == "upstream" and item.get("semantic_risk") == "low")
        ]
    if last_feedback and last_feedback.status in {"overfit_poc", "semantic_regression", "bad_patch_location", "nonlocal_invariant"}:
        ranked = [item for item in ranked if item.get("location_type") == "upstream"] + [
            item for item in ranked if item.get("location_type") != "upstream"
        ]
    limit = 3 if candidate.generalization_score >= 0.75 else 2
    return ranked[:limit]


def _verification_feedback_from_dict(feedback: dict) -> VerificationFeedback:
    allowed = set(VerificationFeedback.__dataclass_fields__)
    raw = dict(feedback or {})
    payload = {key: value for key, value in raw.items() if key in allowed}
    details = payload.get("details") if isinstance(payload.get("details"), dict) else {}
    details = dict(details)
    extras = {key: value for key, value in raw.items() if key not in allowed}
    for key in ("runtime_output", "crash_site", "frames", "errors", "residual_risk"):
        if key in extras and key not in details:
            details[key] = extras[key]
    if extras:
        details["extra_feedback"] = extras
    payload["details"] = details
    payload.setdefault("status", "unknown")
    payload.setdefault("message", "")
    return VerificationFeedback(**payload)


def _candidate_location_plan(candidate: ConstraintCandidate, suspect: dict) -> list[dict]:
    locations: list[dict] = []
    seen: set[tuple[str, int, str]] = set()
    challenge_status = str(candidate.challenge_result.get("status", "")).lower()
    patchability_score = float(candidate.challenge_result.get("patchability_score", 1.0) or 1.0)

    def add(location: dict, source: str) -> None:
        if not isinstance(location, dict):
            return
        file = str(location.get("file", "")).strip()
        line = int(location.get("line", -1) or -1)
        role = str(location.get("role", "")).strip()
        if not file or line <= 0:
            return
        key = (file, line, role)
        if key in seen:
            return
        seen.add(key)
        entry = dict(location)
        entry["source"] = source
        locations.append(entry)

    abstract_constraint = candidate.abstract_constraint if isinstance(candidate.abstract_constraint, dict) else {}
    add(abstract_constraint.get("enforcement_site", {}), "counterfactual_enforcement")
    add(suspect.get("preferred_edit_location", {}), "preferred")
    for item in suspect.get("candidate_edit_locations", []) or []:
        add(item, "candidate")
    for group in suspect.get("location_groups", []) or []:
        for item in group.get("locations", []) or []:
            add(item, "group")

    def weight(location: dict) -> tuple:
        role = str(location.get("role", ""))
        source = str(location.get("source", ""))
        why = str(location.get("why_here", "")).lower()
        patchability = float(location.get("patchability_score", 0.0) or 0.0)
        enforcement_roles = {
            "producer",
            "existing_guard",
            "init_path",
            "ownership_transfer",
            "api_boundary",
            "state_transition",
        }
        is_upstreamish = (
            "upstream" in role
            or "root_cause" in role
            or "state_init" in role
            or "constructor_init" in role
            or "earlier" in why
        )
        same_site_guard = "same_site_guard" in role
        low_patchability_case = challenge_status in {"inconclusive", "needs_source_check"} or patchability_score < 0.45
        return (
            0 if source == "counterfactual_enforcement" else 1,
            0 if role in enforcement_roles else 1,
            0 if (low_patchability_case and is_upstreamish) else 1,
            1 if same_site_guard else 0,
            -patchability,
            int(location.get("line", 0) or 0),
        )

    locations.sort(key=weight)
    return locations[:4]


def _parse_python_literal(response: str):
    text = str(response or "").strip()
    if not text:
        return None
    fenced = re.search(r"```(?:python|json)?\s*(.*?)```", text, re.S)
    if fenced:
        text = fenced.group(1).strip()
    start = min((idx for idx in (text.find("{"), text.find("[")) if idx != -1), default=-1)
    end = max(text.rfind("}"), text.rfind("]"))
    if start != -1 and end != -1 and end > start:
        text = text[start : end + 1]
    try:
        return ast.literal_eval(text)
    except Exception:
        return None


def _generic_operational_intent(text: str, template: str = "") -> bool:
    normalized = " ".join(str(text or "").lower().split())
    template_normalized = " ".join(str(template or "").lower().split())
    if not normalized:
        return True
    if template_normalized and normalized == template_normalized:
        return True
    generic_markers = (
        "repair the upstream state transition",
        "repair the operational mechanism",
        "apply the minimal repair",
        "repair the size or extent relation",
    )
    return any(marker in normalized for marker in generic_markers)


def _llm_operational_repair_intent(state: BugHypothesisState, suspect: dict, llm_agent, logger=None) -> dict:
    report = state.current_root_cause_report()
    if report is None or str(report.evidence_family) != "operational" or llm_agent is None:
        return {}
    if not _generic_operational_intent(report.operational_repair_intent, report.direct_patch_contract):
        return {}
    prompt = OPERATIONAL_REPAIR_INTENT_PROMPT.format(
        template_intent=report.operational_repair_intent or report.direct_patch_contract,
        bug_type_profile=suspect.get("bug_type_profile", {}),
        evidence_kind=report.evidence_kind,
        preferred_repair_stage=report.preferred_repair_stage,
        preferred_edit_location=report.preferred_edit_location,
        candidate_edit_locations=report.candidate_edit_locations[:8],
        variable_names=suspect.get("variable_names", []),
        debug_summary=suspect.get("debug_summary", ""),
    )
    try:
        parsed = _parse_python_literal(llm_agent.query(prompt, logger=logger))
    except Exception as exc:
        if logger is not None:
            logger.warning("Operational repair-intent LLM failed: %s", exc)
        return {}
    if not isinstance(parsed, dict):
        return {}

    repair_intent = str(parsed.get("repair_intent", "")).strip()
    if not repair_intent or _generic_operational_intent(repair_intent, report.direct_patch_contract):
        return {}

    def clean_list(value) -> list[str]:
        if not isinstance(value, list):
            return []
        return [str(item).strip() for item in value if str(item).strip()][:6]

    return {
        "repair_intent": repair_intent[:600],
        "mechanism_hint": str(parsed.get("mechanism_hint", "")).strip()[:120],
        "required_edits": clean_list(parsed.get("required_edits", [])),
        "forbidden_patch_shape": clean_list(parsed.get("forbidden_patch_shape", [])),
        "reason": str(parsed.get("reason", "")).strip()[:600],
    }


def _refine_operational_root_cause_report(state: BugHypothesisState, suspect: dict, llm_agent, logger=None) -> dict:
    report = state.current_root_cause_report()
    if report is None or str(report.evidence_family) != "operational":
        return report.__dict__ if report is not None else {}
    if state_only_no_angelic(state.profile):
        return report.__dict__
    inference = _llm_operational_repair_intent(state, suspect, llm_agent, logger=logger)
    if not inference:
        return report.__dict__

    report.operational_repair_intent = inference["repair_intent"]
    suspect["operational_repair_intent_inference"] = inference
    report.evidence_requirements = list(report.evidence_requirements or [])
    detail = "LLM operational repair intent inferred from debug summary."
    if inference.get("reason"):
        detail = f"{detail} {inference['reason']}"
    if detail not in report.evidence_requirements:
        report.evidence_requirements.append(detail)
    if report.hypothesis_id or state.active_hypothesis_id:
        state.set_root_cause_report(report, hypothesis_id=report.hypothesis_id or state.active_hypothesis_id)

    refined = dict(report.__dict__)
    refined["operational_repair_intent_inference"] = inference
    return refined


def _llm_patch_strategy_plan(candidate: ConstraintCandidate, suspect: dict, llm_agent, logger=None) -> list[dict]:
    if llm_agent is None:
        return []
    function_name = str(suspect.get("function_name", "")).strip()
    function_body = ""
    if function_name:
        try:
            function_body = patch_agent.function_body(suspect.get("file", ""), function_name)
        except Exception as exc:
            if logger is not None:
                logger.warning("Failed to fetch function body for patch planning: %s", exc)
    prompt = PATCH_STRATEGY_ANALYST_PROMPT.format(
        bug_type_profile=(candidate.bug_type_profile or suspect.get("bug_type_profile") or {}),
        constraint=candidate.constraint,
        constraint_status=candidate.constraint_status,
        repair_intent=candidate.repair_intent,
        debug_summary=suspect.get("debug_summary", ""),
        angelic_values=candidate.top_angelic_examples[:3],
        demonic_summary=candidate.demonic_summary,
        function_body=function_body,
    )
    try:
        parsed = _parse_python_literal(llm_agent.query(prompt, logger=logger))
    except Exception as exc:
        if logger is not None:
            logger.warning("Patch strategy LLM failed for `%s`: %s", candidate.constraint, exc)
        parsed = None
    if not isinstance(parsed, list):
        return []
    out: list[dict] = []
    for item in parsed[:3]:
        if not isinstance(item, dict):
            continue
        strategy = str(item.get("strategy", "")).strip()
        location_type = str(item.get("location_type", "")).strip()
        semantic_risk = str(item.get("semantic_risk", "")).strip()
        rationale = str(item.get("rationale", "")).strip()
        if strategy not in {
            "reject_invalid_input",
            "clamp_or_normalize",
            "fix_upstream_invariant",
            "bounds_check_before_access",
            "null_or_lifetime_guard",
            "allocation_size_fix",
            "loop_bound_fix",
            "semantic_noop_reject",
        }:
            continue
        if location_type not in {"upstream", "same_site", "downstream"}:
            continue
        if semantic_risk not in {"low", "medium", "high"}:
            continue
        normalized = {
            "strategy": strategy,
            "location_type": location_type,
            "semantic_risk": semantic_risk,
            "rationale": rationale or "LLM-recommended strategy.",
            "requires_regression_check": semantic_risk == "high",
        }
        if normalized not in out:
            out.append(normalized)
    return out


def run_patch_round(state: BugHypothesisState, llm_agent=None, logger=None) -> AgentMessage:
    suspect = state.current_suspect()
    if suspect is None:
        return AgentMessage(
            actor="patch",
            claims=["No suspect available for patch generation."],
            confidence=0.0,
            recommended_next_actor="debug",
        )

    _refine_operational_root_cause_report(state, suspect, llm_agent, logger=logger)
    patch_plan = plan_patch_round(
        state=state,
        suspect=suspect,
        pending_constraints=_patch_constraints_remaining(state)[:6],
        patch_agent_module=patch_agent,
    )
    root_cause_report = patch_plan.root_cause_report
    direct_patch_mode = patch_plan.direct_patch_mode
    pending_constraints = list(patch_plan.pending_constraints)
    state_only_mode = state_only_no_angelic(state.profile)
    budget_limited = patch_search_budget_limited(state.profile)
    if budget_limited:
        pending_constraints = pending_constraints[:1]
    operational_patch_mode = any(c.constraint_status == "operational_repair_intent" for c in pending_constraints)
    counterfactual_patch_mode = any(c.constraint_status == "counterfactual_contract" for c in pending_constraints)

    if not pending_constraints:
        return AgentMessage(
            actor="patch",
            claims=[patch_plan.empty_claim],
            confidence=0.0,
            recommended_next_actor="done" if state_only_mode else patch_plan.empty_next_actor,
            artifacts={"root_cause_report": root_cause_report} if root_cause_report else {},
        )

    generated: list[PatchCandidate] = []
    last_feedback = state.last_verification_feedback()
    if direct_patch_mode:
        state.mark_direct_patch_attempted()

    for candidate in pending_constraints:
        strategy_plan = list(candidate.strategy_hints)
        if direct_patch_mode:
            for item in patch_agent._rank_patch_strategies(
                str(root_cause_report.get("direct_patch_contract", "")),
                suspect,
            )[:3]:
                if item not in strategy_plan:
                    strategy_plan.append(item)
        location_plan = _candidate_location_plan(candidate, suspect)
        if direct_patch_mode:
            location_plan = [dict(item) for item in root_cause_report.get("candidate_edit_locations", []) or []] or location_plan
        llm_plan = [] if state_only_mode else _llm_patch_strategy_plan(candidate, suspect, llm_agent, logger=logger)
        for item in llm_plan:
            if item not in strategy_plan:
                strategy_plan.append(item)
        for item in _candidate_strategy_plan(candidate, suspect, last_feedback):
            if item not in strategy_plan:
                strategy_plan.append(item)
        patch_candidate_limit = 1 if budget_limited else 4
        if budget_limited:
            location_plan = location_plan[:3]
            strategy_plan = strategy_plan[:2]
        produced_for_constraint = False
        for active_location in location_plan or [suspect.get("preferred_edit_location", {})]:
            for forced_strategy in strategy_plan:
                patch_suspect = dict(suspect)
                patch_suspect.update(candidate.__dict__)
                if candidate.typed_angelic_evidence:
                    patch_suspect["typed_angelic_evidence"] = candidate.typed_angelic_evidence
                elif state.current_fuzz_result():
                    patch_suspect["typed_angelic_evidence"] = (state.current_fuzz_result() or {}).get("typed_angelic_evidence", {})
                if candidate.demonic_trace_summary:
                    patch_suspect["demonic_trace_summary"] = candidate.demonic_trace_summary
                elif state.current_fuzz_result():
                    patch_suspect["demonic_trace_summary"] = (state.current_fuzz_result() or {}).get("demonic_trace_summary", {})
                for item in candidate.strategy_hints:
                    if isinstance(item, dict) and "angelic_consumption_contract" in item:
                        patch_suspect["angelic_consumption_contract"] = item["angelic_consumption_contract"]
                if last_feedback is not None:
                    patch_suspect["last_verification_status"] = last_feedback.status
                    patch_suspect["last_verification_blame_hint"] = last_feedback.blame_hint
                patch_suspect["forced_patch_strategy"] = forced_strategy
                patch_suspect["challenge_result"] = dict(candidate.challenge_result or {})
                patch_suspect["active_patch_location"] = dict(active_location or {})
                if candidate.abstract_constraint.get("type") in {"counterfactual_contract", "counterfactual_invariant"}:
                    patch_suspect["counterfactual_invariant"] = dict(candidate.abstract_constraint)
                    patch_suspect["counterfactual_contract"] = dict(candidate.abstract_constraint)
                    patch_suspect["validation_obligations"] = list(
                        candidate.abstract_constraint.get("validation_obligations", []) or []
                    )
                candidate_locations = list(patch_suspect.get("candidate_edit_locations", []) or [])
                prioritized_locations = [dict(active_location)] + [loc for loc in candidate_locations if loc != active_location]
                patch_suspect["candidate_edit_locations"] = prioritized_locations
                if active_location:
                    patch_suspect["preferred_edit_location"] = dict(active_location)
                patch = patch_agent.patch(state.profile, candidate.constraint, patch_suspect, logger=logger)
                if patch and patch.get("patches"):
                    meta = {
                        "hypothesis_id": state.active_hypothesis_id,
                        "hypothesis_summary": _current_hypothesis_summary(state),
                        "suspect_file": suspect.get("file"),
                        "suspect_line": suspect.get("line"),
                        "debug_summary": suspect.get("debug_summary", ""),
                        "bug_type_profile": candidate.bug_type_profile or state.bug_type_profile or {},
                        "typed_angelic_evidence": candidate.typed_angelic_evidence or (state.current_fuzz_result() or {}).get("typed_angelic_evidence", {}),
                        "demonic_trace_summary": candidate.demonic_trace_summary or (state.current_fuzz_result() or {}).get("demonic_trace_summary", {}),
                        "challenge_result": dict(candidate.challenge_result or {}),
                        "abstract_constraint": dict(candidate.abstract_constraint or {}),
                        "active_patch_location": dict(active_location or {}),
                        "heuristic": bool(patch.get("heuristic")),
                        "repair_layer": "layer1" if direct_patch_mode else ("counterfactual" if counterfactual_patch_mode else "layer2"),
                        "root_cause_report": root_cause_report if direct_patch_mode or operational_patch_mode or counterfactual_patch_mode else {},
                        "counterfactual_invariant": dict(candidate.abstract_constraint or {}) if counterfactual_patch_mode else {},
                        "counterfactual_contract": dict(candidate.abstract_constraint or {}) if counterfactual_patch_mode else {},
                        "evidence_family": (
                            "counterfactual"
                            if counterfactual_patch_mode
                            else "operational" if candidate.constraint_status == "operational_repair_intent" else "predicate"
                        ),
                        "evidence_kind": (candidate.typed_angelic_evidence or {}).get("evidence_kind", ""),
                        "constraint_role": candidate.constraint_role,
                        "strategy": patch.get("strategy", forced_strategy.get("strategy", "bounds_check_before_access")),
                        "location_type": patch.get("location_type", forced_strategy.get("location_type", "same_site")),
                        "semantic_risk": patch.get("semantic_risk", forced_strategy.get("semantic_risk", "medium")),
                        "requires_regression_check": bool(patch.get("requires_regression_check", False)),
                    }
                    generated.append(
                        PatchCandidate(
                            constraint=candidate.constraint,
                            patches=patch.get("patches", []),
                            retry=int(patch.get("retry", 0)),
                            valid=bool(patch.get("valid", False)),
                            resign=bool(patch.get("resign", False)),
                            metadata=meta,
                            strategy=meta["strategy"],
                            location_type=meta["location_type"],
                            semantic_risk=meta["semantic_risk"],
                            requires_regression_check=meta["requires_regression_check"],
                        )
                    )
                    produced_for_constraint = True
                if len(generated) >= patch_candidate_limit:
                    break
            if len(generated) >= patch_candidate_limit or produced_for_constraint:
                break
        if not produced_for_constraint:
            state.mark_patch_constraint_tried(candidate.constraint)
        if len(generated) >= patch_candidate_limit:
            break

    if not generated and not budget_limited:
        have = {pc.constraint for pc in state.current_patch_candidates()}
        for cand in state.current_valid_constraints()[:6]:
            if cand.constraint in have:
                continue
            heuristic_suspect = dict(suspect)
            if last_feedback is not None:
                heuristic_suspect["last_verification_status"] = last_feedback.status
            hp = try_heuristic_min_patch(state.profile, heuristic_suspect, cand.constraint)
            if hp and hp.get("patches"):
                if logger:
                    logger.info("Heuristic patch candidate produced for constraint: %s", cand.constraint)
                generated.append(
                    PatchCandidate(
                        constraint=cand.constraint,
                        patches=hp["patches"],
                        retry=int(hp.get("retry", 0)),
                        valid=bool(hp.get("valid", False)),
                        resign=bool(hp.get("resign", False)),
                            metadata={
                                "hypothesis_id": state.active_hypothesis_id,
                                "hypothesis_summary": _current_hypothesis_summary(state),
                            "suspect_file": suspect.get("file"),
                            "suspect_line": suspect.get("line"),
                            "debug_summary": suspect.get("debug_summary", ""),
                            "bug_type_profile": cand.bug_type_profile or state.bug_type_profile or {},
                            "typed_angelic_evidence": cand.typed_angelic_evidence or (state.current_fuzz_result() or {}).get("typed_angelic_evidence", {}),
                            "demonic_trace_summary": cand.demonic_trace_summary or (state.current_fuzz_result() or {}).get("demonic_trace_summary", {}),
                                "challenge_result": dict(cand.challenge_result or {}),
                                "heuristic": True,
                                "repair_layer": "layer2",
                                "strategy": hp.get("strategy", "bounds_check_before_access"),
                                "location_type": hp.get("location_type", "same_site"),
                                "semantic_risk": hp.get("semantic_risk", "medium"),
                            "requires_regression_check": bool(hp.get("requires_regression_check", False)),
                        },
                        strategy=hp.get("strategy", "bounds_check_before_access"),
                        location_type=hp.get("location_type", "same_site"),
                        semantic_risk=hp.get("semantic_risk", "medium"),
                        requires_regression_check=bool(hp.get("requires_regression_check", False)),
                    )
                )
                break

    state.add_patch_candidates(generated)
    if generated:
        state.update_active_hypothesis("patch_generated", success=True, details={"count": len(generated)})
        message = AgentMessage(
            actor="patch",
            claims=[
                (
                    f"PatchAgent produced {len(generated)} direct patch candidate(s) from the root-cause report."
                    if direct_patch_mode
                    else (
                        f"PatchAgent produced {len(generated)} patch candidate(s) from the counterfactual contract."
                        if counterfactual_patch_mode
                        else (
                        f"PatchAgent produced {len(generated)} patch candidate(s) from operational repair intent."
                        if operational_patch_mode
                        else f"PatchAgent produced {len(generated)} patch candidate(s) from validated constraints."
                        )
                    )
                )
            ],
            evidence=[
                EvidenceItem(
                    source="patch",
                    summary=f"Generated patch for constraint {generated[0].constraint}",
                    kind="patch_candidate",
                    payload={"patch_count": len(generated[0].patches), "heuristic": generated[0].metadata.get("heuristic")},
                )
            ],
            confidence=0.6,
            questions_for_others=[
                OpenQuestion(
                    source="patch",
                    question=(
                        "Can VerifyAgent classify whether this direct patch is strong enough to accept or should escalate into Layer 2?"
                        if direct_patch_mode
                        else "Can VerifyAgent determine whether the candidate fixes the crash or refines the hypothesis?"
                    ),
                    target_actor="verify",
                )
            ],
            recommended_next_actor="verify",
            artifacts={
                "patch_candidates": [candidate.__dict__ for candidate in generated],
                **({"root_cause_report": root_cause_report} if direct_patch_mode or operational_patch_mode or counterfactual_patch_mode else {}),
                **(
                    {"counterfactual_contract": counterfactual_agent.contract_to_dict(state.current_counterfactual_contract())}
                    if counterfactual_patch_mode and state.current_counterfactual_contract() is not None
                    else {}
                ),
            },
        )
        return _attach_round_metrics(
            message,
            patch_round_metrics(generated=generated, recommended_next_actor=message.recommended_next_actor),
        )

    more = _patch_constraints_remaining(state)
    next_actor = "done" if state_only_mode else (
        "patch" if more else ("layer2" if direct_patch_mode else ("counterfactual" if counterfactual_patch_mode else "constraint"))
    )
    return AgentMessage(
        actor="patch",
        claims=[patch_plan.empty_claim],
        confidence=0.1,
        recommended_next_actor=next_actor,
        artifacts={"root_cause_report": root_cause_report} if root_cause_report else {},
    )


def run_verify_round(state: BugHypothesisState, logger=None) -> AgentMessage:
    candidate = state.next_unverified_patch()
    if candidate is None:
        next_actor = "done" if state.champion_patch else "patch"
        return AgentMessage(
            actor="verify",
            claims=["No pending patch candidate remains for verification."],
            confidence=0.0,
            recommended_next_actor=next_actor,
        )

    patch_payload = {
        "patches": candidate.patches,
        "profile": state.profile,
        "constraint": candidate.constraint,
        "hypothesis_id": candidate.metadata.get("hypothesis_id", ""),
        "hypothesis_summary": candidate.metadata.get("hypothesis_summary", ""),
        "suspect_file": candidate.metadata.get("suspect_file", ""),
        "suspect_line": candidate.metadata.get("suspect_line", -1),
        "bug_type_profile": candidate.metadata.get("bug_type_profile", {}),
        "typed_angelic_evidence": candidate.metadata.get("typed_angelic_evidence", {}),
        "demonic_trace_summary": candidate.metadata.get("demonic_trace_summary", {}),
        "challenge_result": candidate.metadata.get("challenge_result", {}),
        "repair_layer": candidate.metadata.get("repair_layer", "layer2"),
        "root_cause_report": candidate.metadata.get("root_cause_report", {}),
        "evidence_family": candidate.metadata.get("evidence_family", ""),
        "evidence_kind": candidate.metadata.get("evidence_kind", ""),
        "constraint_role": candidate.metadata.get("constraint_role", ""),
        "strategy": candidate.strategy,
        "location_type": candidate.location_type,
        "semantic_risk": candidate.semantic_risk,
        "requires_regression_check": candidate.requires_regression_check,
    }
    feedback = verify_patch_feedback(
        patch_payload,
        expected_file=candidate.metadata.get("suspect_file"),
        expected_line=candidate.metadata.get("suspect_line"),
        logger=logger,
    )
    candidate.verification = feedback
    decision = classify_verification_outcome(candidate, feedback)
    if (
        lldb_only(state.profile)
        and feedback.get("status") == "pass"
        and feedback.get("layer1_verdict") == "weak"
    ):
        decision = VerifyRoundDecision(
            candidate_status="validated",
            next_actor="done",
            claim="LLDB-only VerifyAgent accepted the replay-passing direct patch without Layer 2 validation.",
            confidence=0.75,
            event="lldb_only_replay_verified_patch",
            success=True,
            done=True,
        )
        feedback["message"] = (
            "Direct patch passed replay and was accepted by the LLDB-only ablation "
            "without counterfactual validation."
        )
    candidate.status = decision.candidate_status
    state.add_verification_feedback(_verification_feedback_from_dict(feedback))

    if decision.done:
        if decision.event:
            state.update_active_hypothesis(decision.event, success=decision.success, details={"constraint": candidate.constraint})
        patch_payload["verification_feedback"] = feedback
        patch_payload["verification_confidence"] = feedback.get("details", {}).get("verification_confidence", 0.75)
        candidate.metadata["verified_patch_payload"] = patch_payload
        next_actor = "verify" if state.next_unverified_patch() is not None else "done"
        message = AgentMessage(
            actor="verify",
            claims=[decision.claim],
            evidence=[
                EvidenceItem(
                    source="verify",
                    summary=feedback["message"],
                    kind="verification_pass",
                    payload=feedback,
                )
            ],
            confidence=decision.confidence,
            recommended_next_actor=next_actor,
            artifacts={"verification_feedback": feedback, "validated_patch_candidate": patch_payload},
        )
        return _attach_round_metrics(message, verification_round_metrics(feedback=feedback, candidate=candidate))

    if decision.event:
        state.update_active_hypothesis(
            decision.event,
            success=decision.success,
            details={"constraint": candidate.constraint, "verdict": feedback.get("layer1_verdict", "")},
        )
    if decision.next_actor == "layer2":
        state.request_layer2_fuzz_refresh(
            reason=(
                f"verify:{feedback.get('status', 'unknown')}:{feedback.get('layer1_verdict', '') or candidate.metadata.get('repair_layer', 'layer2')}"
            ),
            hypothesis_id=state.active_hypothesis_id,
        )
    if feedback.get("layer1_verdict") in {"weak", "suspicious"}:
        message = AgentMessage(
            actor="verify",
            claims=[decision.claim],
            evidence=[
                EvidenceItem(
                    source="verify",
                    summary=feedback["message"],
                    kind="verification_feedback",
                    payload=feedback,
                )
            ],
            confidence=decision.confidence,
            questions_for_others=[
                OpenQuestion(
                    source="verify",
                    question=decision.question,
                    target_actor=decision.next_actor,
                )
            ],
            recommended_next_actor=decision.next_actor,
            artifacts={"verification_feedback": feedback},
        )
        return _attach_round_metrics(message, verification_round_metrics(feedback=feedback, candidate=candidate))

    message = AgentMessage(
        actor="verify",
        claims=[decision.claim],
        evidence=[
            EvidenceItem(
                source="verify",
                summary=feedback["message"],
                kind="verification_feedback",
                payload=feedback,
            )
        ],
        confidence=0.45,
        questions_for_others=[
            OpenQuestion(
                source="verify",
                question=decision.question,
                target_actor=decision.next_actor,
            )
        ],
        recommended_next_actor=decision.next_actor,
        artifacts={"verification_feedback": feedback},
    )
    return _attach_round_metrics(message, verification_round_metrics(feedback=feedback, candidate=candidate))


def _all_patch_candidates(state: BugHypothesisState) -> list[tuple[str, int, PatchCandidate]]:
    items: list[tuple[str, int, PatchCandidate]] = []
    seen: set[int] = set()
    for hypothesis_id, candidates in (state.patch_candidates_by_hypothesis or {}).items():
        for index, candidate in enumerate(candidates or []):
            seen.add(id(candidate))
            items.append((str(hypothesis_id or ""), index, candidate))
    for index, candidate in enumerate(state.patch_candidates or []):
        if id(candidate) not in seen:
            items.append((state.active_hypothesis_id, index, candidate))
    return items


def _candidate_vote_id(hypothesis_id: str, index: int) -> str:
    safe_hid = re.sub(r"[^A-Za-z0-9_.-]+", "_", str(hypothesis_id or "hyp"))
    return f"{safe_hid}#{index}"


def _patch_snippet(patches: list[dict], max_chars: int = 1600) -> str:
    lines: list[str] = []
    for patch in patches or []:
        lines.append(f"file={patch.get('file')} lines={patch.get('start_line')}..{patch.get('end_line')}")
        lines.append(str(patch.get("patch", "")))
    text = "\n".join(lines)
    if len(text) > max_chars:
        return text[:max_chars] + "\n...[truncated]"
    return text


def _deterministic_champion_score(candidate: PatchCandidate) -> tuple:
    feedback = candidate.verification or {}
    details = feedback.get("details") if isinstance(feedback.get("details"), dict) else {}
    confidence = float(details.get("verification_confidence", 0.0) or 0.0)
    risk_rank = {"low": 2, "medium": 1, "high": 0}.get(str(candidate.semantic_risk or "medium"), 1)
    layer_rank = 1 if str(candidate.metadata.get("repair_layer", "layer2")) == "layer2" else 0
    regression_penalty = 1 if candidate.requires_regression_check else 0
    patch_size = sum(len(str(patch.get("patch", ""))) for patch in candidate.patches or [])
    return (
        confidence,
        risk_rank,
        layer_rank,
        -regression_penalty,
        -patch_size,
    )


def _build_verified_patch_payload(state: BugHypothesisState, candidate: PatchCandidate) -> dict:
    payload = dict(candidate.metadata.get("verified_patch_payload") or {})
    if payload:
        return payload
    payload = {
        "patches": candidate.patches,
        "profile": state.profile,
        "constraint": candidate.constraint,
        "hypothesis_id": candidate.metadata.get("hypothesis_id", ""),
        "hypothesis_summary": candidate.metadata.get("hypothesis_summary", ""),
        "suspect_file": candidate.metadata.get("suspect_file", ""),
        "suspect_line": candidate.metadata.get("suspect_line", -1),
        "strategy": candidate.strategy,
        "location_type": candidate.location_type,
        "semantic_risk": candidate.semantic_risk,
        "requires_regression_check": candidate.requires_regression_check,
        "verification_feedback": candidate.verification,
    }
    payload["verification_confidence"] = (candidate.verification or {}).get("details", {}).get("verification_confidence", 0.75)
    return payload


def _llm_vote_for_champion(validated: list[dict], llm_agent, logger=None) -> dict | None:
    if llm_agent is None or len(validated) < 2:
        return None
    compact = []
    for item in validated:
        candidate = item["candidate"]
        feedback = candidate.verification or {}
        compact.append(
            {
                "id": item["id"],
                "hypothesis_id": item["hypothesis_id"],
                "constraint": candidate.constraint[:700],
                "hypothesis_summary": str(candidate.metadata.get("hypothesis_summary", ""))[:900],
                "strategy": candidate.strategy,
                "location_type": candidate.location_type,
                "semantic_risk": candidate.semantic_risk,
                "requires_regression_check": candidate.requires_regression_check,
                "verification_status": feedback.get("status"),
                "verification_message": str(feedback.get("message", ""))[:900],
                "residual_risk": (feedback.get("details") or {}).get("residual_risk") if isinstance(feedback.get("details"), dict) else "",
                "patch": _patch_snippet(candidate.patches),
            }
        )
    prompt = (
        "You are selecting the champion patch among internally verified crash repairs.\n"
        "Hard rules:\n"
        "- Only choose from the provided candidate ids.\n"
        "- Prefer fixes that address the root cause over crash-site suppression.\n"
        "- Prefer lower semantic risk, smaller localized diffs, and fewer residual risks.\n"
        "- Do not choose a candidate with sanitizer/runtime failure; those candidates should not be in this list.\n"
        "Return exactly a Python/JSON dict: "
        "{\"best_candidate_id\": \"...\", \"rationale\": \"...\", \"ranked_candidate_ids\": [\"...\"]}.\n\n"
        f"Candidates:\n{compact}"
    )
    try:
        parsed = _parse_python_literal(llm_agent.query(prompt, logger=logger))
    except Exception as exc:
        if logger is not None:
            logger.warning("Champion vote LLM failed: %s", exc)
        return None
    if not isinstance(parsed, dict):
        return None
    return parsed


def select_champion_patch(state: BugHypothesisState, llm_agent=None, logger=None) -> dict | None:
    validated: list[dict] = []
    for hypothesis_id, index, candidate in _all_patch_candidates(state):
        if candidate.status != "validated":
            continue
        feedback = candidate.verification or {}
        if feedback.get("status") != "pass":
            continue
        validated.append(
            {
                "id": _candidate_vote_id(hypothesis_id, index),
                "hypothesis_id": hypothesis_id,
                "index": index,
                "candidate": candidate,
            }
        )
    if not validated:
        return None
    by_id = {item["id"]: item for item in validated}
    vote = _llm_vote_for_champion(validated, llm_agent, logger=logger)
    used_llm_vote = False
    chosen = None
    if vote:
        chosen_id = str(vote.get("best_candidate_id", ""))
        chosen = by_id.get(chosen_id)
        used_llm_vote = chosen is not None
    if chosen is None:
        chosen = max(validated, key=lambda item: _deterministic_champion_score(item["candidate"]))
        vote = {
            "best_candidate_id": chosen["id"],
            "rationale": "Deterministic fallback selected the strongest validated candidate.",
            "ranked_candidate_ids": [item["id"] for item in sorted(validated, key=lambda item: _deterministic_champion_score(item["candidate"]), reverse=True)],
        }
    payload = _build_verified_patch_payload(state, chosen["candidate"])
    payload["champion_selection"] = {
        "method": "llm_vote" if used_llm_vote else "deterministic_fallback",
        "candidate_id": chosen["id"],
        "candidate_count": len(validated),
        "vote": vote,
    }
    state.champion_patch = payload
    state.champion_feedback = chosen["candidate"].verification
    return payload
