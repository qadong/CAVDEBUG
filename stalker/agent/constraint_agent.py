from __future__ import annotations

import ast
import re

from agent.contracts import AgentMessage, ConstraintCandidate, EvidenceItem, OpenQuestion
from agent.prompts import (
    CONSTRAINT_SEMANTICS_PROMPT,
    OPERATIONAL_CONSTRAINT_GENERALIZATION_PROMPT,
    STALK_BRAINSTORM_PROMPT,
)
from agent.state import BugHypothesisState
from agent.type_angelic import build_stage_prompt_overlay, infer_bug_type_profile
from tools.debugger.experiment_runner import DebuggerIntervention
from tools.debugger.harness import DebuggerHarness
from tools.debugger.functions import (
    debugger_assign,
    debugger_add_functional_guard,
    debugger_assign_expression,
    debugger_continue,
    debugger_print,
    debugger_run_to_line,
)
from utils.logger import logf
from utils.seed_records import angelic_assignment_sets, demonic_value_map

NAME = "agent-constraint"


class _ConstraintDebuggerBackend:
    def run(self):
        raise NotImplementedError("Constraint flow does not use raw debugger run().")

    def continue_run(self):
        result = debugger_continue()
        return result if isinstance(result, tuple) and len(result) == 2 else ({}, "")

    def run_to_line(self, file, start_line, end_line=None, ignore_count=None, condition=None):
        result = debugger_run_to_line(file, start_line, end_line=end_line, ignore_count=ignore_count, condition=condition)
        if isinstance(result, tuple) and len(result) == 2:
            return result
        return {"reason": "breakpoint-hit", "file": file, "line": start_line}, ""

    def run_to_last_hit(self, file, line):
        raise NotImplementedError("Constraint flow does not use run_to_last_hit().")

    def clear_breakpoints(self):
        return []

    def set_breakpoint(self, file, start_line, end_line=None, ignore_count=None, condition=None):
        return []

    def get_breakpoint_hit_count(self, breakpoint_id):
        return 0

    def print_value(self, expression):
        return debugger_print(expression)

    def get_type(self, expression):
        return "unknown"

    def assign(self, variable, value):
        return debugger_assign(variable, value)

    def assign_expression(self, expression):
        return debugger_assign_expression(expression)

    def add_functional_guard(self, file, line, condition, return_value):
        return debugger_add_functional_guard(file, line, condition, return_value)

    def execute(self, command):
        return ""

    def backtrace(self):
        return []

    def reset_cost_stats(self):
        return None

    def get_cost_stats(self):
        return {}


def _make_constraint_harness(suspect_object: dict | None = None) -> DebuggerHarness:
    return DebuggerHarness(suspect_object=suspect_object or {}, backend=_ConstraintDebuggerBackend())


def _collect_function_body(suspect_object: dict, logger) -> str:
    function_body = ""
    try:
        from tools.file.functions import file_get_decorated_content
        from tools.lsp.functions import lsp_get_function

        function_name = suspect_object.get("function_name", "")
        if function_name:
            function_body = lsp_get_function(suspect_object["file"], function_name)

        if not function_body:
            start_line = max(1, suspect_object.get("line", 1) - 20)
            end_line = suspect_object.get("line", 1) + 20
            function_body = file_get_decorated_content(suspect_object["file"], start_line, end_line)
    except Exception as exc:
        logger.warning(f"Failed to fetch function body: {exc}")
    return function_body


def _parse_constraint_candidates(response: str, initial_constraint: str, logger) -> list[str]:
    try:
        start_idx = response.find("[")
        end_idx = response.rfind("]")
        if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
            list_str = response[start_idx : end_idx + 1]
            parsed = ast.literal_eval(list_str)
        else:
            parsed = []
        if not isinstance(parsed, list):
            logger.warning("LLM response for constraint candidates was not a list.")
            parsed = []
    except (ValueError, SyntaxError) as exc:
        logger.error(f"Error parsing constraint candidates from LLM response: {exc}")
        parsed = []

    cleaned = [str(candidate) for candidate in parsed]
    if str(initial_constraint) not in cleaned:
        cleaned.insert(0, str(initial_constraint))
    return cleaned[:10]


def _example(value, kind: str, source: str = "fuzz") -> dict:
    return {"value": value, "kind": kind, "source": source}


def _constraint_kind(constraint: str) -> str:
    text = str(constraint or "").strip()
    return "operational" if text.startswith("LOGIC:") else "predicate"


def _assignment_targets_for_probes(suspect_object: dict) -> list[str]:
    out: list[str] = []
    for name in suspect_object.get("variable_names", []) or []:
        text = str(name).strip()
        if text and text not in out:
            out.append(text)
    ctx = suspect_object.get("context_variables", {})
    if isinstance(ctx, dict):
        for name in ctx.keys():
            text = str(name).strip()
            if text and text not in out:
                out.append(text)
    return out


def _coerce_probe_scalar(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return str(int(value))
    text = str(value).strip()
    if not text:
        return None
    if text == "NULL":
        return text
    if re.fullmatch(r"-?\d+", text) or re.fullmatch(r"0x[0-9a-fA-F]+", text):
        return text
    addr_match = re.search(r"(0x[0-9a-fA-F]+)", text)
    if addr_match:
        return addr_match.group(1)
    int_match = re.search(r"=\s*(-?\d+)\b", text)
    if int_match:
        return int_match.group(1)
    return None


def _dedupe_probe_values(values: list, limit: int) -> list:
    out: list = []
    seen: set[str] = set()
    for value in values:
        if value is None:
            continue
        key = repr(value)
        if key in seen:
            continue
        seen.add(key)
        out.append(value)
        if len(out) >= limit:
            break
    return out


def _generate_counterexample_probes(suspect_object: dict, fuzz_result: dict, limit: int = 20) -> list:
    probes: list = []
    var_type = str(suspect_object.get("debugger_reported_type") or suspect_object.get("llm_inferred_type") or "").lower()
    seed_values = list(demonic_value_map(suspect_object).values())
    seed_values.extend(fuzz_result.get("demonic_values", [])[:5])
    assignment_targets = set(_assignment_targets_for_probes(suspect_object))

    if "*" in var_type or any("0x" in str(v) for v in seed_values):
        probes.extend(["NULL"])
        for value in seed_values[:4]:
            text = str(value)
            if text.startswith("0x"):
                try:
                    addr = int(text, 16)
                    probes.extend([hex(addr - 1), hex(addr), hex(addr + 1), hex(addr + 4096)])
                except ValueError:
                    pass
    else:
        probes.extend([-1, 0, 1, 2, 7, 8, 15, 16, 31, 32, 255, 256, 1024, 2147483647, 4294967295])

    trace_pairs = fuzz_result.get("trace_pairs", []) or []
    for pair in trace_pairs[:5]:
        changed = pair.get("path_delta", {}).get("changed_expressions", {})
        relational_probe: dict[str, str] = {}
        for expr, delta in changed.items():
            before_value = _coerce_probe_scalar(delta.get("before"))
            after_value = _coerce_probe_scalar(delta.get("after"))
            probes.append(before_value)
            probes.append(after_value)
            if expr in assignment_targets and before_value is not None:
                relational_probe[expr] = before_value
        if relational_probe:
            probes.append(relational_probe)

    relation_targets = _extract_relation_tokens(suspect_object, fuzz_result)
    offsets = [name for name in relation_targets if "offset" in name.lower()]
    lengths = [name for name in relation_targets if any(tok in name.lower() for tok in ("len", "size", "count"))]
    for offset in offsets[:2]:
        if offset not in assignment_targets:
            continue
        probes.extend([{offset: "0"}, {offset: "1"}, {offset: "-1"}])
        for length in lengths[:2]:
            if length not in assignment_targets:
                continue
            probes.extend(
                [
                    {offset: "0", length: "0"},
                    {offset: "1", length: "1"},
                    {offset: "1", length: "0"},
                    {offset: "2", length: "1"},
                ]
            )

    pointers = [name for name in relation_targets if any(tok in name.lower() for tok in ("ptr", "buf", "cursor"))]
    bases = [name for name in relation_targets if "base" in name.lower()]
    ends = [name for name in relation_targets if "end" in name.lower()]
    for ptr in pointers[:2]:
        if ptr not in assignment_targets:
            continue
        probes.append({ptr: "NULL"})
        for base in bases[:1]:
            if base in assignment_targets:
                probes.append({ptr: base})
        for end in ends[:1]:
            if end in assignment_targets:
                probes.append({ptr: end})

    return _dedupe_probe_values(probes, limit)


def _looks_like_nonassignable_aggregate(expr: str, inferred_type: str = "") -> bool:
    text = str(expr or "").strip()
    type_text = str(inferred_type or "").strip().lower()
    if not text:
        return False
    if "[" in text or text.startswith("*"):
        return False
    if re.search(r"\[[^\]]+\]$", type_text) or type_text.endswith("[]"):
        return True
    if any(token in type_text for token in ("struct ", "union ", "enum ")):
        return True
    if any(token in text.lower() for token in ("code_size", "look_up", "tree_")):
        return True
    return False


def _parse_logic_intervention(value) -> dict[str, str] | None:
    text = str(value or "").strip()
    if not text.startswith("LOGIC:"):
        return None
    match = re.match(r"^LOGIC:(AT|IF|GUARD)\((.*?)\)(?:\s*THEN\s*(.+))?$", text, re.S)
    if not match:
        return None
    kind, head, action = match.groups()
    parsed = {
        "kind": kind,
        "head": head.strip(),
        "action": (action or "").strip(),
        "raw": text,
    }
    if kind == "AT":
        loc = re.match(r"^(.*):(\d+)$", parsed["head"])
        if loc:
            parsed["file"] = loc.group(1).strip()
            parsed["line"] = loc.group(2).strip()
    return parsed


def _logic_intervention_summary(logic: dict[str, str]) -> str:
    kind = str(logic.get("kind", "")).upper()
    head = str(logic.get("head", "")).strip()
    action = str(logic.get("action", "")).strip()
    if kind == "AT":
        return f"Replay logic action at {head}: {action or '(guard-only)'}"
    if kind == "IF":
        return f"Replay conditional logic for `{head}`: {action or '(guard-only)'}"
    if kind == "GUARD":
        return f"Replay guard logic for `{head}`: {action or '(guard-only)'}"
    return f"Replay logic intervention `{logic.get('raw', '')}`"


def _abstract_logic_constraint(logic: dict[str, str]) -> dict[str, object]:
    kind = str(logic.get("kind", "")).upper()
    action = str(logic.get("action", "")).strip()
    head = str(logic.get("head", "")).strip()
    abstract_text = ""
    normalized_variables: list[str] = []
    if kind == "AT":
        abstract_text = f"Apply state normalization at {head}"
    elif kind == "IF":
        abstract_text = f"Apply conditional repair when `{head}` holds"
    elif kind == "GUARD":
        abstract_text = f"Apply guard `{head}` before the protected operation"
    if action:
        assigns = re.findall(r"([A-Za-z_][A-Za-z0-9_\-\>\[\]\.\*]+)\s*=", action)
        normalized_variables = [item.strip() for item in assigns if item.strip()]
        if normalized_variables:
            abstract_text += f" by normalizing {', '.join(normalized_variables[:3])}"
        elif any(tok in action for tok in ("memset", "bzero", "memcpy", "memmove")):
            abstract_text += " via a memory-state repair"
        elif "?" in action and ":" in action:
            abstract_text += " via a clamp-like conditional assignment"
    return {
        "kind": "operational",
        "logic_kind": kind.lower(),
        "text": abstract_text.strip() or f"Replay `{logic.get('raw', '')}`",
        "normalized_variables": normalized_variables[:6],
        "raw": logic.get("raw", ""),
    }


def _merge_operational_abstractions(base: dict[str, object], inferred: dict[str, object]) -> dict[str, object]:
    merged = dict(base or {})
    for key in (
        "text",
        "normalized_variables",
        "guard_condition",
        "effect_summary",
        "generalized_predicate",
        "repair_stage",
        "overfit_risk",
    ):
        value = inferred.get(key)
        if isinstance(value, list):
            if value:
                merged[key] = value
        elif str(value or "").strip():
            merged[key] = value
    merged["source"] = "llm_generalized" if inferred else merged.get("source", "heuristic")
    return merged


def _generalize_operational_constraint_with_llm(
    llm_agent,
    suspect_object: dict,
    fuzz_result: dict,
    constraint: str,
    angelic_values: list,
    demonic_values: list,
    function_body: str,
    logger,
) -> dict[str, object]:
    logic = _parse_logic_intervention(constraint)
    heuristic = _abstract_logic_constraint(logic) if logic else {
        "kind": "operational",
        "text": "Operational state repair inferred from debugger intervention.",
        "normalized_variables": [],
        "guard_condition": "",
        "effect_summary": "",
        "generalized_predicate": "",
        "repair_stage": "unknown",
        "overfit_risk": "medium",
        "source": "heuristic",
    }
    if llm_agent is None:
        return heuristic

    bug_type_profile = suspect_object.get("bug_type_profile") or infer_bug_type_profile(
        suspect_object.get("profile", {}),
        suspect_object.get("reproduce_result"),
        suspect_object=suspect_object,
        debug_summary=suspect_object.get("debug_summary", ""),
        function_body=function_body,
    )
    prompt = OPERATIONAL_CONSTRAINT_GENERALIZATION_PROMPT.format(
        constraint=constraint,
        debug_summary=suspect_object.get("debug_summary", ""),
        angelic_values=angelic_values[:8],
        demonic_values=demonic_values[:8],
        function_body=function_body,
    )
    typed_evidence = fuzz_result.get("typed_angelic_evidence", {}) if isinstance(fuzz_result, dict) else {}
    if typed_evidence:
        prompt += (
            "\nTyped Angelic Evidence Summary:\n"
            f"- bug_type: {typed_evidence.get('bug_type')}\n"
            f"- angelic_type: {typed_evidence.get('angelic_type')}\n"
            f"- generalized_spec: {typed_evidence.get('generalized_spec', {})}\n"
            f"- repair_locations: {typed_evidence.get('repair_locations', [])}\n"
        )
    prompt += build_stage_prompt_overlay("constraint", bug_type_profile)
    try:
        parsed = _parse_python_literal(llm_agent.query(prompt, logger=logger))
    except Exception as exc:
        logger.warning("Operational constraint generalization LLM failed for `%s`: %s", constraint, exc)
        parsed = None
    if not isinstance(parsed, dict):
        return heuristic

    normalized_variables = parsed.get("normalized_variables", [])
    if not isinstance(normalized_variables, list):
        normalized_variables = []
    inferred = {
        "text": str(parsed.get("text", "")).strip(),
        "normalized_variables": [str(v).strip() for v in normalized_variables if str(v).strip()][:8],
        "guard_condition": str(parsed.get("guard_condition", "")).strip(),
        "effect_summary": str(parsed.get("effect_summary", "")).strip(),
        "generalized_predicate": str(parsed.get("generalized_predicate", "")).strip(),
        "repair_stage": str(parsed.get("repair_stage", "")).strip(),
        "overfit_risk": str(parsed.get("overfit_risk", "")).strip(),
    }
    return _merge_operational_abstractions(heuristic, inferred)


def _apply_logic_intervention(
    logic: dict[str, str],
    default_file: str,
    default_line: int,
) -> tuple[bool, str]:
    harness = _make_constraint_harness({"file": default_file, "line": default_line})
    target_file = logic.get("file", default_file)
    target_line = int(logic.get("line", default_line) or default_line)
    harness.prepare(target_file, target_line)
    kind = str(logic.get("kind", "")).upper()
    head = str(logic.get("head", "")).strip()
    action = str(logic.get("action", "")).strip()
    if kind == "GUARD":
        condition = head or "1"
        result = harness.apply(
            DebuggerIntervention(
                kind="functional_guard",
                payload={
                    "file": target_file,
                    "line": target_line,
                    "condition": condition,
                    "return_value": action or "0",
                },
            )
        )
        return result.success, result.message
    if not action:
        return True, "guard_only_logic_intervention"
    result = harness.apply(DebuggerIntervention(kind="assign_expression", payload={"expression": action}))
    return result.success, result.message if not result.success else "ok"


def _run_operational_constraint_check(
    constraint: str,
    suspect_object: dict,
    logger,
) -> dict[str, object]:
    file = suspect_object["file"]
    line = suspect_object["line"]
    logic = _parse_logic_intervention(constraint)
    abstract_constraint = _abstract_logic_constraint(logic or {"raw": constraint})
    result = {
        "constraint": constraint,
        "constraint_kind": "operational",
        "constraint_status": "weakly_supported",
        "status": "weakly_supported",
        "precheck_status": "pending",
        "reason": "",
        "support_stats": {
            "operational_examples_seen": 0,
            "operational_apply_failures": 0,
        },
        "mechanism_hint": _fallback_mechanism_from_values([constraint]),
        "proxy_like": False,
        "execution_check": {},
        "challenge_result": {},
        "top_angelic_examples": [constraint],
        "non_scalar_angelic_examples": [constraint],
        "abstract_constraint": abstract_constraint,
    }
    if logic is None:
        result["constraint_status"] = "rejected"
        result["status"] = "rejected"
        result["precheck_status"] = "rejected"
        result["reason"] = "Malformed LOGIC constraint; could not parse operational intervention."
        return result

    try:
        applied, apply_msg = _apply_logic_intervention(logic, file, line)
    except Exception as exc:
        applied, apply_msg = False, str(exc)
    if not applied:
        result["constraint_status"] = "rejected"
        result["status"] = "rejected"
        result["precheck_status"] = "rejected"
        result["support_stats"]["operational_apply_failures"] = 1
        result["reason"] = f"Operational intervention could not be applied: {apply_msg}"
        result["execution_check"] = {
            "attempted": False,
            "classification": "apply_failed",
            "reason": apply_msg,
        }
        return result

    result["support_stats"]["operational_examples_seen"] = 1
    try:
        dbg_output, target_output = debugger_continue()
        outcome = _challenge_outcome_from_continue(dbg_output, target_output)
        reason = str((dbg_output or {}).get("reason", "unknown"))
    except Exception as exc:
        outcome = "eval_unavailable"
        reason = f"continue_failed:{exc}"
        target_output = ""
    execution_check = {
        "attempted": True,
        "classification": "safer_execution" if outcome == "angelic" else "same_or_other_crash" if outcome == "demonic" else "unclear_execution",
        "reason": f"Operational replay outcome={outcome} ({reason})",
        "debugger_reason": reason,
    }
    result["execution_check"] = execution_check
    result["challenge_result"] = {
        "status": "supported" if outcome == "angelic" else "falsified" if outcome == "demonic" else "inconclusive",
        "supporting_interventions": [{"intervention": logic, "source": "operational_constraint"}] if outcome == "angelic" else [],
        "counterexample_interventions": [{"intervention": logic, "source": "operational_constraint"}] if outcome == "demonic" else [],
        "constraint_eval_records": [{"intervention": {"kind": "logic", "payload": logic}, "outcome": outcome}],
        "patchability_score": 0.82 if outcome == "angelic" else 0.1 if outcome == "demonic" else 0.45,
        "overall_score": 0.86 if outcome == "angelic" else 0.0 if outcome == "demonic" else 0.42,
        "recommended_next_actor": "patch" if outcome == "angelic" else "debug",
        "abstract_constraint": abstract_constraint,
    }
    if outcome == "angelic":
        result["constraint_status"] = "supported_and_executable"
        result["status"] = "supported_and_executable"
        result["precheck_status"] = "passed"
        result["reason"] = f"Operational intervention replay prevented the failure. {_logic_intervention_summary(logic)}"
        result["overall_score"] = 0.86
    elif outcome == "demonic":
        result["constraint_status"] = "rejected"
        result["status"] = "rejected"
        result["precheck_status"] = "rejected"
        result["reason"] = f"Operational intervention replay still crashed. {_logic_intervention_summary(logic)}"
        result["overall_score"] = 0.0
    else:
        result["constraint_status"] = "weakly_supported"
        result["status"] = "weakly_supported"
        result["precheck_status"] = "passed_limited"
        result["reason"] = f"Operational intervention replay was inconclusive. {_logic_intervention_summary(logic)}"
        result["overall_score"] = 0.42
    return _finalize_constraint_result(result)


def _challenge_outcome_from_continue(debug_output: dict | None, target_output: str) -> str:
    reason = str((debug_output or {}).get("reason", "")).lower()
    note = str((debug_output or {}).get("note", "")).lower()
    text = f"{reason} {note} {target_output}".lower()
    if "sanitizer" in text or "signal" in text or "crash" in text:
        return "demonic"
    if reason in {"exited-normally", "breakpoint-hit"} and "error" not in text:
        return "angelic"
    if reason:
        return "unchanged"
    return "eval_unavailable"


def _precheck_score_from_status(info: dict[str, object]) -> float:
    status = str(info.get("precheck_status", "")).lower()
    if status == "rejected":
        return 0.0
    if status == "passed_limited":
        return 0.4
    if status == "passed":
        return 0.65 if bool(info.get("proxy_like")) else 0.75
    return 0.2


def _score_challenge_result(result: dict[str, object]) -> dict[str, float]:
    supports = len(result.get("supporting_interventions", []) or [])
    counters = len(result.get("counterexample_interventions", []) or [])
    new_angelic = len(result.get("new_angelic_values", []) or [])
    new_demonic = len(result.get("new_demonic_values", []) or [])
    state_deltas = len(result.get("state_delta_records", []) or [])
    proxy_like = bool(result.get("proxy_like"))
    eval_records = result.get("constraint_eval_records", []) or []
    support_records = result.get("supporting_interventions", []) or []
    support_sources = {
        str((record.get("intervention") or {}).get("source", ""))
        for record in support_records
        if isinstance(record, dict)
    }
    support_kinds = {
        str((record.get("intervention") or {}).get("kind", ""))
        for record in support_records
        if isinstance(record, dict)
    }
    logic_only_support = bool(support_kinds) and support_kinds == {"logic"}
    eval_unavailable = sum(
        1
        for record in eval_records
        if str(record.get("outcome", "")) in {"eval_unavailable", "apply_failed"}
    )
    support_score = min(1.0, 0.2 * supports + 0.1 * new_angelic)
    falsification_score = min(1.0, 0.35 * counters + 0.1 * new_demonic)
    explanatory_score = min(
        1.0,
        0.15 * supports
        + 0.1 * state_deltas
        + (0.1 if support_sources & {"bounds_family", "count_capacity_family", "pointer_range_family"} else 0.0),
    )
    patchability_score = 0.85 - 0.35 * falsification_score
    if proxy_like:
        patchability_score -= 0.18
    if logic_only_support:
        patchability_score -= 0.12
    if eval_unavailable > max(0, supports):
        patchability_score -= 0.10
    patchability_score = max(0.0, min(1.0, patchability_score))
    overall_score = max(
        0.0,
        min(1.0, 0.45 * support_score + 0.25 * explanatory_score + 0.15 * patchability_score - 0.55 * falsification_score),
    )
    return {
        "support_score": support_score,
        "falsification_score": falsification_score,
        "explanatory_score": explanatory_score,
        "patchability_score": patchability_score,
        "overall_score": overall_score,
    }


def _finalize_constraint_result(info: dict[str, object]) -> dict[str, object]:
    precheck_status = str(info.get("precheck_status", "pending") or "pending")
    challenge_result = dict(info.get("challenge_result", {}) or {})
    challenge_status = str(challenge_result.get("status", "pending") or "pending").lower()

    info["precheck_score"] = _precheck_score_from_status(info)
    info["challenge_status"] = challenge_status or "pending"
    info["challenge_score"] = float(challenge_result.get("overall_score", 0.0) or 0.0)

    if precheck_status == "rejected":
        info["constraint_status"] = "rejected"
        info["status"] = "rejected"
        info["overall_score"] = 0.0
        return info

    if challenge_status == "falsified":
        info["constraint_status"] = "rejected"
        info["status"] = "rejected"
        info["reason"] = (
            f"Constraint falsified by challenger. {info.get('reason', '')} "
            f"Counterexamples={len(challenge_result.get('counterexample_interventions', []))}."
        ).strip()
        return info

    if challenge_status == "supported":
        supported_status = "supported_but_proxy_like" if info.get("proxy_like") else "supported_and_executable"
        info["constraint_status"] = supported_status
        info["status"] = supported_status
        info["reason"] = f"Constraint supported by challenger. {info.get('reason', '')}".strip()
        return info

    if challenge_status == "needs_source_check":
        info["constraint_status"] = "weakly_supported"
        info["status"] = "needs_source_check"
        info["reason"] = (
            f"{info.get('reason', '')} Challenger could not conclude due to debugger/source limitations."
        ).strip()
        return info

    if challenge_status == "inconclusive":
        info["constraint_status"] = "weakly_supported"
        info["status"] = "challenged_inconclusive"
        info["reason"] = f"{info.get('reason', '')} Challenger remained inconclusive.".strip()
        return info

    return info


def _build_challenge_interventions(
    constraint: str,
    suspect_object: dict,
    angelic_list: list,
    demonic_list: list,
    counterexample_probes: list,
    budget: int,
) -> list[dict[str, object]]:
    del constraint
    out: list[dict[str, object]] = []
    seen: set[str] = set()

    def add(kind: str, payload, source: str) -> None:
        key = f"{kind}:{repr(payload)}"
        if key in seen or len(out) >= budget:
            return
        seen.add(key)
        out.append({"kind": kind, "payload": payload, "source": source})

    for value in angelic_list:
        if len(out) >= budget:
            break
        logic = _parse_logic_intervention(value)
        if logic:
            add("logic", logic, "angelic_logic")
        else:
            add("assignment", value, "angelic")

    for value in counterexample_probes:
        if len(out) >= budget:
            break
        logic = _parse_logic_intervention(value)
        if logic:
            add("logic", logic, "probe_logic")
        else:
            add("assignment", value, "active_probe")

    relation_targets = _extract_relation_tokens(suspect_object, {"minimal_deltas": [], "trace_pairs": []})
    offsets = [name for name in relation_targets if "offset" in name.lower()]
    sizes = [name for name in relation_targets if any(tok in name.lower() for tok in ("len", "size", "count", "capacity"))]
    for offset in offsets[:1]:
        add("assignment", {offset: "0"}, "bounds_family")
        add("assignment", {offset: "1"}, "bounds_family")
        add("assignment", {offset: "-1"}, "bounds_family")
        for size in sizes[:1]:
            add("assignment", {offset: "0", size: "0"}, "bounds_family")
            add("assignment", {offset: "1", size: "1"}, "bounds_family")
            add("assignment", {offset: "2", size: "1"}, "bounds_family")
            add("assignment", {offset: "0", size: "1"}, "bounds_family")
            add("assignment", {offset: "1", size: "0"}, "bounds_family")

    counts = [name for name in relation_targets if "count" in name.lower()]
    capacities = [name for name in relation_targets if "capacity" in name.lower()]
    elem_sizes = [name for name in relation_targets if "elem" in name.lower() or "stride" in name.lower()]
    lengths = [name for name in relation_targets if any(tok in name.lower() for tok in ("len", "size"))]
    for count in counts[:1]:
        add("assignment", {count: "0"}, "count_capacity_family")
        add("assignment", {count: "1"}, "count_capacity_family")
        for capacity in capacities[:1]:
            add("assignment", {count: capacity}, "count_capacity_family")
            add("assignment", {count: f"({capacity}) + 1"}, "count_capacity_family")
        for elem_size in elem_sizes[:1]:
            for length in lengths[:1]:
                add("assignment", {count: "1", elem_size: length}, "count_capacity_family")

    pointers = [name for name in relation_targets if any(tok in name.lower() for tok in ("ptr", "cursor", "buf"))]
    bases = [name for name in relation_targets if "base" in name.lower() or "start" in name.lower()]
    ends = [name for name in relation_targets if "end" in name.lower()]
    for ptr in pointers[:1]:
        for base in bases[:1]:
            add("assignment", {ptr: base}, "pointer_range_family")
            add("assignment", {ptr: f"({base}) - 1"}, "pointer_range_family")
        for end in ends[:1]:
            add("assignment", {ptr: end}, "pointer_range_family")
            add("assignment", {ptr: f"({end}) - 1"}, "pointer_range_family")

    for value in demonic_list[:2]:
        if len(out) >= budget:
            break
        logic = _parse_logic_intervention(value)
        if logic:
            add("logic", logic, "demonic_logic")
        else:
            add("assignment", value, "demonic")

    for value in angelic_list[:2]:
        logic = _parse_logic_intervention(value)
        if not logic or len(out) >= budget:
            continue
        weakened = dict(logic)
        action = str(weakened.get("action", ""))
        if weakened.get("kind") == "AT" and action:
            weakened["action"] = action.replace(" = 0", " = 1", 1)
            add("logic", weakened, "logic_replay_family")
        elif weakened.get("kind") in {"IF", "GUARD"}:
            add("logic", weakened, "logic_replay_family")
    return out[:budget]


def _run_constraint_challenger(
    constraint: str,
    precheck_info: dict[str, object],
    suspect_object: dict,
    angelic_list: list,
    demonic_list: list,
    counterexample_probes: list,
    logger,
    intervention_budget: int | None = None,
) -> dict[str, object]:
    file = suspect_object["file"]
    line = suspect_object["line"]
    harness = _make_constraint_harness(suspect_object)
    assignment_targets = _available_assignment_targets(suspect_object)
    primary_var = suspect_object["variable_names"][0]
    var_type = suspect_object.get("llm_inferred_type") or "unknown"
    primary_is_nonassignable_aggregate = _looks_like_nonassignable_aggregate(primary_var, var_type)
    budget = int(intervention_budget or suspect_object.get("constraint_challenger_budget", 8) or 8)

    def _is_truthy(eval_result: str) -> bool:
        text = (eval_result or "").strip().lower()
        return text in {"1", "true"} or text.endswith(" = 1") or text.endswith("=1")

    def _looks_like_eval_unavailable(eval_result: str) -> bool:
        text = (eval_result or "").strip().lower()
        return any(
            marker in text
            for marker in (
                "lldb process has exited",
                "debuggerprocessitederror",
                "lldb_eval_process_exited",
                "lldb_eval_timeout",
                "lldb_eval_no_frame",
                "lldb_eval_mi_unstable",
            )
        )

    def _eval_with_retry(expr: str, target_file: str, target_line: int) -> tuple[str | None, str | None]:
        try:
            eval_result = harness.session.print_value(f"(int)({expr})")
        except Exception as exc:
            return None, f"eval_exception: {exc}"
        if _looks_like_eval_unavailable(eval_result):
            try:
                harness.prepare(target_file, target_line)
                eval_result = harness.session.print_value(f"(int)({expr})")
            except Exception as exc:
                return None, f"retry_exception: {exc}"
            if _looks_like_eval_unavailable(eval_result):
                return None, f"eval_unavailable_after_retry: {eval_result}"
        return eval_result, None

    def _extract_assignment_map(value) -> dict[str, str] | None:
        if value is None:
            return None
        if isinstance(value, dict):
            out: dict[str, str] = {}
            for k, v in value.items():
                lhs = str(k).strip()
                if not lhs:
                    continue
                if lhs == primary_var and primary_is_nonassignable_aggregate and "[" not in lhs and not lhs.startswith("*"):
                    continue
                out[lhs] = str(v).strip()
            return out or None
        if isinstance(value, (int, float)):
            if primary_is_nonassignable_aggregate:
                return None
            return {primary_var: str(int(value))}
        text = str(value).strip()
        if not text or text.startswith("LOGIC:"):
            return None
        assignments: dict[str, str] = {}
        for chunk in [chunk.strip() for chunk in text.split(";") if chunk.strip()]:
            match = re.match(r"^([A-Za-z_][A-Za-z0-9_\-\>\[\]\.\*]*)\s*=\s*(.+)$", chunk)
            if not match:
                continue
            lhs, rhs = match.groups()
            lhs = lhs.strip()
            rhs = rhs.strip()
            if lhs == primary_var and primary_is_nonassignable_aggregate and "[" not in lhs and not lhs.startswith("*"):
                continue
            if lhs in assignment_targets or lhs == primary_var:
                assignments[lhs] = rhs
        if assignments:
            return assignments
        if primary_is_nonassignable_aggregate:
            return None
        if re.match(r"^-?\d+$", text) or re.match(r"^0x[0-9a-fA-F]+$", text):
            return {primary_var: text}
        return None

    def _format_assignment_expr(lhs: str, rhs: str) -> str:
        if lhs == primary_var:
            assign_val = rhs
            if "*" in var_type and not assign_val.startswith("(") and "NULL" not in assign_val:
                assign_val = f"({var_type}){rhs}"
            return f"{lhs} = {assign_val}"
        return f"{lhs} = {rhs}"

    def _apply_assignment_map(assignments: dict[str, str]) -> tuple[bool, str]:
        for lhs, rhs in assignments.items():
            result = harness.apply(
                DebuggerIntervention(
                    kind="assign_expression",
                    payload={"expression": _format_assignment_expr(lhs, rhs)},
                )
            )
            success, msg = result.success, result.message
            if not success:
                return False, f"{lhs}: {msg}"
        return True, "ok"

    result: dict[str, object] = {
        "constraint": constraint,
        "status": "inconclusive",
        "supporting_interventions": [],
        "counterexample_interventions": [],
        "new_angelic_values": [],
        "new_demonic_values": [],
        "constraint_eval_records": [],
        "state_delta_records": [],
        "notes": [],
        "recommended_next_actor": "patch",
        "precheck_status": precheck_info.get("precheck_status", "unknown"),
        "proxy_like": bool(precheck_info.get("proxy_like")),
    }

    for intervention in _build_challenge_interventions(
        constraint, suspect_object, angelic_list, demonic_list, counterexample_probes, budget
    ):
        kind = str(intervention.get("kind", "assignment"))
        payload = intervention.get("payload")
        harness.prepare(file, line)
        if kind == "logic":
            applied, apply_msg = _apply_logic_intervention(payload or {}, file, line)
            if payload:
                result["notes"].append(_logic_intervention_summary(payload))
        else:
            assignments = _extract_assignment_map(payload)
            applied, apply_msg = _apply_assignment_map(assignments or {}) if assignments else (False, "No concrete assignment map")
        if not applied:
            result["constraint_eval_records"].append(
                {"intervention": intervention, "outcome": "apply_failed", "error": apply_msg}
            )
            continue

        eval_result, eval_err = _eval_with_retry(constraint, file, line)
        if eval_result is None:
            result["constraint_eval_records"].append(
                {"intervention": intervention, "outcome": "eval_unavailable", "error": eval_err}
            )
            continue

        try:
            debug_output, target_output = harness.session.continue_run()
            outcome = _challenge_outcome_from_continue(debug_output, target_output)
        except Exception as exc:
            debug_output, target_output = {}, ""
            outcome = "eval_unavailable"
            result["notes"].append(f"continue_failed: {exc}")

        record = {
            "intervention": intervention,
            "constraint_eval": eval_result,
            "outcome": outcome,
            "debugger_reason": str((debug_output or {}).get("reason", "")),
        }
        result["constraint_eval_records"].append(record)

        truthy = _is_truthy(eval_result)
        if truthy and outcome == "demonic":
            result["counterexample_interventions"].append(record)
        elif (not truthy) and outcome == "angelic":
            result["counterexample_interventions"].append(record)
        elif truthy and outcome == "angelic":
            result["supporting_interventions"].append(record)
            result["new_angelic_values"].append(payload)
        elif (not truthy) and outcome == "demonic":
            result["supporting_interventions"].append(record)
            result["new_demonic_values"].append(payload)
        else:
            result["state_delta_records"].append(record)

    scores = _score_challenge_result(result)
    result.update(scores)
    if result["counterexample_interventions"]:
        result["status"] = "falsified"
        result["recommended_next_actor"] = "debug"
        result["notes"].append("Found counterexample where constraint prediction mismatched execution outcome.")
    elif result["supporting_interventions"]:
        result["status"] = "supported"
        if float(result.get("patchability_score", 0.0) or 0.0) < 0.45:
            result["recommended_next_actor"] = "constraint"
            result["notes"].append("Constraint is supported, but patchability remains low; prefer upstream reformulation before patching.")
        else:
            result["recommended_next_actor"] = "patch"
        result["notes"].append("Constraint survived adversarial challenge without strong counterexample.")
    elif int(precheck_info.get("support_stats", {}).get("eval_failures", 0)) > 0:
        result["status"] = "needs_source_check"
        result["recommended_next_actor"] = "debug"
    else:
        result["status"] = "inconclusive"
        result["recommended_next_actor"] = "fuzz"
    return result


def _extract_delta_expressions(fuzz_result: dict) -> list[str]:
    expressions: list[str] = []
    for item in fuzz_result.get("minimal_deltas", []) or []:
        path_delta = item.get("path_delta", {}) or {}
        changed = path_delta.get("changed_expressions", {}) or {}
        for expr in changed.keys():
            text = str(expr).strip()
            if text and text not in expressions:
                expressions.append(text)
    return expressions[:12]


def _extract_relation_tokens(suspect_object: dict, fuzz_result: dict) -> list[str]:
    tokens: list[str] = []
    for name in suspect_object.get("variable_names", []) or []:
        text = str(name).strip()
        if text:
            tokens.append(text)
    for name in suspect_object.get("suspect_expressions", []) or []:
        text = str(name).strip()
        if text:
            tokens.append(text)
    for expr in _extract_delta_expressions(fuzz_result):
        text = str(expr).strip()
        if text:
            tokens.append(text)
    out: list[str] = []
    for token in tokens:
        if token not in out:
            out.append(token)
    return out[:16]


def _deterministic_constraint_candidates(suspect_object: dict, fuzz_result: dict, initial_constraint: str) -> list[str]:
    return [initial_constraint] if initial_constraint else []


def _build_history(state: BugHypothesisState) -> str:
    lines: list[str] = []
    rejected = [candidate for candidate in state.current_constraint_candidates() if candidate.status == "rejected"]
    for candidate in rejected[-8:]:
        lines.append(f"- `{candidate.constraint}`: {candidate.reason}")

    last_feedback = state.last_verification_feedback()
    if last_feedback and last_feedback.status != "pass":
        lines.append(f"- verify feedback: {last_feedback.message}")

    if not lines:
        return ""
    return (
        "Previous attempts that did not work:\n"
        + "\n".join(lines)
        + "\nPlease avoid repeating the same invalid logic."
    )


def _available_assignment_targets(suspect_object: dict) -> list[str]:
    out: list[str] = []
    primary_var = str((suspect_object.get("variable_names") or [""])[0]).strip()
    primary_type = str(suspect_object.get("llm_inferred_type") or suspect_object.get("debugger_reported_type") or "")
    for name in suspect_object.get("variable_names", []) or []:
        text = str(name).strip()
        if text == primary_var and _looks_like_nonassignable_aggregate(text, primary_type):
            continue
        if text and text not in out:
            out.append(text)
    ctx = suspect_object.get("context_variables", {})
    if isinstance(ctx, dict):
        for name in ctx.keys():
            text = str(name).strip()
            if text and text not in out:
                out.append(text)
    return out


def _fallback_mechanism_from_values(values: list) -> str:
    text = " ".join(str(value).lower() for value in values if value is not None)
    if any(token in text for token in ("memset", "zero", "[0]", "= 0", "init")):
        return "memory_init"
    if any(token in text for token in ("free", "release", "ownership", "owned", "null")):
        return "ownership_reset"
    if any(token in text for token in ("offset", "len", "length", "size", "count", "bound", "index")):
        return "bounds_normalization"
    if any(token in text for token in ("guard", "check", "if(", "if ")) or "&&" in text or "||" in text:
        return "guard_condition"
    if any(token in text for token in ("return", "skip", "branch", "goto")):
        return "branch_suppression"
    return "guard_condition"


def _fallback_repair_intent(suspect_object: dict, mechanism_hint: str) -> str:
    summary = str(suspect_object.get("debug_summary", "")).strip()
    if mechanism_hint == "memory_init":
        return "Ensure data that may be read on this path is initialized before use."
    if mechanism_hint == "ownership_reset":
        return "Ensure resource ownership or lifetime state prevents invalid reuse or double release."
    if mechanism_hint == "bounds_normalization":
        return "Restore the size, offset, or count invariant required before the unsafe access."
    if mechanism_hint == "branch_suppression":
        return "Prevent execution from entering the unsafe branch unless the required state invariant holds."
    if summary:
        first_sentence = summary.split(".")[0].strip()
        if first_sentence:
            return first_sentence + "."
    return "Restore the intended safety condition before the crash site."


def _summarize_demonic_state(suspect_object: dict, fuzz_result: dict) -> str:
    summary = str(suspect_object.get("debug_summary", "")).strip()
    if summary:
        return summary.split(".")[0].strip() + "."
    demonic = fuzz_result.get("demonic_values", [])[:2]
    if demonic:
        return f"Unsafe execution is associated with demonic values: {demonic}."
    return "Unsafe execution reaches the current crash state."


def _constraint_mechanism_mismatch(constraint: str, mechanism_hint: str) -> bool:
    text = str(constraint or "").lower()
    relational = any(token in text for token in ("<", ">", "<=", ">=", " !=", "==", "&&", "||"))
    if mechanism_hint == "memory_init":
        return relational and not any(token in text for token in ("init", "zero", "null"))
    if mechanism_hint == "ownership_reset":
        return not any(token in text for token in ("null", "free", "life", "owner", "release"))
    if mechanism_hint == "branch_suppression":
        return relational and "return" not in text
    return False


def _parse_python_literal(response: str):
    text = str(response or "").strip()
    if not text:
        return None
    fenced = re.search(r"```(?:python|json)?\s*(.*?)```", text, re.S)
    if fenced:
        text = fenced.group(1).strip()
    start = min((idx for idx in (text.find("{"), text.find("[")) if idx != -1), default=-1)
    end_brace = max(text.rfind("}"), text.rfind("]"))
    if start != -1 and end_brace != -1 and end_brace > start:
        text = text[start : end_brace + 1]
    try:
        return ast.literal_eval(text)
    except Exception:
        return None


def _normalize_strategy_hint(item: dict) -> dict | None:
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
    strategy = str(item.get("strategy", "")).strip()
    location_type = str(item.get("location_type", "")).strip()
    semantic_risk = str(item.get("semantic_risk", "")).strip()
    rationale = str(item.get("rationale", "")).strip()
    if strategy not in allowed_strategy or location_type not in allowed_location or semantic_risk not in allowed_risk:
        return None
    return {
        "strategy": strategy,
        "location_type": location_type,
        "semantic_risk": semantic_risk,
        "rationale": rationale or "LLM-recommended strategy.",
        "requires_regression_check": semantic_risk == "high",
    }


def _extract_evidence_variables(angelic_values: list) -> list[str]:
    out: list[str] = []
    for value in angelic_values:
        text = str(value or "")
        for lhs, _rhs in re.findall(r"([A-Za-z_][A-Za-z0-9_\-\>\[\]\.\*]+)\s*=\s*([^;]+)", text):
            lhs = lhs.strip()
            if lhs and lhs not in out:
                out.append(lhs)
    return out[:8]


def _sanitize_angelic_effect(angelic_values: list, mechanism_hint: str, debug_summary: str) -> str:
    joined = " ".join(str(v) for v in angelic_values if v is not None).lower()
    summary = str(debug_summary or "").strip()
    if mechanism_hint == "memory_init":
        if any(token in joined for token in ("memset", "zero", "clear", "init")):
            return "Increasing initialization or clearing coverage prevented the failing read/use of previously uninitialized state."
        return "A state-initialization intervention prevented the failing read/use."
    if mechanism_hint == "bounds_normalization":
        return "Adjusting a bound- or size-dependent state prevented the invalid access."
    if mechanism_hint == "ownership_reset":
        return "Resetting ownership or lifetime-related state prevented invalid reuse."
    if mechanism_hint == "branch_suppression":
        return "Preventing entry into the unsafe branch avoided the failure."
    if summary:
        return summary.split(".")[0].strip() + "."
    return "An angelic intervention changed program state in a way that prevented the failure."


def _build_angelic_consumption_contract(
    constraint: str,
    mechanism_hint: str,
    proxy_like: bool,
    angelic_values: list,
    debug_summary: str,
) -> dict[str, object]:
    evidence_variables = _extract_evidence_variables(angelic_values)
    patch_family_map = {
        "memory_init": "initialization_coverage_repair",
        "bounds_normalization": "bounds_or_extent_repair",
        "ownership_reset": "ownership_or_lifetime_repair",
        "branch_suppression": "guard_or_rejection_repair",
        "guard_condition": "state_invariant_repair",
    }
    patch_family = patch_family_map.get(mechanism_hint, "state_invariant_repair")
    if proxy_like:
        visibility = "hide"
    elif mechanism_hint in {"memory_init", "bounds_normalization", "ownership_reset", "branch_suppression"}:
        visibility = "sanitize"
    else:
        visibility = "show"
    forbidden_literalizations: list[str] = []
    if visibility != "show":
        for value in angelic_values:
            text = str(value or "").strip()
            if not text:
                continue
            if text not in forbidden_literalizations:
                forbidden_literalizations.append(text)
            for lhs, rhs in re.findall(r"([A-Za-z_][A-Za-z0-9_\-\>\[\]\.\*]+)\s*=\s*([^;]+)", text):
                literal = f"{lhs.strip()} = {rhs.strip()}"
                clamp = f"clamp {lhs.strip()} to {rhs.strip()}"
                if literal not in forbidden_literalizations:
                    forbidden_literalizations.append(literal)
                if clamp not in forbidden_literalizations:
                    forbidden_literalizations.append(clamp)
    return {
        "angelic_consumption_mode": "abstract_only" if visibility != "show" else "raw_allowed",
        "raw_angelic_visibility": visibility,
        "proxy_like": proxy_like,
        "patch_family": patch_family,
        "evidence_variables": evidence_variables,
        "forbidden_literalizations": forbidden_literalizations[:12],
        "observed_effect": _sanitize_angelic_effect(angelic_values, mechanism_hint, debug_summary),
        "patch_guidance": (
            f"Repair {patch_family.replace('_', ' ')} rather than forcing the observed angelic values."
            if visibility != "show"
            else "The angelic value itself appears close to the intended invariant."
        ),
        "constraint_text": constraint,
    }


def _infer_preferred_repair_stage(mechanism_hint: str, proxy_like: bool, suspect_object: dict) -> str:
    if mechanism_hint == "memory_init":
        return "initialization"
    if mechanism_hint == "ownership_reset":
        return "ownership_lifetime"
    if mechanism_hint == "bounds_normalization":
        return "allocation_extent" if "alloc" in str(suspect_object.get("debug_summary", "")).lower() else "state_update"
    if mechanism_hint in {"branch_suppression", "guard_condition"}:
        return "state_update" if proxy_like else "input_validation"
    return str(suspect_object.get("preferred_repair_stage", "state_update"))


def _infer_forbidden_repair_stages_from_semantics(preferred_stage: str, proxy_like: bool) -> list[str]:
    forbidden: list[str] = []
    if proxy_like and "crash_guard" not in forbidden:
        forbidden.append("crash_guard")
    if preferred_stage != "input_validation" and preferred_stage not in {"", "crash_guard"}:
        if "crash_guard" not in forbidden:
            forbidden.append("crash_guard")
    return forbidden


def _infer_constraint_semantics_with_llm(
    llm_agent,
    suspect_object: dict,
    fuzz_result: dict,
    constraint: str,
    angelic_values: list,
    demonic_values: list,
    function_body: str,
    logger,
) -> dict[str, object]:
    bug_type_profile = suspect_object.get("bug_type_profile") or infer_bug_type_profile(
        suspect_object.get("profile", {}),
        suspect_object.get("reproduce_result"),
        suspect_object=suspect_object,
        debug_summary=suspect_object.get("debug_summary", ""),
        function_body=function_body,
    )
    if llm_agent is None:
        mechanism_hint = _fallback_mechanism_from_values(angelic_values)
        return {
            "mechanism_hint": mechanism_hint,
            "repair_intent": _fallback_repair_intent(suspect_object, mechanism_hint),
            "demonic_summary": _summarize_demonic_state(suspect_object, fuzz_result),
            "proxy_like": _constraint_mechanism_mismatch(constraint, mechanism_hint),
            "reason": "Fallback heuristic semantics.",
            "strategy_hints": [],
            "angelic_consumption_contract": _build_angelic_consumption_contract(
                constraint,
                mechanism_hint,
                _constraint_mechanism_mismatch(constraint, mechanism_hint),
                angelic_values,
                suspect_object.get("debug_summary", ""),
            ),
        }

    prompt = CONSTRAINT_SEMANTICS_PROMPT.format(
        constraint=constraint,
        debug_summary=suspect_object.get("debug_summary", ""),
        angelic_values=angelic_values[:8],
        demonic_values=demonic_values[:8],
        function_body=function_body,
    )
    typed_evidence = fuzz_result.get("typed_angelic_evidence", {}) if isinstance(fuzz_result, dict) else {}
    if typed_evidence:
        prompt += (
            "\nTyped Angelic Evidence Summary:\n"
            f"- bug_type: {typed_evidence.get('bug_type')}\n"
            f"- angelic_type: {typed_evidence.get('angelic_type')}\n"
            f"- generalized_spec: {typed_evidence.get('generalized_spec', {})}\n"
            f"- repair_locations: {typed_evidence.get('repair_locations', [])}\n"
            f"- forbidden_patch_patterns: {typed_evidence.get('forbidden_patch_patterns', [])}\n"
        )
    prompt += build_stage_prompt_overlay("constraint", bug_type_profile)
    try:
        parsed = _parse_python_literal(llm_agent.query(prompt, logger=logger))
    except Exception as exc:
        logger.warning("Constraint semantics LLM failed for `%s`: %s", constraint, exc)
        parsed = None

    if not isinstance(parsed, dict):
        mechanism_hint = _fallback_mechanism_from_values(angelic_values)
        return {
            "mechanism_hint": mechanism_hint,
            "repair_intent": _fallback_repair_intent(suspect_object, mechanism_hint),
            "demonic_summary": _summarize_demonic_state(suspect_object, fuzz_result),
            "proxy_like": _constraint_mechanism_mismatch(constraint, mechanism_hint),
            "reason": "Fallback heuristic semantics after unparsable LLM output.",
            "strategy_hints": [],
            "angelic_consumption_contract": _build_angelic_consumption_contract(
                constraint,
                mechanism_hint,
                _constraint_mechanism_mismatch(constraint, mechanism_hint),
                angelic_values,
                suspect_object.get("debug_summary", ""),
            ),
        }

    mechanism_hint = str(parsed.get("mechanism_hint", "")).strip() or _fallback_mechanism_from_values(angelic_values)
    repair_intent = str(parsed.get("repair_intent", "")).strip() or _fallback_repair_intent(suspect_object, mechanism_hint)
    demonic_summary = str(parsed.get("demonic_summary", "")).strip() or _summarize_demonic_state(suspect_object, fuzz_result)
    proxy_like = bool(parsed.get("proxy_like", _constraint_mechanism_mismatch(constraint, mechanism_hint)))
    reason = str(parsed.get("reason", "")).strip()
    strategy_hints_raw = parsed.get("strategy_hints", []) or []
    strategy_hints: list[dict] = []
    if isinstance(strategy_hints_raw, list):
        for item in strategy_hints_raw[:3]:
            if isinstance(item, dict):
                normalized = _normalize_strategy_hint(item)
                if normalized and normalized not in strategy_hints:
                    strategy_hints.append(normalized)
    return {
        "mechanism_hint": mechanism_hint,
        "repair_intent": repair_intent,
        "demonic_summary": demonic_summary,
        "proxy_like": proxy_like,
        "reason": reason,
        "strategy_hints": strategy_hints,
        "angelic_consumption_contract": _build_angelic_consumption_contract(
            constraint,
            mechanism_hint,
            proxy_like,
            angelic_values,
            suspect_object.get("debug_summary", ""),
        ),
    }


def _choose_execution_probe(constraint: str, angelic_values: list, counterexample_probes: list, suspect_object: dict) -> dict[str, str] | None:
    primary_var = str((suspect_object.get("variable_names") or [""])[0]).strip()
    primary_type = str(suspect_object.get("llm_inferred_type") or suspect_object.get("debugger_reported_type") or "")
    primary_is_nonassignable_aggregate = _looks_like_nonassignable_aggregate(primary_var, primary_type)
    candidates = list(angelic_values) + list(counterexample_probes)
    for value in candidates:
        if isinstance(value, dict):
            out: dict[str, str] = {}
            for k, v in value.items():
                lhs = str(k).strip()
                if not lhs:
                    continue
                if lhs == primary_var and primary_is_nonassignable_aggregate and "[" not in lhs and not lhs.startswith("*"):
                    continue
                out[lhs] = str(v).strip()
            if out:
                return out
            continue
        text = str(value).strip()
        if not text or text.startswith("LOGIC:"):
            continue
        if re.fullmatch(r"-?\d+", text) or re.fullmatch(r"0x[0-9a-fA-F]+", text):
            if primary_is_nonassignable_aggregate:
                continue
            return {primary_var: text}
        assignments: dict[str, str] = {}
        chunks = [chunk.strip() for chunk in text.split(";") if chunk.strip()]
        for chunk in chunks:
            match = re.match(r"^([A-Za-z_][A-Za-z0-9_\-\>\[\]\.\*]*)\s*=\s*(.+)$", chunk)
            if match:
                lhs, rhs = match.groups()
                if lhs.strip() == primary_var and primary_is_nonassignable_aggregate and "[" not in lhs and not lhs.startswith("*"):
                    continue
                assignments[lhs.strip()] = rhs.strip()
        if assignments:
            return assignments
    return None


def _run_execution_probe(
    constraint: str,
    assignments: dict[str, str] | None,
    suspect_object: dict,
    apply_assignment_map,
    eval_with_retry,
    logger,
) -> dict[str, object]:
    result = {
        "attempted": False,
        "classification": "not_run",
        "reason": "No concrete satisfying intervention available.",
        "constraint": constraint,
    }
    if not assignments:
        return result
    file = suspect_object["file"]
    line = suspect_object["line"]
    debugger_run_to_line(file, line)
    applied, apply_err = apply_assignment_map(assignments)
    if not applied:
        result["classification"] = "apply_failed"
        result["reason"] = f"Failed to apply execution probe: {apply_err}"
        return result
    eval_result, eval_err = eval_with_retry(constraint, file, line)
    if eval_result is None:
        result["classification"] = "eval_failed"
        result["reason"] = f"Constraint could not be re-evaluated before continue: {eval_err}"
        return result
    if str(eval_result).strip().lower() not in {"1", "true"} and not str(eval_result).strip().endswith((" = 1", "=1")):
        result["classification"] = "not_satisfied"
        result["reason"] = f"Probe assignments did not satisfy constraint (result={eval_result})."
        return result
    result["attempted"] = True
    try:
        dbg_output, target_output = debugger_continue()
        reason = str((dbg_output or {}).get("reason", "unknown"))
        note = str((dbg_output or {}).get("note", ""))
        text = f"{reason} {note} {target_output}".lower()
        result["debugger_reason"] = reason
        result["debugger_note"] = note
        if reason in {"exited-normally", "breakpoint-hit"} and "error" not in text and "sanitizer" not in text:
            result["classification"] = "safer_execution"
            result["reason"] = f"Continuing after satisfying the constraint led to {reason}."
        elif "sanitizer" in text or "signal" in text:
            result["classification"] = "same_or_other_crash"
            result["reason"] = f"Continuing after satisfying the constraint still crashed ({reason})."
        else:
            result["classification"] = "unclear_execution"
            result["reason"] = f"Execution effect after satisfying the constraint was unclear ({reason})."
    except Exception as exc:
        logger.warning("Execution probe failed for `%s`: %s", constraint, exc)
        result["classification"] = "continue_failed"
        result["reason"] = f"Execution probe failed: {exc}"
    return result


@logf(NAME)
def online_verify_constraints(
    constraints: list[str],
    angelic_list: list,
    demonic_list: list,
    suspect_object: dict,
    logger=None,
) -> dict[str, dict[str, object]]:
    """
    Screen constraints using debugger evidence.
    Returns a mapping of constraint -> structured support metadata.
    """
    file = suspect_object["file"]
    line = suspect_object["line"]
    harness = _make_constraint_harness(suspect_object)
    var_name = suspect_object["variable_names"][0]
    var_type = suspect_object.get("llm_inferred_type") or "unknown"

    logger.info(f"Online verifying {len(constraints)} constraints")

    results: dict[str, dict[str, object]] = {}
    assignment_targets = _available_assignment_targets(suspect_object)
    primary_var = suspect_object["variable_names"][0]
    primary_is_nonassignable_aggregate = _looks_like_nonassignable_aggregate(primary_var, var_type)
    angelic_non_scalar = [value for value in angelic_list if isinstance(value, str) and value.strip().startswith("LOGIC:")]
    demonic_non_scalar = [value for value in demonic_list if isinstance(value, str) and value.strip().startswith("LOGIC:")]
    mechanism_hint = _fallback_mechanism_from_values(list(angelic_list) + angelic_assignment_sets(suspect_object))
    counterexample_probes = _generate_counterexample_probes(suspect_object, {"demonic_values": demonic_list})
    challenge_top_k = int(
        suspect_object.get("constraint_challenge_top_k")
        or (suspect_object.get("bug_type_profile") or {}).get("constraint_challenge_top_k", 0)
        or 3
    )
    challenge_budget = int(
        suspect_object.get("constraint_challenger_budget")
        or (suspect_object.get("bug_type_profile") or {}).get("constraint_challenger_budget", 0)
        or 8
    )

    def _is_lldb_expr_compatible(expr: str) -> tuple[bool, str]:
        text = (expr or "").strip()
        if not text:
            return False, "Empty constraint"
        if re.search(r"\b(min|max|GF_ARRAY_LENGTH)\s*\(", text):
            return False, "Uses helper/macro call (min/max/GF_ARRAY_LENGTH) which is not available in LLDB expr"
        if re.search(r"\b[A-Z][A-Z0-9_]{2,}\b", text):
            return False, "Uses macro-like identifier (ALL_CAPS) which is usually not available in LLDB expr"
        calls = re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", text)
        for name in calls:
            if name != "sizeof":
                return False, f"Contains function/macro call `{name}(...)` which is not allowed in LLDB expr"
        return True, "OK"

    def _is_truthy(eval_result: str) -> bool:
        text = (eval_result or "").strip().lower()
        return text in {"1", "true"} or text.endswith(" = 1") or text.endswith("=1")

    def _is_falsy(eval_result: str) -> bool:
        text = (eval_result or "").strip().lower()
        return text in {"0", "false"} or text.endswith(" = 0") or text.endswith("=0")

    def _looks_like_eval_unavailable(eval_result: str) -> bool:
        text = (eval_result or "").strip().lower()
        return any(
            marker in text
            for marker in (
                "lldb process has exited",
                "debuggerprocessitederror",
                "lldb_eval_process_exited",
                "lldb_eval_timeout",
                "lldb_eval_no_frame",
                "lldb_eval_mi_unstable",
            )
        )

    def _eval_with_retry(constraint: str, target_file: str, target_line: int) -> tuple[str | None, str | None]:
        try:
            eval_result = harness.session.print_value(f"(int)({constraint})")
        except Exception as exc:
            return None, f"eval_exception: {exc}"

        if _looks_like_eval_unavailable(eval_result):
            logger.warning(
                f"Constraint eval unavailable for `{constraint}`: {eval_result}. "
                "Retrying once after re-run to breakpoint..."
            )
            try:
                harness.prepare(target_file, target_line)
                eval_result = harness.session.print_value(f"(int)({constraint})")
            except Exception as exc:
                return None, f"retry_exception: {exc}"
            if _looks_like_eval_unavailable(eval_result):
                return None, f"eval_unavailable_after_retry: {eval_result}"
        return eval_result, None

    def _extract_assignment_map(value) -> dict[str, str] | None:
        if value is None:
            return None
        if isinstance(value, dict):
            out: dict[str, str] = {}
            for k, v in value.items():
                lhs = str(k).strip()
                if not lhs:
                    continue
                if lhs == primary_var and primary_is_nonassignable_aggregate and "[" not in lhs and not lhs.startswith("*"):
                    continue
                out[lhs] = str(v).strip()
            return out or None
        if isinstance(value, (int, float)):
            if primary_is_nonassignable_aggregate:
                return None
            return {primary_var: str(int(value))}
        text = str(value).strip()
        if not text or text.startswith("LOGIC:"):
            return None
        assignments: dict[str, str] = {}
        chunks = [chunk.strip() for chunk in text.split(";") if chunk.strip()]
        for chunk in chunks:
            match = re.match(r"^([A-Za-z_][A-Za-z0-9_\-\>\[\]\.\*]*)\s*=\s*(.+)$", chunk)
            if match:
                lhs, rhs = match.groups()
                lhs = lhs.strip()
                rhs = rhs.strip()
                if lhs == primary_var and primary_is_nonassignable_aggregate and "[" not in lhs and not lhs.startswith("*"):
                    continue
                if lhs in assignment_targets or lhs == primary_var:
                    assignments[lhs] = rhs
        if assignments:
            return assignments
        if primary_is_nonassignable_aggregate:
            return None
        if re.match(r"^-?\d+$", text) or re.match(r"^0x[0-9a-fA-F]+$", text):
            return {primary_var: text}
        return None

    def _format_assignment_expr(lhs: str, rhs: str) -> str:
        if lhs == primary_var:
            assign_val = rhs
            if "*" in var_type and not assign_val.startswith("(") and "NULL" not in assign_val:
                assign_val = f"({var_type}){rhs}"
            return f"{lhs} = {assign_val}"
        return f"{lhs} = {rhs}"

    def _apply_assignment_map(assignments: dict[str, str]) -> tuple[bool, str]:
        for lhs, rhs in assignments.items():
            expr = _format_assignment_expr(lhs, rhs)
            result = harness.apply(DebuggerIntervention(kind="assign_expression", payload={"expression": expr}))
            success, msg = result.success, result.message
            if not success:
                return False, f"{lhs}: {msg}"
        return True, "ok"

    prelim: list[tuple[str, dict[str, object]]] = []
    for constraint in constraints:
        if _constraint_kind(constraint) == "operational":
            prelim.append((constraint, _run_operational_constraint_check(constraint, suspect_object, logger)))
            continue
        stats = {
            "positive_examples_seen": 0,
            "negative_examples_seen": 0,
            "positive_examples_skipped": 0,
            "negative_examples_skipped": 0,
            "non_scalar_positive_count": len(angelic_non_scalar),
            "non_scalar_negative_count": len(demonic_non_scalar),
            "eval_failures": 0,
        }
        info: dict[str, object] = {
            "constraint": constraint,
            "constraint_kind": "predicate",
            "constraint_status": "weakly_supported",
            "status": "weakly_supported",
            "precheck_status": "pending",
            "precheck_score": 0.0,
            "reason": "",
            "support_stats": stats,
            "mechanism_hint": mechanism_hint,
            "proxy_like": False,
            "execution_check": {},
            "challenge_result": {},
            "challenge_status": "pending",
            "challenge_score": 0.0,
            "top_angelic_examples": list(angelic_list[:3]),
            "non_scalar_angelic_examples": angelic_non_scalar[:3],
        }
        compatible, compat_reason = _is_lldb_expr_compatible(constraint)
        if not compatible:
            info["constraint_status"] = "rejected"
            info["status"] = "rejected"
            info["precheck_status"] = "rejected"
            info["reason"] = compat_reason
            prelim.append((constraint, _finalize_constraint_result(info)))
            continue

        rejected_reason = None
        for value in angelic_list:
            harness.prepare(file, line)
            assignments = _extract_assignment_map(value)
            if assignments is None:
                logger.warning(f"Skipping non-scalar angelic candidate during constraint verify: {value}")
                stats["positive_examples_skipped"] += 1
                continue
            applied, apply_err = _apply_assignment_map(assignments)
            if not applied:
                logger.warning(f"Failed to apply angelic assignment map {assignments}: {apply_err}")
                stats["positive_examples_skipped"] += 1
                stats["eval_failures"] += 1
                continue
            stats["positive_examples_seen"] += 1
            eval_result, eval_err = _eval_with_retry(constraint, file, line)
            if eval_result is None:
                stats["eval_failures"] += 1
                stats["positive_examples_skipped"] += 1
                continue
            if not _is_truthy(eval_result):
                rejected_reason = (
                    "False negative: Constraint evaluated to FALSE for safe "
                    f"(Angelic) value '{value}' (Result: {eval_result})."
                )
                break

        if rejected_reason is None:
            for value in demonic_list:
                value_str = str(value) if value is not None else ""
                if value == "NULL" or "not available" in value_str:
                    stats["negative_examples_skipped"] += 1
                    continue
                if value_str.strip().startswith("LOGIC:"):
                    logger.warning(f"Skipping non-scalar demonic candidate during constraint verify: {value}")
                    stats["negative_examples_skipped"] += 1
                    continue
                harness.prepare(file, line)
                assignments = _extract_assignment_map(value)
                if assignments is None:
                    logger.warning(f"Skipping non-scalar demonic candidate during constraint verify: {value}")
                    stats["negative_examples_skipped"] += 1
                    continue
                applied, apply_err = _apply_assignment_map(assignments)
                if not applied:
                    logger.warning(f"Failed to apply demonic assignment map {assignments}: {apply_err}")
                    stats["negative_examples_skipped"] += 1
                    stats["eval_failures"] += 1
                    continue
                stats["negative_examples_seen"] += 1
                eval_result, eval_err = _eval_with_retry(constraint, file, line)
                if eval_result is None:
                    stats["eval_failures"] += 1
                    stats["negative_examples_skipped"] += 1
                    continue
                if not _is_falsy(eval_result):
                    rejected_reason = (
                        "False positive: Constraint evaluated to TRUE for unsafe "
                        f"(Demonic) value '{value}' (Result: {eval_result})."
                    )
                    break

        if rejected_reason:
            info["constraint_status"] = "rejected"
            info["status"] = "rejected"
            info["precheck_status"] = "rejected"
            info["reason"] = rejected_reason
            prelim.append((constraint, _finalize_constraint_result(info)))
            continue

        usable_total = int(stats["positive_examples_seen"]) + int(stats["negative_examples_seen"])
        if usable_total == 0:
            info["constraint_status"] = "rejected"
            info["status"] = "rejected"
            info["precheck_status"] = "rejected"
            info["reason"] = "No usable scalar evidence could be evaluated for this constraint."
        elif int(stats["positive_examples_seen"]) == 0 or int(stats["negative_examples_seen"]) == 0 or int(stats["eval_failures"]) > usable_total:
            info["constraint_status"] = "weakly_supported"
            info["status"] = "weakly_supported"
            info["precheck_status"] = "passed_limited"
            info["reason"] = "Constraint aligns with limited evidence but lacks balanced scalar support."
        else:
            proxy_like = _constraint_mechanism_mismatch(constraint, mechanism_hint)
            info["proxy_like"] = proxy_like
            if proxy_like:
                info["constraint_status"] = "supported_but_proxy_like"
                info["status"] = "supported_but_proxy_like"
                info["precheck_status"] = "passed"
                info["reason"] = "Constraint matches scalar evidence but looks proxy-like relative to angelic mechanism."
            else:
                info["constraint_status"] = "weakly_supported"
                info["status"] = "weakly_supported"
                info["precheck_status"] = "passed"
                info["reason"] = "Constraint is supported by scalar evidence and awaits execution screening."
        info["precheck_score"] = _precheck_score_from_status(info)
        prelim.append((constraint, info))

    executable_candidates = [
        item for item in prelim
        if item[1]["constraint_status"] in {"weakly_supported", "supported_but_proxy_like"}
        and item[1].get("constraint_kind", "predicate") != "operational"
    ][: max(1, challenge_top_k)]
    for constraint, info in executable_candidates:
        assignments = _choose_execution_probe(constraint, angelic_list, counterexample_probes=[], suspect_object=suspect_object)
        execution_check = _run_execution_probe(constraint, assignments, suspect_object, _apply_assignment_map, _eval_with_retry, logger)
        info["execution_check"] = execution_check
        if execution_check.get("classification") == "safer_execution":
            info["constraint_status"] = "supported_and_executable"
            info["status"] = "supported_and_executable"
            info["reason"] = str(execution_check.get("reason"))
        elif info["constraint_status"] == "weakly_supported":
            info["reason"] = f"{info['reason']} Execution check: {execution_check.get('reason')}"
        else:
            info["reason"] = f"{info['reason']} Execution check: {execution_check.get('reason')}"
        challenge_result = _run_constraint_challenger(
            constraint=constraint,
            precheck_info=info,
            suspect_object=suspect_object,
            angelic_list=angelic_list,
            demonic_list=demonic_list,
            counterexample_probes=counterexample_probes,
            intervention_budget=challenge_budget,
            logger=logger,
        )
        info["challenge_result"] = challenge_result
        info["overall_score"] = float(challenge_result.get("overall_score", 0.0) or 0.0)
        stats["challenger_support_count"] = len(challenge_result.get("supporting_interventions", []) or [])
        stats["challenger_counterexample_count"] = len(challenge_result.get("counterexample_interventions", []) or [])
        _finalize_constraint_result(info)

    for constraint, info in prelim:
        results[constraint] = info
    return results


@logf(NAME, True)
def run_constraint_round(state: BugHypothesisState, llm_agent, logger=None) -> tuple[list[ConstraintCandidate], AgentMessage]:
    suspect_object = state.current_suspect()
    fuzz_result = state.current_fuzz_result() or {}

    if not suspect_object or not fuzz_result:
        message = AgentMessage(
            actor="constraint",
            claims=["Missing suspect or fuzz result, unable to derive constraints."],
            confidence=0.0,
            recommended_next_actor="debug" if not suspect_object else "fuzz",
        )
        return [], message

    initial_constraint = str(fuzz_result.get("deduced_constraint", "")).strip()
    function_body = _collect_function_body(suspect_object, logger)
    history = _build_history(state)
    valid_candidates: list[ConstraintCandidate] = []
    rejected_candidates: list[ConstraintCandidate] = []
    known_assignments = angelic_assignment_sets(suspect_object)
    angelic_values = list(fuzz_result.get("angelic_values", [])) + list(known_assignments)
    positive_examples = [_example(v, "positive") for v in angelic_values]
    negative_examples = [_example(v, "negative") for v in fuzz_result.get("demonic_values", [])]
    counterexample_probes = _generate_counterexample_probes(suspect_object, fuzz_result)
    bug_type_profile = suspect_object.get("bug_type_profile") or state.bug_type_profile or infer_bug_type_profile(
        profile=state.profile,
        reproduce_result=state.reproduce_result,
        suspect_object=suspect_object,
        debug_summary=suspect_object.get("debug_summary", ""),
        function_body=function_body,
    )
    typed_evidence = fuzz_result.get("typed_angelic_evidence", {})

    semantics_cache: dict[str, dict[str, object]] = {}
    operational_generalization_cache: dict[str, dict[str, object]] = {}

    for attempt in range(3):
        logger.info(f"Constraint generation attempt {attempt + 1}/3")
        prompt = STALK_BRAINSTORM_PROMPT.format(
            initial_constraint=initial_constraint,
            debug_summary=suspect_object.get("debug_summary", "No summary provided."),
            suspect_object=suspect_object,
            angelic_values=angelic_values,
            demonic_values=fuzz_result.get("demonic_values", []),
            function_body=function_body,
            history=history,
        )
        if typed_evidence:
            prompt += (
                "\nTyped Angelic Evidence Summary:\n"
                f"- bug_type: {typed_evidence.get('bug_type')}\n"
                f"- angelic_type: {typed_evidence.get('angelic_type')}\n"
                f"- generalized_spec: {typed_evidence.get('generalized_spec', {})}\n"
                f"- repair_locations: {typed_evidence.get('repair_locations', [])}\n"
                f"- forbidden_patch_patterns: {typed_evidence.get('forbidden_patch_patterns', [])}\n"
            )
        prompt += build_stage_prompt_overlay("constraint", bug_type_profile)
        response = llm_agent.query(prompt, logger=logger)
        candidates = _parse_constraint_candidates(response, initial_constraint, logger)
        merged_candidates: list[str] = []
        for candidate in candidates:
            candidate = str(candidate).strip()
            if not candidate or candidate in merged_candidates:
                continue
            merged_candidates.append(candidate)
            if len(merged_candidates) >= 10:
                break
        for candidate in angelic_values:
            candidate = str(candidate).strip()
            if not candidate.startswith("LOGIC:") or candidate in merged_candidates:
                continue
            merged_candidates.append(candidate)
            if len(merged_candidates) >= 10:
                break
        if not merged_candidates and initial_constraint:
            merged_candidates = [initial_constraint]
        results = online_verify_constraints(
            constraints=merged_candidates,
            angelic_list=angelic_values,
            demonic_list=list(fuzz_result.get("demonic_values", [])) + counterexample_probes,
            suspect_object=suspect_object,
            logger=logger,
        )

        current_failures: list[tuple[str, str]] = []
        for constraint in merged_candidates:
            result = results.get(constraint, {"constraint_status": "rejected", "reason": "No verification result", "support_stats": {}})
            constraint_status = str(result.get("constraint_status", "rejected"))
            precheck_status = str(result.get("precheck_status", "unknown"))
            challenge_status = str(result.get("challenge_status", result.get("challenge_result", {}).get("status", "pending"))).lower()
            reason = str(result.get("reason", "No verification result"))
            if constraint_status in {"supported_and_executable", "supported_but_proxy_like"} and challenge_status == "supported":
                status = "validated"
            elif challenge_status == "needs_source_check":
                status = "needs_source_check"
            elif challenge_status == "inconclusive":
                status = "challenged_inconclusive"
            else:
                status = "rejected"
            counterexamples = []
            if constraint_status == "rejected":
                counterexamples = [
                    {"constraint": constraint, "reason": reason, "probes": counterexample_probes[:20]}
                ]
            top_angelic_examples = list(result.get("top_angelic_examples", angelic_values[:3]))[:3]
            if constraint_status == "rejected":
                semantics = {
                    "mechanism_hint": result.get("mechanism_hint") or _fallback_mechanism_from_values(angelic_values),
                    "repair_intent": _fallback_repair_intent(suspect_object, result.get("mechanism_hint") or _fallback_mechanism_from_values(angelic_values)),
                    "demonic_summary": _summarize_demonic_state(suspect_object, fuzz_result),
                    "proxy_like": False,
                    "reason": reason,
                    "strategy_hints": [],
                }
            elif constraint in semantics_cache:
                semantics = semantics_cache[constraint]
            else:
                semantics = _infer_constraint_semantics_with_llm(
                    llm_agent,
                    suspect_object,
                    fuzz_result,
                    constraint,
                    angelic_values,
                    list(fuzz_result.get("demonic_values", [])),
                    function_body,
                    logger,
                )
                semantics_cache[constraint] = semantics
            mechanism_hint = str(semantics.get("mechanism_hint") or result.get("mechanism_hint") or _fallback_mechanism_from_values(angelic_values))
            repair_intent = str(semantics.get("repair_intent") or _fallback_repair_intent(suspect_object, mechanism_hint))
            demonic_summary = str(semantics.get("demonic_summary") or _summarize_demonic_state(suspect_object, fuzz_result))
            strategy_hints = list(semantics.get("strategy_hints", []))
            proxy_like = bool(semantics.get("proxy_like", False))
            angelic_consumption_contract = dict(semantics.get("angelic_consumption_contract", {}))
            abstract_constraint = dict(result.get("abstract_constraint", {}))
            if _constraint_kind(constraint) == "operational":
                if constraint not in operational_generalization_cache:
                    operational_generalization_cache[constraint] = _generalize_operational_constraint_with_llm(
                        llm_agent,
                        suspect_object,
                        fuzz_result,
                        constraint,
                        angelic_values,
                        list(fuzz_result.get("demonic_values", [])),
                        function_body,
                        logger,
                    )
                abstract_constraint = _merge_operational_abstractions(
                    abstract_constraint,
                    operational_generalization_cache[constraint],
                )
            preferred_repair_stage = _infer_preferred_repair_stage(mechanism_hint, proxy_like, suspect_object)
            if _constraint_kind(constraint) == "operational":
                generalized_stage = str(abstract_constraint.get("repair_stage", "")).strip()
                if generalized_stage and generalized_stage != "unknown":
                    preferred_repair_stage = generalized_stage
            forbidden_repair_stages = _infer_forbidden_repair_stages_from_semantics(preferred_repair_stage, proxy_like)
            causal_chain_summary = str(
                suspect_object.get("causal_chain_summary")
                or f"Constraint reasoning indicates the crash site is downstream; prefer {preferred_repair_stage.replace('_', ' ')} over crash-site repair."
            )
            if constraint_status != "rejected":
                if proxy_like and constraint_status == "supported_and_executable":
                    constraint_status = "supported_but_proxy_like"
                    status = "validated"
                    reason = str(semantics.get("reason") or reason)
                elif proxy_like and constraint_status == "weakly_supported":
                    reason = str(semantics.get("reason") or reason)
                elif not proxy_like and constraint_status == "supported_but_proxy_like":
                    constraint_status = "weakly_supported"
                    status = "needs_source_check"
            candidate = ConstraintCandidate(
                constraint=constraint,
                constraint_kind=_constraint_kind(constraint),
                status=status,
                constraint_status=constraint_status,
                reason=reason,
                attempts=attempt + 1,
                verification={
                    "attempt": attempt + 1,
                    "reason": reason,
                    "active_probe_count": len(counterexample_probes),
                    "trace_pair_count": len(fuzz_result.get("trace_pairs", []) or []),
                    "constraint_status": constraint_status,
                    "precheck_status": precheck_status,
                    "precheck_score": float(result.get("precheck_score", 0.0) or 0.0),
                    "challenge_status": challenge_status,
                    "challenge_score": float(result.get("challenge_score", 0.0) or 0.0),
                },
                precheck_status=precheck_status,
                precheck_score=float(result.get("precheck_score", 0.0) or 0.0),
                challenge_status=challenge_status,
                challenge_score=float(result.get("challenge_score", 0.0) or 0.0),
                evidence=[
                    suspect_object.get("debug_summary", ""),
                    f"angelic={angelic_values[:3]}",
                    f"demonic={fuzz_result.get('demonic_values', [])[:3]}",
                    f"minimal_deltas={fuzz_result.get('minimal_deltas', [])[:2]}",
                ],
                required_expressions=suspect_object.get("suspect_expressions", [])[:20],
                positive_examples=positive_examples,
                negative_examples=negative_examples + [_example(v, "negative", "active_probe") for v in counterexample_probes],
                counterexamples=counterexamples,
                generalization_score=(
                    0.9 if constraint_status == "supported_and_executable"
                    else 0.72 if constraint_status == "supported_but_proxy_like"
                    else 0.4 if constraint_status == "weakly_supported"
                    else 0.0
                ),
                repair_intent=repair_intent,
                top_angelic_examples=top_angelic_examples,
                demonic_summary=demonic_summary,
                support_stats=dict(result.get("support_stats", {})),
                mechanism_hint=mechanism_hint,
                constraint_role="generalized_hypothesis",
                execution_check=dict(result.get("execution_check", {})),
                challenge_result=dict(result.get("challenge_result", {})),
                recommended_next_actor=str(result.get("challenge_result", {}).get("recommended_next_actor", "patch")),
                overall_score=float(result.get("overall_score", 0.0) or 0.0),
                causal_chain_summary=causal_chain_summary,
                preferred_repair_stage=preferred_repair_stage,
                forbidden_repair_stages=forbidden_repair_stages,
                bug_type_profile=bug_type_profile,
                typed_angelic_evidence=typed_evidence,
                demonic_trace_summary=fuzz_result.get("demonic_trace_summary", {}),
                abstract_constraint=abstract_constraint,
                strategy_hints=(
                    strategy_hints
                    + ([{"operational_generalization": abstract_constraint}] if _constraint_kind(constraint) == "operational" and abstract_constraint else [])
                    + ([{"angelic_consumption_contract": angelic_consumption_contract}] if angelic_consumption_contract else [])
                ),
            )
            if challenge_status == "supported" and constraint_status in {"supported_and_executable", "supported_but_proxy_like"}:
                valid_candidates.append(candidate)
            else:
                rejected_candidates.append(candidate)
                current_failures.append((constraint, reason))

        if valid_candidates:
            break

        if current_failures:
            history += "\n\nAttempt failed. The following constraints were invalid:\n"
            for constraint, reason in current_failures[:8]:
                history += f"- `{constraint}`: {reason}\n"
            history += "Please try different logic or syntax. Do NOT repeat failed constraints."

    all_candidates = valid_candidates or rejected_candidates
    if valid_candidates:
        supported_candidates = [
            candidate for candidate in valid_candidates
            if str(candidate.challenge_result.get("status", "")).lower() == "supported"
        ]
        patchable_supported = [
            candidate for candidate in supported_candidates
            if float(candidate.challenge_result.get("patchability_score", 1.0) or 1.0) >= 0.45
        ]
        next_actor = "patch"
        patch_question = "Can PatchAgent realize the validated guard with a minimal diff?"
        if patchable_supported:
            next_actor = "patch"
        elif supported_candidates:
            next_actor = "constraint"
            patch_question = "Constraint is supported but patchability is low; can ConstraintAgent refine it toward a safer upstream invariant?"
        elif any(str(candidate.challenge_result.get("status", "")).lower() == "inconclusive" for candidate in valid_candidates):
            next_actor = "fuzz"
            patch_question = "Challenger remained inconclusive; can FuzzAgent search for stronger relational evidence or new state splits?"
        elif any(str(candidate.challenge_result.get("status", "")).lower() == "needs_source_check" for candidate in valid_candidates):
            next_actor = "debug"
            patch_question = "Challenger needs source/debugger clarification; can DebugAgent refine the intervention point?"
        message = AgentMessage(
            actor="constraint",
            claims=[f"Screened {len(valid_candidates)} constraint candidate(s) as usable generalized hypotheses against angelic/demonic evidence."],
            evidence=[
                EvidenceItem(
                    source="constraint",
                    summary=f"Top screened constraint: {valid_candidates[0].constraint}",
                    kind="validated_constraint",
                    payload={
                        **valid_candidates[0].verification,
                        "challenge_result": valid_candidates[0].challenge_result,
                        "overall_score": valid_candidates[0].overall_score,
                    },
                )
            ],
            confidence=0.75,
            questions_for_others=[
                OpenQuestion(
                    source="constraint",
                    question=patch_question,
                    target_actor=next_actor,
                )
            ],
            recommended_next_actor=next_actor,
            artifacts={"constraint_candidates": [candidate.__dict__ for candidate in all_candidates]},
        )
    else:
        challenged_inconclusive = [
            candidate for candidate in all_candidates
            if candidate.challenge_status in {"inconclusive", "needs_source_check"}
        ]
        next_actor = "debug"
        rejection_summary = "Constraint verification failed for all generated candidates."
        question = "Root cause hypothesis may be incomplete. Can DebugAgent revisit the suspect?"
        if any(candidate.challenge_status == "inconclusive" for candidate in challenged_inconclusive):
            next_actor = "fuzz"
            rejection_summary = "No constraint candidate achieved challenger support; strongest candidates remained inconclusive after precheck."
            question = "Challenger was inconclusive after precheck. Can FuzzAgent search for stronger relational evidence or new state splits?"
        elif any(candidate.challenge_status == "needs_source_check" for candidate in challenged_inconclusive):
            next_actor = "debug"
            rejection_summary = "No constraint candidate achieved challenger support; the remaining candidates need source/debugger clarification."
            question = "Challenger needs source/debugger clarification. Can DebugAgent refine the intervention point?"
        message = AgentMessage(
            actor="constraint",
            claims=["No constraint candidate achieved challenger-backed validation."],
            evidence=[
                EvidenceItem(
                    source="constraint",
                    summary=rejection_summary,
                    kind="constraint_rejection",
                    payload={
                        "attempts": len(rejected_candidates),
                        "challenged_candidates": len(challenged_inconclusive),
                    },
                )
            ],
            confidence=0.15,
            questions_for_others=[
                OpenQuestion(
                    source="constraint",
                    question=question,
                    target_actor=next_actor,
                )
            ],
            recommended_next_actor=next_actor,
            artifacts={"constraint_candidates": [candidate.__dict__ for candidate in all_candidates]},
        )

    return all_candidates, message
