import os
import re
import json
from typing import Any, Tuple

from agent.reproduce_agent import derive_input_variants, run_profile_once, run_secbench_repro_once
from tools.file.functions import file_apply_patches, file_undo_patches
from utils.command import is_secbench_profile, run_reproduce, run_validation_build
from utils.logger import logf
from utils.parsers import parse_sanitizer_output, parse_sanitizer_stack_frame

NAME = "verification"


def run_compile(profile: dict | None = None):
    return run_validation_build(profile)


def _extract_compile_errors(stderr: str) -> list[str]:
    errors = []
    for line in stderr.split("\n"):
        if "error:" in line:
            errors.append(re.sub(r"\x1b\[[0-9;]*m", "", line.strip()))
    return errors


_BUILD_FAILURE_RE = re.compile(
    r"("
    r"\berror:|"
    r"\bfailed\b|"
    r"\bfailure\b|"
    r"\btraceback\b|"
    r"\bexception\b|"
    r"undefined reference|"
    r"patch does not apply|"
    r"patch failed|"
    r"FAILED \(|"
    r"\bFAIL:|"
    r"\bERROR:"
    r")",
    re.IGNORECASE,
)


def _extract_build_failure_lines(output: str, limit: int = 20) -> list[str]:
    lines: list[str] = []
    for raw_line in str(output or "").splitlines():
        line = re.sub(r"\x1b\[[0-9;]*m", "", raw_line).strip()
        if not line:
            continue
        if _BUILD_FAILURE_RE.search(line):
            lines.append(line)
    return lines[-limit:]


def _truncate_build_output(text: str, max_lines: int = 15, max_chars: int = 800) -> str:
    """Return last N lines of text for LLM feedback when compile/post-build fails."""
    if not text or not text.strip():
        return "(no output)"
    lines = [l for l in text.strip().split("\n") if l.strip()]
    if len(lines) <= max_lines:
        out = "\n".join(lines)
    else:
        out = "\n".join(lines[-max_lines:])
    if len(out) > max_chars:
        return "..." + out[-max_chars:]
    return out


def _first_failed_replay_item(report: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(report, dict):
        return {}
    for item in report.get("items", []) or []:
        if isinstance(item, dict) and item.get("status") != "pass":
            return item
    return {}


def _extract_crash_site(frames: list[str] | None, logger=None) -> dict[str, Any] | None:
    for frame in frames or []:
        try:
            function, filename, line = parse_sanitizer_stack_frame(frame, logger=logger)
        except Exception:
            continue
        if filename:
            return {
                "function": function,
                "file": filename,
                "line": line,
            }
    return None


def _same_site(expected_file: str | None, expected_line: int | None, crash_site: dict[str, Any] | None) -> bool:
    if not expected_file or not expected_line or not crash_site:
        return False
    if os.path.basename(expected_file) != os.path.basename(crash_site["file"]):
        return False
    return abs(int(expected_line) - int(crash_site["line"])) <= 3


def _has_sanitizer_signature(text: str) -> bool:
    return bool(
        re.search(
            r"(AddressSanitizer|MemorySanitizer|UndefinedBehaviorSanitizer|LeakSanitizer|ThreadSanitizer|runtime error:|ERROR:\s+\w*Sanitizer)",
            str(text or ""),
            re.IGNORECASE,
        )
    )


def _runtime_output(result: dict[str, Any] | None) -> str:
    result = result or {}
    return "\n".join(
        str(result.get(field, "") or "")
        for field in ("error", "stdout", "stderr")
        if str(result.get(field, "") or "").strip()
    )


def _replay_status(result: dict[str, Any] | None) -> str:
    result = result or {}
    raw_return_code = result.get("return_code", 1)
    return_code = int(raw_return_code if raw_return_code is not None else 1)
    if return_code == -66:
        return "timeout"
    if return_code == 0 and not _has_sanitizer_signature(_runtime_output(result)):
        return "pass"
    return "fail"


def _runtime_failure_without_sanitizer_message(return_code: int, runtime_output: str, bug_type_profile: dict | None) -> tuple[str, str]:
    bug_type = str((bug_type_profile or {}).get("bug_type", "unknown")).lower()
    output_preview = _truncate_build_output(runtime_output, max_lines=8, max_chars=600)
    sanitizer_expected = bug_type in {
        "out_of_bounds",
        "integer_overflow",
        "use_after_free",
        "double_free",
        "invalid_free",
        "heap_corruption_later_crash",
        "invalid_pointer",
        "uninitialized_use",
        "data_race",
        "resource_leak",
    }
    if sanitizer_expected:
        message = (
            "Original sanitizer crash was not reproduced, but the patched program still exited non-zero "
            f"(return code {return_code}). Treat this as an ambiguous runtime failure, not proof that the "
            "original crash remains."
        )
        blame_hint = (
            "The sanitizer signature disappeared; inspect the raw runtime output and decide whether the patch "
            "introduced/retained an ordinary error exit or should be accepted with additional semantic checks."
        )
    else:
        message = (
            f"Patched program exited non-zero without a sanitizer stack (return code {return_code}). "
            "This indicates runtime verification failed, but it is not necessarily the original crash."
        )
        blame_hint = (
            "No sanitizer stack was available; classify from program semantics and raw output instead of assuming crash persistence."
        )
    if output_preview and output_preview != "(no output)":
        message += f"\n\nRuntime output excerpt:\n```\n{output_preview}\n```"
    return message, blame_hint


def _format_runtime_failure_message(prefix: str, error: str, runtime_output: str) -> str:
    message = f"{prefix}: \n```\n{error}\n```"
    if "Runtime output excerpt" in message:
        return message
    output_preview = _truncate_build_output(runtime_output, max_lines=30, max_chars=2000)
    if output_preview and output_preview != "(no output)":
        message += f"\n\nRuntime output excerpt:\n```\n{output_preview}\n```"
    return message


def _discover_regression_inputs(profile: dict | None, max_inputs: int = 30) -> list[str]:
    if not profile:
        return []
    configured = profile.get("benign_inputs") or profile.get("regression_inputs") or []
    if isinstance(configured, str):
        configured = [configured]
    out: list[str] = []
    for path in [str(path) for path in configured if path]:
        if path not in out:
            out.append(path)
        if len(out) >= max_inputs:
            break
    return out


def _empty_tier_report(profile: dict | None = None) -> dict[str, Any]:
    variants = profile.get("variant_inputs") if profile else None
    variants_enabled = bool(variants) or bool(profile and profile.get("enable_variant_replay"))
    regression_inputs = _discover_regression_inputs(profile)
    return {
        "tier1_original_poc": {"status": "not_run"},
        "tier2_variants": {
            "status": "disabled" if not variants_enabled else "configured_not_executed",
            "input_count": len(variants or []),
        },
        "tier3_regression": {
            "status": "regression_unavailable" if not regression_inputs else "configured_not_executed",
            "input_count": len(regression_inputs),
            "inputs": regression_inputs[:30],
        },
    }


def _guard_like_strategy(strategy: str, location_type: str) -> bool:
    return strategy in {
        "bounds_check_before_access",
        "reject_invalid_input",
        "null_or_lifetime_guard",
        "semantic_noop_reject",
    } or location_type == "same_site"


def _infer_replay_failure_status(
    patch: dict,
    fallback_status: str,
    fallback_actor: str,
    fallback_hint: str,
) -> tuple[str, str, str]:
    strategy = str(patch.get("strategy", ""))
    location_type = str(patch.get("location_type", ""))
    semantic_risk = str(patch.get("semantic_risk", "medium"))
    constraint_text = str(patch.get("constraint", "")).lower()

    if fallback_status == "same_site_crash" and _guard_like_strategy(strategy, location_type):
        if any(token in constraint_text for token in ("offset", "len", "length", "size", "count", "end", "base")):
            return (
                "nonlocal_invariant",
                "debug",
                "Local guard did not repair the relational state; expand the search upstream to the invariant producer.",
            )
    if fallback_status in {"overfit_poc", "semantic_regression"} and _guard_like_strategy(strategy, location_type):
        return (
            "bad_patch_location",
            "patch",
            "Patch shape looks too local to the crash sink; move the repair upstream or normalize earlier state.",
        )
    if fallback_status == "semantic_regression" and semantic_risk == "high":
        return (
            "bad_patch_location",
            "patch",
            "High-risk patch changed behavior too aggressively; prefer a lower-risk upstream repair.",
        )
    return fallback_status, fallback_actor, fallback_hint


def _verification_confidence(tier_report: dict[str, Any], patch: dict) -> float:
    tier2_status = tier_report.get("tier2_variants", {}).get("status")
    tier3_status = tier_report.get("tier3_regression", {}).get("status")
    semantic_risk = str(patch.get("semantic_risk", "medium"))
    confidence = 0.75
    if tier2_status == "pass":
        confidence += 0.15
    if tier3_status == "pass":
        confidence += 0.10
    elif tier3_status == "regression_unavailable":
        confidence -= 0.10
    if semantic_risk == "low":
        confidence += 0.05
    elif semantic_risk == "high":
        confidence -= 0.10
    return max(0.0, min(1.0, round(confidence, 2)))


def _direct_patch_alignment(patch: dict) -> str:
    root_cause_report = patch.get("root_cause_report") if isinstance(patch.get("root_cause_report"), dict) else {}
    preferred_stage = str(root_cause_report.get("preferred_repair_stage", "") or "")
    topology = str(root_cause_report.get("repair_topology", "") or "")
    semantic_risk = str(patch.get("semantic_risk", "medium"))
    location_type = str(patch.get("location_type", "same_site"))
    strategy = str(patch.get("strategy", ""))
    guard_like = _guard_like_strategy(strategy, location_type)
    if semantic_risk == "high":
        return "poor"
    if preferred_stage and preferred_stage != "crash_guard" and location_type == "same_site" and guard_like:
        return "poor"
    if topology in {"caller_to_callee", "cross_file_invariant", "init_then_use"} and location_type != "upstream":
        return "partial"
    if location_type == "upstream":
        return "aligned"
    return "aligned" if not guard_like else "partial"


def _classify_direct_patch_assessment(
    patch: dict,
    status: str,
    tier_report: dict[str, Any],
    obligation_summary: dict[str, Any],
    confidence: float,
    residual_risk: str,
    default_next_actor: str,
    default_blame_hint: str,
) -> dict[str, Any]:
    llm_decision = _judge_direct_patch_with_llm(
        patch=patch,
        status=status,
        tier_report=tier_report,
        obligation_summary=obligation_summary,
        confidence=confidence,
        residual_risk=residual_risk,
        default_next_actor=default_next_actor,
        default_blame_hint=default_blame_hint,
    )
    if llm_decision:
        return llm_decision
    return {
        "verdict": "suspicious" if status == "pass" else "failed",
        "recommended_next_actor": "layer2",
        "rationale": "Direct patch judge LLM was unavailable or returned invalid JSON; do not accept a Layer 1 direct patch without LLM judgment.",
        "verification_confidence": confidence,
        "residual_risk": residual_risk or "llm_direct_patch_judge_unavailable",
        "root_cause_alignment": _direct_patch_alignment(patch),
        "source_status": status,
        "layer2_validation_required": True,
        "direct_patch_risk": str(
            ((patch.get("root_cause_report") or {}).get("direct_patch_risk", "high"))
            if isinstance(patch.get("root_cause_report"), dict)
            else "high"
        ),
        "decision_source": "llm_unavailable",
    }


def _extract_json_object(text: str) -> dict[str, Any] | None:
    if not text:
        return None
    candidates = []
    fenced = re.findall(r"```json\s*(\{.*?\})\s*```", text, flags=re.DOTALL | re.IGNORECASE)
    candidates.extend(fenced)
    brace_match = re.search(r"(\{.*\})", text, flags=re.DOTALL)
    if brace_match:
        candidates.append(brace_match.group(1))
    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            continue
    return None


def _judge_direct_patch_with_llm(
    patch: dict,
    status: str,
    tier_report: dict[str, Any],
    obligation_summary: dict[str, Any],
    confidence: float,
    residual_risk: str,
    default_next_actor: str,
    default_blame_hint: str,
) -> dict[str, Any] | None:
    if patch.get("llm_verifier_enabled", True) is False:
        return None

    allowed_verdicts = {"strong", "weak", "suspicious", "failed"}
    allowed_next = {"done", "counterfactual", "layer2", "debug", "constraint", "fuzz", "patch"}

    evidence = {
        "source_status": status,
        "default_next_actor": default_next_actor,
        "default_blame_hint": default_blame_hint,
        "verification_confidence": confidence,
        "residual_risk": residual_risk,
        "tier_report": tier_report,
        "obligation_summary": obligation_summary,
        "patch_metadata": {
            "patches": patch.get("patches", []),
            "strategy": patch.get("strategy", ""),
            "location_type": patch.get("location_type", ""),
            "semantic_risk": patch.get("semantic_risk", "medium"),
            "constraint": patch.get("constraint", ""),
            "suspect_file": patch.get("suspect_file", ""),
            "suspect_line": patch.get("suspect_line", -1),
            "function_name": patch.get("function_name", ""),
        },
        "root_cause_report": patch.get("root_cause_report", {}) if isinstance(patch.get("root_cause_report"), dict) else {},
        "bug_type_profile": patch.get("bug_type_profile", {}) if isinstance(patch.get("bug_type_profile"), dict) else {},
        "typed_angelic_evidence": patch.get("typed_angelic_evidence", {}) if isinstance(patch.get("typed_angelic_evidence"), dict) else {},
    }

    prompt = (
        "You are a patch verification judge for C/C++ crash repair.\n"
        "You are given structured execution evidence from a programmatic verifier.\n"
        "You are the sole Layer 1 direct-patch acceptance judge. Do NOT defer to any rule-based fallback.\n"
        "Do NOT invent evidence. Use the evidence bundle to decide whether a direct patch should be accepted, treated as weak, treated as suspicious, or rejected.\n\n"
        "Decision rubric:\n"
        "- `strong`: evidence supports accepting the direct patch.\n"
        "- `weak`: the patch likely works for the observed failure, but more Layer 2 validation is needed.\n"
        "- `suspicious`: the patch may suppress the symptom, but repair semantics/location/risk look wrong.\n"
        "- `failed`: evidence shows the patch should not be accepted in its current form.\n\n"
        "Patch-shape policy:\n"
        "- Allow patches that add a condition and return a semantically meaningful error value/status, such as `return DW_DLV_ERROR;`, `return -1;`, `return false;`, or an established project error code, when the runtime evidence shows this is the intended malformed-input/error path and no sanitizer crash remains.\n"
        "- Do NOT accept patches that add a condition and then use a bare `return;`, skip the operation, silently drop work, or otherwise exit without reporting an error in non-void error-handling code. Treat these as `suspicious` or `failed` because they can hide state corruption or create new bugs.\n"
        "- Do NOT reject a patch merely because the fixed program exits non-zero when the output indicates a controlled semantic error for malformed input and the sanitizer crash is gone.\n"
        "- Prefer `weak` over `strong` when replay evidence is narrow, regression inputs are unavailable, or validation obligations remain incomplete, even if the patch shape is semantically plausible.\n\n"
        "Return JSON only with this schema:\n"
        "{\n"
        '  "verdict": "strong|weak|suspicious|failed",\n'
        '  "recommended_next_actor": "done|layer2|debug|constraint|fuzz|patch",\n'
        '  "rationale": "<short reason>",\n'
        '  "verification_confidence": <float 0.0-1.0>,\n'
        '  "residual_risk": "<short string>",\n'
        '  "root_cause_alignment": "aligned|partial|poor"\n'
        "}\n\n"
        f"Evidence bundle:\n```json\n{json.dumps(evidence, ensure_ascii=True, indent=2)}\n```"
    )

    try:
        from agent.generic_agent import GenericAgent, load_llm_config

        load_llm_config()
        judge = GenericAgent(
            name="VerifyJudge",
            system_prompt=(
                "You are a careful verification judge. "
                "You must output strict JSON only, grounded entirely in the supplied evidence."
            ),
        )
        response = judge.query(prompt)
    except Exception:
        return None

    parsed = _extract_json_object(response)
    if not parsed:
        return None

    verdict = str(parsed.get("verdict", "")).strip().lower()
    next_actor = str(parsed.get("recommended_next_actor", "")).strip().lower()
    rationale = str(parsed.get("rationale", "")).strip()
    alignment = str(parsed.get("root_cause_alignment", "")).strip().lower()
    llm_residual_risk = str(parsed.get("residual_risk", residual_risk)).strip()
    try:
        llm_confidence = float(parsed.get("verification_confidence", confidence))
    except Exception:
        llm_confidence = confidence

    if verdict not in allowed_verdicts or next_actor not in allowed_next:
        return None
    if alignment not in {"aligned", "partial", "poor"}:
        alignment = _direct_patch_alignment(patch)

    return {
        "verdict": verdict,
        "recommended_next_actor": next_actor,
        "rationale": rationale or "LLM direct-patch judge did not provide a rationale.",
        "verification_confidence": max(0.0, min(1.0, round(llm_confidence, 2))),
        "residual_risk": llm_residual_risk,
        "root_cause_alignment": alignment,
        "source_status": status,
        "layer2_validation_required": verdict in {"weak", "suspicious"},
        "direct_patch_risk": str(
            ((patch.get("root_cause_report") or {}).get("direct_patch_risk", "high"))
            if isinstance(patch.get("root_cause_report"), dict)
            else "high"
        ),
        "decision_source": "llm",
    }


def _judge_runtime_failure_with_llm(
    patch: dict,
    return_code: int,
    runtime_output: str,
    fallback_status: str,
    fallback_next_actor: str,
    fallback_blame_hint: str,
) -> dict[str, Any] | None:
    if patch.get("llm_verifier_enabled", True) is False:
        return None

    allowed_statuses = {
        "pass",
        "weak_constraint",
        "semantic_regression",
        "bad_patch_location",
        "nonlocal_invariant",
        "runtime_failure",
        "same_site_crash",
        "new_site_crash",
        "failed",
    }
    allowed_next = {"done", "layer2", "debug", "constraint", "fuzz", "patch"}
    evidence = {
        "return_code": return_code,
        "runtime_output": _truncate_build_output(runtime_output, max_lines=20, max_chars=1200),
        "fallback_status": fallback_status,
        "fallback_next_actor": fallback_next_actor,
        "fallback_blame_hint": fallback_blame_hint,
        "patch_metadata": {
            "strategy": patch.get("strategy", ""),
            "location_type": patch.get("location_type", ""),
            "semantic_risk": patch.get("semantic_risk", "medium"),
            "constraint": patch.get("constraint", ""),
            "suspect_file": patch.get("suspect_file", ""),
            "suspect_line": patch.get("suspect_line", -1),
            "function_name": patch.get("function_name", ""),
        },
        "root_cause_report": patch.get("root_cause_report", {}) if isinstance(patch.get("root_cause_report"), dict) else {},
        "bug_type_profile": patch.get("bug_type_profile", {}) if isinstance(patch.get("bug_type_profile"), dict) else {},
        "typed_angelic_evidence": patch.get("typed_angelic_evidence", {}) if isinstance(patch.get("typed_angelic_evidence"), dict) else {},
    }
    prompt = (
        "You are a patch verification judge for C/C++ crash repair.\n"
        "The programmatic verifier observed a non-zero runtime result, but no sanitizer stack could be parsed.\n"
        "Decide whether the patch successfully fixed the original crash, using only the provided evidence.\n"
        "A non-zero return code is not automatically a crash: if the original sanitizer failure disappeared and the raw output "
        "looks like an expected rejection/error path for malformed input, you may return status `pass`. "
        "Return a failure status only when the evidence indicates the crash remains, moved, or the patch introduced a harmful runtime failure.\n\n"
        "Return JSON only with this schema:\n"
        "{\n"
        '  "status": "pass|weak_constraint|semantic_regression|bad_patch_location|nonlocal_invariant|runtime_failure|same_site_crash|new_site_crash|failed",\n'
        '  "recommended_next_actor": "layer2|debug|constraint|fuzz|patch|done",\n'
        '  "blame_hint": "<short reason>",\n'
        '  "message": "<short verifier-facing message>"\n'
        "}\n\n"
        f"Evidence bundle:\n```json\n{json.dumps(evidence, ensure_ascii=True, indent=2)}\n```"
    )

    try:
        from agent.generic_agent import GenericAgent, load_llm_config

        load_llm_config()
        judge = GenericAgent(
            name="RuntimeVerifyJudge",
            system_prompt=(
                "You are a careful runtime failure judge. "
                "You must output strict JSON only, grounded entirely in the supplied evidence."
            ),
        )
        response = judge.query(prompt)
    except Exception:
        return None

    parsed = _extract_json_object(response)
    if not parsed:
        return None

    status = str(parsed.get("status", "")).strip().lower()
    next_actor = str(parsed.get("recommended_next_actor", "")).strip().lower()
    blame_hint = str(parsed.get("blame_hint", "")).strip()
    message = str(parsed.get("message", "")).strip()
    if status not in allowed_statuses or next_actor not in allowed_next:
        return None
    return {
        "status": status,
        "recommended_next_actor": next_actor,
        "blame_hint": blame_hint or fallback_blame_hint,
        "message": message or "Patch failed during runtime verification.",
        "decision_source": "llm",
    }


def _looks_like_support_or_harness_path(path: str) -> bool:
    normalized = str(path or "").replace("\\", "/").lower()
    support_markers = (
        "/scripts/",
        "/script/",
        "/fuzz/",
        "/tests/",
        "/test/",
        "/examples/",
        "/example/",
        "/bench/",
        "/benchmark/",
        "/corpus/",
    )
    return any(marker in normalized for marker in support_markers)


def _product_contract_repair_gap(patch: dict) -> tuple[bool, str]:
    patches = patch.get("patches") or []
    if not patches:
        return False, ""
    bug_type = str((patch.get("bug_type_profile") or {}).get("bug_type", "unknown")).lower()
    suspect_file = str(patch.get("suspect_file", "") or "")
    patch_files = [str(item.get("file", "") or "") for item in patches if isinstance(item, dict)]
    if not patch_files:
        return False, ""
    all_support = all(_looks_like_support_or_harness_path(path) for path in patch_files)
    if not all_support:
        return False, ""
    if _looks_like_support_or_harness_path(suspect_file):
        return False, ""
    if bug_type in {"out_of_bounds", "integer_overflow", "use_after_free", "double_free", "invalid_free", "heap_corruption_later_crash", "invalid_pointer", "uninitialized_use"}:
        return True, (
            "Patch only modifies fuzz/test/support files even though the inferred root-cause bug type suggests a product-code contract repair is required."
        )
    return False, ""


def _normalize_obligation_token(text: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "_", str(text or "").strip().lower()).strip("_")
    return normalized or "unknown"


def _evaluate_validation_obligations(
    obligations: list[str],
    tier_report: dict[str, Any],
    bug_type_profile: dict[str, Any] | None = None,
) -> dict[str, Any]:
    tier1_status = str(tier_report.get("tier1_original_poc", {}).get("status", "not_run"))
    tier2_status = str(tier_report.get("tier2_variants", {}).get("status", "not_available"))
    tier3_status = str(tier_report.get("tier3_regression", {}).get("status", "regression_unavailable"))
    bug_type = str((bug_type_profile or {}).get("bug_type", "unknown"))

    coverage: list[dict[str, str]] = []
    unmet: list[str] = []
    warnings: list[str] = []

    for obligation in obligations:
        token = _normalize_obligation_token(obligation)
        status = "informational"
        note = "No dedicated automated check is currently wired for this obligation."
        if token == "original_poc_passes":
            status = "satisfied" if tier1_status in {"pass", "pass_llm_nonzero"} else "unmet"
            note = "Original reproducer must execute cleanly after patching."
        elif token in {"asan_clean", "msan_valgrind_clean", "ubsan_clean"}:
            status = "satisfied" if tier1_status == "pass" and tier2_status != "fail" and tier3_status != "fail" else "unmet"
            note = "Sanitizer-clean replay is approximated by successful PoC and replay runs."
        elif token == "lsan_clean":
            if tier3_status == "pass":
                status = "satisfied"
                note = "Regression replay exercised cleanup-oriented paths without failure."
            else:
                status = "needs_targeted_followup"
                note = "Leak-specific cleanup coverage was not explicitly exercised."
        elif token == "boundary_neighbor_values_checked":
            status = "satisfied" if tier2_status == "pass" else "needs_targeted_followup"
            note = "Nearby variant replay is the best available proxy for boundary-neighbor coverage."
        elif token in {
            "alias_set_reviewed",
            "all_construction_paths_initialized",
            "assertion_invariant_restored",
            "zero_input_semantics_checked",
            "no_leak_regression",
            "first_bad_access_identified_or_strongly_approximated",
            "pointer_provenance_preserved",
            "allocation_access_consistency_maintained",
            "null_contract_respected_on_all_paths",
            "termination_base_case_reached",
            "no_unbounded_recursion_remains",
        }:
            if tier2_status == "pass" or tier3_status == "pass":
                status = "partially_satisfied"
                note = "Replay coverage increases confidence, but this obligation still needs semantic review."
            else:
                status = "needs_targeted_followup"
                note = "No targeted replay evidence currently covers this semantic obligation."
        elif token == "regression_tests_pass":
            status = "satisfied" if tier3_status == "pass" else "needs_targeted_followup"
            note = "Regression replay is the current proxy for this obligation."
        elif token == "tsan_clean":
            status = "needs_targeted_followup"
            note = "TSan-style race validation is not available in the current verifier."

        coverage.append({"obligation": obligation, "status": status, "note": note})
        if status == "unmet":
            unmet.append(obligation)
        elif status == "needs_targeted_followup":
            warnings.append(obligation)

    if bug_type in {"data_race", "resource_leak"} and not obligations:
        warnings.append(f"{bug_type}: missing explicit validation obligations")

    return {
        "coverage": coverage,
        "unmet": unmet,
        "warnings": warnings,
    }


def _run_variant_replay(profile: dict | None, max_variants: int = 20, logger=None) -> dict[str, Any]:
    if not profile:
        return {"status": "not_available", "input_count": 0, "items": []}
    configured = profile.get("variant_inputs") or []
    if not configured and not profile.get("enable_variant_replay"):
        return {
            "status": "disabled",
            "input_count": 0,
            "items": [],
            "note": "Variant replay disabled unless profile enables it or provides variant_inputs.",
        }
    variants = derive_input_variants(profile, max_variants=max_variants)
    if not variants:
        return {"status": "not_available", "input_count": 0, "items": []}
    items = []
    failed = False
    for args in variants[:max_variants]:
        result = run_profile_once(profile, args_override=args, logger=logger)
        item = {
            "args": args,
            "command": result.get("command"),
            "return_code": result.get("return_code"),
            "status": _replay_status(result),
            "file": result.get("file"),
            "line": result.get("line"),
            "runtime_output": _truncate_build_output(_runtime_output(result), max_lines=50, max_chars=4000),
        }
        items.append(item)
        if item["status"] != "pass":
            failed = True
    return {
        "status": "fail" if failed else "pass",
        "input_count": len(variants[:max_variants]),
        "items": items,
    }


def _run_regression_replay(profile: dict | None, max_inputs: int = 30, logger=None) -> dict[str, Any]:
    inputs = _discover_regression_inputs(profile, max_inputs=max_inputs)
    if not profile or not inputs:
        return {"status": "regression_unavailable", "input_count": 0, "items": []}
    base_args = [str(arg) for arg in profile.get("args", [])]
    if not base_args:
        return {"status": "regression_unavailable", "input_count": 0, "items": []}
    items = []
    failed = False
    for path in inputs[:max_inputs]:
        args = [path] + base_args[1:]
        result = run_profile_once(profile, args_override=args, logger=logger)
        item = {
            "args": args,
            "command": result.get("command"),
            "return_code": result.get("return_code"),
            "status": _replay_status(result),
            "file": result.get("file"),
            "line": result.get("line"),
            "runtime_output": _truncate_build_output(_runtime_output(result), max_lines=50, max_chars=4000),
        }
        items.append(item)
        if item["status"] != "pass":
            failed = True
    return {
        "status": "fail" if failed else "pass",
        "input_count": len(items),
        "items": items,
    }


def _run_primary_replay(profile: dict | None, logger=None) -> dict[str, Any]:
    if profile and profile.get("file"):
        if is_secbench_profile(profile):
            return run_secbench_repro_once(profile, logger=logger)
        return run_profile_once(profile, logger=logger)
    return_code, stdout, stderr = run_reproduce(profile)
    return {
        "status": True,
        "return_code": return_code,
        "error": "\n".join(part for part in [str(stdout or ""), str(stderr or "")] if part.strip()),
        "stdout": stdout,
        "stderr": stderr,
        "func": "N/A",
        "file": "N/A",
        "line": -1,
        "command": "arvo",
        "args": [],
    }


@logf(NAME, True)
def collect_patch_evidence(
    patch: dict,
    expected_file: str | None = None,
    expected_line: int | None = None,
    logger=None,
) -> dict[str, Any]:
    profile = patch.get("profile") if isinstance(patch.get("profile"), dict) else None
    bug_type_profile = patch.get("bug_type_profile") if isinstance(patch.get("bug_type_profile"), dict) else {}
    typed_angelic_evidence = patch.get("typed_angelic_evidence") if isinstance(patch.get("typed_angelic_evidence"), dict) else {}
    counterfactual_contract = patch.get("counterfactual_contract") if isinstance(patch.get("counterfactual_contract"), dict) else {}
    validation_obligations = list(
        counterfactual_contract.get("validation_obligations", [])
        or typed_angelic_evidence.get("validation_obligations", [])
        or bug_type_profile.get("validation_obligations", [])
        or []
    )
    tier_report = _empty_tier_report(profile)
    obligation_summary = _evaluate_validation_obligations(validation_obligations, tier_report, bug_type_profile)
    evidence = {
        "patch": patch,
        "expected_file": expected_file,
        "expected_line": expected_line,
        "profile": profile,
        "bug_type_profile": bug_type_profile,
        "typed_angelic_evidence": typed_angelic_evidence,
        "counterfactual_contract": counterfactual_contract,
        "validation_obligations": validation_obligations,
        "tier_report": tier_report,
        "obligation_summary": obligation_summary,
        "stage": "initial",
    }

    patches = patch.get("patches")
    if not patches:
        evidence["stage"] = "invalid_patch"
        evidence["failure"] = {
            "status": "apply_error",
            "message": "Invalid patch object provided.",
            "error_signature": "invalid_patch",
            "old_site_vs_new_site": "unknown",
            "blame_hint": "Patch payload is incomplete.",
            "recommended_next_actor": "patch",
        }
        return evidence

    project_root = str((profile or {}).get("src") or "").strip()
    if project_root:
        for item in patches:
            submitted_file = str(item.get("file") or "").strip()
            if submitted_file and not os.path.exists(submitted_file):
                suggested_file = None
                if not os.path.isabs(submitted_file):
                    absolute_candidate = os.path.normpath("/" + submitted_file.lstrip("/"))
                    if os.path.exists(absolute_candidate):
                        suggested_file = absolute_candidate
                suggestion = (
                    f" Use this existing absolute path instead: {suggested_file}."
                    if suggested_file
                    else " Use the exact absolute path returned by Source Hints or source tools."
                )
                evidence["stage"] = "apply_error"
                evidence["failure"] = {
                    "status": "apply_error",
                    "message": (
                        f"Patch file path does not exist: {submitted_file}. "
                        f"The current project root is {project_root}.{suggestion} "
                        "Do not remove the leading '/' or add the project name again."
                    ),
                    "error_signature": "patch_file_not_found",
                    "old_site_vs_new_site": "unknown",
                    "blame_hint": "The submitted filename is invalid; patch content was not applied.",
                    "recommended_next_actor": "patch",
                }
                return evidence

    if not file_apply_patches(patches):
        if logger:
            logger.error("Failed to apply patch")
        evidence["stage"] = "apply_error"
        evidence["failure"] = {
            "status": "apply_error",
            "message": "Failed to apply patch, please check the location of the patch",
            "error_signature": "apply_error",
            "old_site_vs_new_site": "unknown",
            "blame_hint": "Patch could not be applied, likely due to a stale location or malformed range.",
            "recommended_next_actor": "patch",
        }
        return evidence

    return_code, stdout, stderr = run_compile(profile)
    file_undo_patches(patches)
    evidence["compile"] = {"return_code": return_code, "stdout": stdout, "stderr": stderr}
    if return_code != 0:
        combined_output = "\n".join(part for part in [str(stdout or ""), str(stderr or "")] if part.strip())
        errors = _extract_compile_errors(combined_output)
        failure_lines = _extract_build_failure_lines(combined_output)
        if errors:
            error_text = "\n".join(errors)
        elif failure_lines:
            error_text = "\n".join(failure_lines)
        else:
            output_tail = _truncate_build_output(combined_output)
            error_text = (
                f"Build command exited non-zero (return code {return_code}) but no compiler/test failure line "
                f"was recognized. Output tail:\n{output_tail}"
            )
        blame_hint = (
            "Patch shape is not compilable; refine the edit before rethinking the hypothesis."
            if errors or failure_lines
            else "Build script failed (e.g. copy step). May be environmental (e.g. 'Text file busy')."
        )
        evidence["stage"] = "compile_error"
        evidence["failure"] = {
            "status": "compile_error",
            "message": f"Build failed during patch validation (return code {return_code}): \n```\n{error_text}\n```",
            "error_signature": "compile_error",
            "old_site_vs_new_site": "unknown",
            "blame_hint": blame_hint,
            "recommended_next_actor": "patch",
            "errors": errors or failure_lines or [error_text],
        }
        return evidence

    primary_result = _run_primary_replay(profile, logger=logger)
    evidence["primary_result"] = primary_result
    primary_return_code = int(primary_result.get("return_code", 1))
    primary_output = _runtime_output(primary_result)
    primary_has_sanitizer = _has_sanitizer_signature(primary_output)
    tier_report["tier1_original_poc"] = {
        "status": "pass" if primary_return_code == 0 and not primary_has_sanitizer else ("timeout" if primary_return_code == -66 else "fail"),
        "return_code": primary_return_code,
        "command": primary_result.get("command", ""),
    }
    evidence["obligation_summary"] = _evaluate_validation_obligations(validation_obligations, tier_report, bug_type_profile)
    if primary_return_code == -66:
        evidence["stage"] = "timeout"
        evidence["failure"] = {
            "status": "timeout",
            "message": "Program timed out, possibly due to an infinite loop.",
            "error_signature": "timeout",
            "old_site_vs_new_site": "unknown",
            "blame_hint": "Patch may introduce a loop or block normal termination.",
            "recommended_next_actor": "patch",
        }
        return evidence
    if primary_return_code != 0 or primary_has_sanitizer:
        error, frames = parse_sanitizer_output(primary_output, logger=logger)
        crash_site = _extract_crash_site(frames, logger=logger)
        site_relation = "unknown"
        recommended_next_actor = "patch"
        parsed_sanitizer = primary_has_sanitizer or bool(error and (frames or _has_sanitizer_signature(primary_output)))
        if primary_has_sanitizer and not error:
            error = "Sanitizer output detected during primary replay"
        blame_hint = (
            "Patch still triggers sanitizer output but the crash site is unknown; patch logic likely needs refinement."
            if parsed_sanitizer
            else "Runtime verification failed without sanitizer evidence."
        )

        def _record_runtime_failure(
            status: str,
            recommended_next_actor: str,
            blame_hint: str,
            message_prefix: str,
        ) -> dict[str, Any]:
            status, recommended_next_actor, blame_hint = _infer_replay_failure_status(
                patch, status, recommended_next_actor, blame_hint
            )
            evidence["stage"] = "runtime_failure"
            evidence["failure"] = {
                "status": status,
                "message": _format_runtime_failure_message(message_prefix, error, primary_output),
                "error_signature": error,
                "runtime_output": _truncate_build_output(primary_output, max_lines=30, max_chars=2000),
                "old_site_vs_new_site": site_relation,
                "blame_hint": blame_hint,
                "recommended_next_actor": recommended_next_actor,
                "crash_site": crash_site,
                "frames": frames or [],
            }
            return evidence

        if _same_site(expected_file, expected_line, crash_site):
            site_relation = "same_site"
            status = "same_site_crash"
            recommended_next_actor = "constraint"
            blame_hint = "Crash remains at the same site; the current constraint or guard is probably too weak."
            return _record_runtime_failure(
                status,
                recommended_next_actor,
                blame_hint,
                "Patch does not fix the crash",
            )
        elif crash_site is not None:
            site_relation = "new_site"
            status = "new_site_crash"
            recommended_next_actor = "debug"
            blame_hint = "Crash moved to a different site; revisit the root-cause hypothesis."
            return _record_runtime_failure(
                status,
                recommended_next_actor,
                blame_hint,
                "Patch does not fix the crash",
            )
        else:
            status = "weak_constraint" if parsed_sanitizer else "runtime_failure"
            recommended_next_actor = "constraint" if parsed_sanitizer else "patch"
            runtime_message, runtime_blame = _runtime_failure_without_sanitizer_message(
                primary_return_code,
                primary_output,
                bug_type_profile,
            )
            error = error or runtime_message
            fallback_runtime_blame = (
                "Runtime failure did not produce a sanitizer stack; classify using semantic evidence and raw program output."
                if parsed_sanitizer
                else runtime_blame
            )
            if parsed_sanitizer:
                return _record_runtime_failure(
                    status,
                    recommended_next_actor,
                    blame_hint,
                    "Patch does not fix the crash",
                )
            llm_runtime = None
            if primary_return_code != 0:
                llm_runtime = _judge_runtime_failure_with_llm(
                    patch=patch,
                    return_code=primary_return_code,
                    runtime_output=primary_output,
                    fallback_status=status,
                    fallback_next_actor=recommended_next_actor,
                    fallback_blame_hint=fallback_runtime_blame,
                )
            if llm_runtime:
                status = str(llm_runtime.get("status", status))
                recommended_next_actor = str(llm_runtime.get("recommended_next_actor", recommended_next_actor))
                blame_hint = str(llm_runtime.get("blame_hint", fallback_runtime_blame))
                error = str(llm_runtime.get("message", error))
                if not parsed_sanitizer and status == "pass":
                    tier_report["tier1_original_poc"] = {
                        "status": "pass_llm_nonzero",
                        "return_code": primary_return_code,
                        "command": primary_result.get("command", ""),
                        "note": "LLM verifier judged the original crash fixed despite non-zero program exit.",
                        "runtime_output": _truncate_build_output(primary_output, max_lines=12, max_chars=800),
                    }
                    evidence["runtime_verifier"] = llm_runtime
                    evidence["obligation_summary"] = _evaluate_validation_obligations(validation_obligations, tier_report, bug_type_profile)
                    if logger:
                        logger.info("Runtime LLM verifier accepted non-zero primary replay as crash-fixed: %s", error)
                    # Continue with variant/regression tiers instead of classifying this as a failed patch.
                    pass
                else:
                    status, recommended_next_actor, blame_hint = _infer_replay_failure_status(
                        patch, status, recommended_next_actor, blame_hint
                    )
                    evidence["stage"] = "runtime_failure"
                    if parsed_sanitizer:
                        message = _format_runtime_failure_message("Patch does not fix the crash", error, primary_output)
                    else:
                        message = _format_runtime_failure_message(
                            "Patch failed runtime verification without reproducing a sanitizer crash",
                            error,
                            primary_output,
                        )
                    evidence["failure"] = {
                        "status": status,
                        "message": message,
                        "error_signature": error,
                        "runtime_output": _truncate_build_output(primary_output, max_lines=30, max_chars=2000),
                        "old_site_vs_new_site": site_relation,
                        "blame_hint": blame_hint,
                        "recommended_next_actor": recommended_next_actor,
                        "crash_site": crash_site,
                        "frames": frames or [],
                    }
                    return evidence
            else:
                return _record_runtime_failure(
                    status,
                    recommended_next_actor,
                    blame_hint,
                    "Patch does not fix the crash"
                    if parsed_sanitizer
                    else "Patch failed runtime verification without reproducing a sanitizer crash",
                )

    variant_report = _run_variant_replay(profile, logger=logger)
    tier_report["tier2_variants"] = variant_report
    evidence["variant_report"] = variant_report
    evidence["obligation_summary"] = _evaluate_validation_obligations(validation_obligations, tier_report, bug_type_profile)
    if variant_report["status"] == "fail":
        failed_item = _first_failed_replay_item(variant_report)
        status, next_actor, blame_hint = _infer_replay_failure_status(
            patch,
            "overfit_poc",
            "constraint",
            "Constraint or patch shape is overfit to the original input; generalize the guard or repair earlier state.",
        )
        evidence["stage"] = "variant_failure"
        evidence["failure"] = {
            "status": status,
            "message": "Patch fixes the original PoC but fails on nearby replay inputs.",
            "error_signature": "overfit_poc",
            "old_site_vs_new_site": "fixed",
            "blame_hint": blame_hint,
            "recommended_next_actor": next_actor,
            "runtime_output": failed_item.get("runtime_output", ""),
            "replay_failure": failed_item,
        }
        return evidence

    regression_report = _run_regression_replay(profile, logger=logger)
    tier_report["tier3_regression"] = regression_report
    evidence["regression_report"] = regression_report
    evidence["obligation_summary"] = _evaluate_validation_obligations(validation_obligations, tier_report, bug_type_profile)
    if regression_report["status"] == "fail":
        failed_item = _first_failed_replay_item(regression_report)
        status, next_actor, blame_hint = _infer_replay_failure_status(
            patch,
            "semantic_regression",
            "patch",
            "Patch likely changes behavior too aggressively; choose a less invasive strategy or move the fix upstream.",
        )
        evidence["stage"] = "regression_failure"
        evidence["failure"] = {
            "status": status,
            "message": "Patch fixes the original PoC but breaks regression inputs.",
            "error_signature": "semantic_regression",
            "old_site_vs_new_site": "fixed",
            "blame_hint": blame_hint,
            "recommended_next_actor": next_actor,
            "runtime_output": failed_item.get("runtime_output", ""),
            "replay_failure": failed_item,
        }
        return evidence

    contract_gap, contract_gap_reason = _product_contract_repair_gap(patch)
    if contract_gap:
        evidence["stage"] = "contract_mismatch"
        evidence["failure"] = {
            "status": "contract_mismatch",
            "message": "Patch suppresses the observed failure but appears to repair only harness/support code rather than the product contract.",
            "error_signature": "contract_mismatch",
            "old_site_vs_new_site": "fixed",
            "blame_hint": contract_gap_reason,
            "recommended_next_actor": "patch",
            "residual_risk": "product_contract_not_repaired",
        }
        return evidence

    evidence["stage"] = "pass"
    return evidence


def judge_patch_evidence(evidence: dict[str, Any], logger=None) -> dict[str, Any]:
    patch = evidence.get("patch", {}) if isinstance(evidence.get("patch"), dict) else {}
    bug_type_profile = evidence.get("bug_type_profile", {}) if isinstance(evidence.get("bug_type_profile"), dict) else {}
    typed_angelic_evidence = evidence.get("typed_angelic_evidence", {}) if isinstance(evidence.get("typed_angelic_evidence"), dict) else {}
    validation_obligations = list(evidence.get("validation_obligations", []) or [])
    tier_report = evidence.get("tier_report", {}) if isinstance(evidence.get("tier_report"), dict) else {}
    obligation_summary = evidence.get("obligation_summary", {}) if isinstance(evidence.get("obligation_summary"), dict) else {}

    def finish(payload: dict[str, Any]) -> dict[str, Any]:
        feedback = dict(payload)
        feedback.setdefault("layer1_verdict", "")
        feedback.setdefault("direct_patch_assessment", {})
        details = feedback.get("details") if isinstance(feedback.get("details"), dict) else {}
        details.setdefault("tiers", tier_report)
        details.setdefault("bug_type_profile", bug_type_profile)
        details.setdefault("typed_angelic_evidence", typed_angelic_evidence)
        details.setdefault("validation_obligations", validation_obligations)
        details.setdefault("validation_obligation_status", obligation_summary)
        feedback["details"] = details

        repair_layer = str(patch.get("repair_layer", "layer2"))
        if repair_layer == "layer1":
            assessment = _classify_direct_patch_assessment(
                patch,
                status=str(feedback.get("status", "unknown")),
                tier_report=details.get("tiers", tier_report),
                obligation_summary=details.get("validation_obligation_status", obligation_summary),
                confidence=float(details.get("verification_confidence", 0.0) or 0.0),
                residual_risk=str(details.get("residual_risk", "") or ""),
                default_next_actor=str(feedback.get("recommended_next_actor", "layer2") or "layer2"),
                default_blame_hint=str(feedback.get("blame_hint", "") or ""),
            )
            feedback["layer1_verdict"] = assessment["verdict"]
            feedback["direct_patch_assessment"] = assessment
            feedback["recommended_next_actor"] = assessment["recommended_next_actor"]
            details["layer_verdict"] = assessment["verdict"]
            if str(feedback.get("status", "")) == "pass" and assessment["verdict"] == "weak":
                feedback["message"] = "Direct patch passed replay but requires Layer 2 validation."
            elif str(feedback.get("status", "")) == "pass" and assessment["verdict"] == "suspicious":
                feedback["message"] = "Direct patch suppresses the crash but still looks suspicious."
        return feedback

    failure = evidence.get("failure") if isinstance(evidence.get("failure"), dict) else None
    if failure:
        return finish(failure)

    confidence = _verification_confidence(tier_report, patch)
    residual_risks: list[str] = []
    if tier_report.get("tier3_regression", {}).get("status") == "regression_unavailable":
        residual_risks.append("regression_unavailable")
    repair_layer = str(patch.get("repair_layer", "layer2"))
    blame_hint = "No further iteration required."
    return finish({
        "status": "pass",
        "message": "Direct patch successfully verified." if repair_layer == "layer1" else "Patch successfully verified.",
        "error_signature": "",
        "old_site_vs_new_site": "fixed",
        "blame_hint": blame_hint,
        "recommended_next_actor": "done",
        "details": {
            "tiers": tier_report,
            "verification_confidence": confidence,
            "bug_type_profile": bug_type_profile,
            "typed_angelic_evidence": typed_angelic_evidence,
            "validation_obligations": validation_obligations,
            "validation_obligation_status": obligation_summary,
            "residual_risk": "; ".join(residual_risks),
            "repair_layer": repair_layer,
        },
    })


@logf(NAME, True)
def verify_patch_feedback(
    patch: dict,
    expected_file: str | None = None,
    expected_line: int | None = None,
    logger=None,
) -> dict[str, Any]:
    evidence = collect_patch_evidence(
        patch,
        expected_file=expected_file,
        expected_line=expected_line,
        logger=logger,
    )
    return judge_patch_evidence(evidence, logger=logger)


@logf(NAME, True)
def verify_patch(patch: dict, logger=None) -> Tuple[bool, str]:
    """
    Backward-compatible verifier that returns the legacy tuple.
    """
    feedback = verify_patch_feedback(
        patch,
        expected_file=patch.get("suspect_file"),
        expected_line=patch.get("suspect_line"),
        logger=logger,
    )
    return feedback["status"] == "pass", feedback["message"]
