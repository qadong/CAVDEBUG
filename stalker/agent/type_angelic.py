from __future__ import annotations

import re
from typing import Any


TYPE_SPECS: dict[str, dict[str, Any]] = {
    "out_of_bounds": {
        "display_name": "out-of-bounds access",
        "signals": ["heap-buffer-overflow", "stack-buffer-overflow", "global-buffer-overflow", "oob", "out of bounds"],
        "angelic_shape": "bounds_value",
        "debug_hint": (
            "Look for typed angelic evidence as bounds-preserving values or relations: idx < len, offset + size <= capacity, "
            "ptr within [base, end), remaining >= access_size. Prefer intervention slots at length parsing, index/offset computation, "
            "loop bounds, and API boundaries before the crash access."
        ),
        "constraint_hint": (
            "Prefer relational constraints between index/offset/size/base/end variables over hardcoded constants. "
            "Model the safe condition as a boundary invariant, not a PoC-specific literal threshold."
        ),
        "patch_hint": (
            "Prefer fixing length parsing, offset computation, loop bounds, or pre-access guards that encode the true boundary relation. "
            "Avoid overfitting to the observed object size or a magic bound from the current PoC."
        ),
        "repair_locations": ["input length parsing", "index/offset computation", "loop boundary", "access precondition", "API boundary"],
        "forbidden_patch_patterns": ["hardcoded_poc_specific_bound", "crash_site_guard_only"],
        "validation_obligations": ["original POC passes", "ASan clean", "boundary-neighbor values checked"],
        "spec_text": "Access must remain within the destination object's valid bounds.",
    },
    "integer_overflow": {
        "display_name": "integer overflow / size overflow",
        "signals": ["signed integer overflow", "integer overflow", "wraparound", "size overflow"],
        "angelic_shape": "arithmetic_range",
        "debug_hint": (
            "Look for typed angelic evidence as arithmetic preconditions: a <= MAX - b, count <= SIZE_MAX / elem_size, "
            "offset <= capacity - size. Intervene before the overflowing arithmetic or before allocation/copy size is consumed."
        ),
        "constraint_hint": (
            "Prefer arithmetic range relations that prevent wraparound and keep downstream allocation/access consistent. "
            "Do not reduce the problem to a single PoC-specific count unless the code truly has a fixed specification."
        ),
        "patch_hint": (
            "Prefer overflow checks before size computation, allocation, or copy/write. Keep the arithmetic invariant and downstream "
            "buffer sizing in sync. Avoid simply widening a type unless it fixes the actual target-size semantics."
        ),
        "repair_locations": ["arithmetic precondition", "allocation sizing", "copy/write size check"],
        "forbidden_patch_patterns": ["poc_specific_count_clamp", "type_widen_only_without_contract_fix"],
        "validation_obligations": ["original POC passes", "UBSan/ASan clean", "allocation/access consistency maintained"],
        "spec_text": "Arithmetic used for sizing or indexing must not overflow before downstream allocation or access.",
    },
    "null_dereference": {
        "display_name": "null dereference",
        "signals": ["null pointer", "null dereference", "addr 0x0", "load of null", "store to null"],
        "angelic_shape": "guard_or_pointer_state",
        "debug_hint": (
            "Look for typed angelic evidence as pointer-state or contract evidence: pointer becomes non-null, "
            "caller avoids passing null, or an early guard rejects the invalid state. Examine initialization paths, caller contracts, "
            "and error-handling branches before the dereference."
        ),
        "constraint_hint": (
            "Model the safe condition as a pointer/contract invariant rather than a raw branch skip. "
            "Distinguish between legitimate nullable API paths and paths that require initialization before use."
        ),
        "patch_hint": (
            "Prefer caller checks, callee entry validation, missing initialization, or state restoration before using the pointer. "
            "Use a crash-site null guard only if it encodes the true API contract and not just a symptom mask."
        ),
        "repair_locations": ["caller argument validation", "callee API boundary", "initialization path", "error propagation path"],
        "forbidden_patch_patterns": ["dummy_pointer_fabrication", "crash_site_guard_only"],
        "validation_obligations": ["original POC passes", "null contract respected on all paths"],
        "spec_text": "Pointers must be initialized and satisfy the API's nullability contract before dereference.",
    },
    "invalid_pointer": {
        "display_name": "invalid pointer dereference",
        "signals": ["invalid access", "segv", "bus error", "wild pointer", "invalid pointer"],
        "angelic_shape": "pointer_state_or_provenance",
        "debug_hint": (
            "Look for typed angelic evidence as pointer provenance restoration: pointer reassigned to a valid base, "
            "offset corrected, or object lifetime/source repaired. Focus on pointer source, pointer arithmetic, and object ownership."
        ),
        "constraint_hint": (
            "Prefer pointer/base/end/provenance relations over literal pointer values. Avoid using concrete addresses as specifications."
        ),
        "patch_hint": (
            "Prefer repairing pointer source, offset validation, or object provenance before the dereference. "
            "Do not overfit to the current concrete address or only guard the last dereference site."
        ),
        "repair_locations": ["pointer source", "pointer arithmetic", "object provenance boundary", "earlier corruption site"],
        "forbidden_patch_patterns": ["concrete_address_literalization", "crash_site_guard_only"],
        "validation_obligations": ["original POC passes", "ASan clean", "pointer provenance preserved"],
        "spec_text": "Pointers must refer to valid live objects and remain within their legal provenance and bounds.",
    },
    "use_after_free": {
        "display_name": "use-after-free",
        "signals": ["heap-use-after-free", "use after free"],
        "angelic_shape": "temporal_lifetime",
        "debug_hint": (
            "Look for typed angelic evidence as lifetime/ownership interventions: delay or remove a free, null a stale alias, "
            "or restore ownership transfer order. Examine the free site, alias propagation, and use site ordering."
        ),
        "constraint_hint": (
            "Model the safe condition as a temporal ownership invariant such as object remains alive until last use or aliases are invalidated after release."
        ),
        "patch_hint": (
            "Prefer repairing ownership transfer, freeing order, alias invalidation, or object lifetime boundaries. "
            "Avoid same-site guards that merely skip one use while leaving stale ownership intact."
        ),
        "repair_locations": ["free site", "ownership transfer", "use-site predecessor path", "cleanup block", "refcount/lifetime manager"],
        "forbidden_patch_patterns": ["skip_use_only_without_lifetime_fix", "delete_release_without_ownership_reason"],
        "validation_obligations": ["original POC passes", "ASan clean", "LSan clean", "alias set reviewed"],
        "spec_text": "Object use must happen before release, and ownership/lifetime must cover every reachable use.",
    },
    "double_free": {
        "display_name": "double free",
        "signals": ["double-free", "attempting double-free"],
        "angelic_shape": "event_or_ownership",
        "debug_hint": (
            "Look for typed angelic evidence as event-order or ownership interventions: skip one cleanup path, reset ownership after first free, "
            "or ensure cleanup runs exactly once."
        ),
        "constraint_hint": (
            "Prefer ownership and cleanup-state invariants over raw branch suppression. Model who owns release responsibility and when it is consumed."
        ),
        "patch_hint": (
            "Prefer fixing first-free/second-free ownership boundaries, cleanup flags, or transfer semantics. "
            "Avoid hiding the second free without addressing why the same object is releasable twice."
        ),
        "repair_locations": ["ownership transfer site", "first free site", "second free site", "cleanup block", "destructor/release helper"],
        "forbidden_patch_patterns": ["global_already_freed_flag", "skip_second_free_only", "single_alias_nullification_only"],
        "validation_obligations": ["original POC passes", "ASan clean", "LSan clean", "no leak regression"],
        "spec_text": "Each owned resource must be released at most once under a consistent ownership protocol.",
    },
    "invalid_free": {
        "display_name": "invalid free",
        "signals": ["invalid-free", "bad-free"],
        "angelic_shape": "allocation_origin_or_ownership",
        "debug_hint": (
            "Look for typed angelic evidence as allocation-origin or ownership interventions: free only heap roots, not interior pointers, "
            "or correct which component owns deallocation."
        ),
        "constraint_hint": (
            "Prefer invariants about allocation origin, ownership, and pointer normalization instead of literal address matching."
        ),
        "patch_hint": (
            "Prefer repairing the pointer source, deallocation target, or ownership contract. "
            "Avoid turning off free blindly unless the ownership model justifies it."
        ),
        "repair_locations": ["free call site", "pointer source", "ownership boundary", "API contract"],
        "forbidden_patch_patterns": ["delete_free_without_ownership_reason", "free_offset_pointer"],
        "validation_obligations": ["original POC passes", "ASan clean", "LSan clean"],
        "spec_text": "Only heap-owned base pointers held by the current owner may be released.",
    },
    "uninitialized_use": {
        "display_name": "uninitialized use",
        "signals": ["use-of-uninitialized-value", "memorysanitizer", "uninitialized"],
        "angelic_shape": "initialization_state",
        "debug_hint": (
            "Look for typed angelic evidence as initialization-state repairs: memset/field initialization/default value restoration "
            "before the value enters control flow, memory access, or API output. Focus on constructors, init paths, partial clearing, and error branches."
        ),
        "constraint_hint": (
            "Prefer constraints that express initialization coverage or state freshness rather than literal proxy values that only widen a side effect."
        ),
        "patch_hint": (
            "Prefer fixing initialization paths, constructor/default-state coverage, and state refresh sites before use. "
            "Avoid literalizing proxy values that only make a memset or branch happen in the current PoC."
        ),
        "repair_locations": ["constructor/init function", "error path defaulting", "field assignment point", "state refresh site"],
        "forbidden_patch_patterns": ["use_site_default_fill_without_init_fix", "literal_constraint_clamp_without_state_repair"],
        "validation_obligations": ["original POC passes", "MSan/Valgrind clean", "all construction paths initialized"],
        "spec_text": "Required object fields must be initialized to valid state before any read, branch, or API use.",
    },
    "assertion_failure": {
        "display_name": "assertion failure / abort",
        "signals": ["assertion failed", "sigabrt", "abort"],
        "angelic_shape": "invariant_or_state_machine",
        "debug_hint": (
            "Look for typed angelic evidence as invariant-restoring state or event sequence changes. "
            "Trace which state-machine transition or caller contract was violated before the assertion."
        ),
        "constraint_hint": (
            "Prefer state-machine or contract relations over simple branch suppression. The safe condition should explain why the assertion should hold."
        ),
        "patch_hint": (
            "Prefer repairing the earlier state transition, contract check, or invalid input path that should preserve the invariant. "
            "Avoid removing the assertion or bypassing the abort unless it is provably a false positive."
        ),
        "repair_locations": ["state transition", "caller contract", "input validation", "error path gate"],
        "forbidden_patch_patterns": ["remove_assert_without_invariant_repair", "abort_suppression_only"],
        "validation_obligations": ["original POC passes", "assertion invariant restored", "regression tests pass"],
        "spec_text": "Program state must satisfy the asserted invariant before the protected operation executes.",
    },
    "divide_by_zero": {
        "display_name": "divide by zero / arithmetic fault",
        "signals": ["divide by zero", "sigfpe", "floating point exception"],
        "angelic_shape": "scalar_guard",
        "debug_hint": (
            "Look for typed angelic evidence as scalar preconditions such as denominator != 0 or legal arithmetic mode/value ranges. "
            "Trace where the denominator or arithmetic parameter was derived."
        ),
        "constraint_hint": (
            "Prefer direct arithmetic preconditions and caller contracts. Avoid constants unless they come from a real format or protocol specification."
        ),
        "patch_hint": (
            "Prefer input validation, parameter normalization, or earlier guard checks before the division site. "
            "A local guard is acceptable if it matches the real arithmetic contract."
        ),
        "repair_locations": ["parameter parsing", "division precondition", "caller contract", "special-case semantics site"],
        "forbidden_patch_patterns": ["replace_zero_with_one", "hardcoded_denominator_constant"],
        "validation_obligations": ["original POC passes", "UBSan clean", "zero-input semantics checked"],
        "spec_text": "Arithmetic preconditions must forbid or correctly special-case zero denominators before division.",
    },
    "stack_overflow": {
        "display_name": "stack overflow / recursion crash",
        "signals": ["stack-overflow", "stack overflow", "recursion"],
        "angelic_shape": "control_or_resource_bound",
        "debug_hint": (
            "Look for typed angelic evidence as recursion depth or loop termination interventions: stop condition, input depth bound, or bounded allocation."
        ),
        "constraint_hint": (
            "Prefer control-flow or resource-bound invariants over literal depth constants from the current PoC."
        ),
        "patch_hint": (
            "Prefer repairing recursion termination, loop progress, or input depth limits. Avoid arbitrary depth caps unless the API truly specifies them."
        ),
        "repair_locations": ["recursion entry", "base case", "input nesting limit", "large stack allocation site"],
        "forbidden_patch_patterns": ["poc_specific_depth_cap", "crash_site_only_guard"],
        "validation_obligations": ["original POC passes", "termination/base-case reached", "no unbounded recursion remains"],
        "spec_text": "Control flow must ensure recursion/stack consumption remains bounded and base cases are reachable.",
    },
    "heap_corruption_later_crash": {
        "display_name": "heap corruption with later crash",
        "signals": ["heap corruption", "malloc crash", "corrupted", "allocator"],
        "angelic_shape": "backward_sliced_bounds_or_lifetime",
        "debug_hint": (
            "Treat the crash site as potentially far from the root cause. Look for earlier writes, frees, or ownership mistakes that corrupt allocator state. "
            "Use backward slicing in the call chain and focus on the earliest writable state that changes later heap behavior."
        ),
        "constraint_hint": (
            "Prefer upstream relations about writes, bounds, or lifetime. Do not use the allocator crash site as the primary semantic anchor."
        ),
        "patch_hint": (
            "Prefer repairing the earlier corrupting write or lifetime mistake, not the later malloc/free symptom site."
        ),
        "repair_locations": ["first bad write", "size/offset computation", "lifetime/ownership event", "input-length parser"],
        "forbidden_patch_patterns": ["allocator_site_guard_only", "malloc_free_symptom_patch"],
        "validation_obligations": ["original POC passes", "ASan clean", "first bad access identified or strongly approximated"],
        "spec_text": "The first corrupting write or temporal violation must be eliminated rather than masking a later allocator crash.",
    },
    "data_race": {
        "display_name": "data race / concurrency crash",
        "signals": ["threadsanitizer", "data race", "race"],
        "angelic_shape": "synchronization_or_event_order",
        "debug_hint": (
            "Look for typed angelic evidence as ordering or synchronization changes: serialize access, hold a lock, or preserve happens-before edges."
        ),
        "constraint_hint": (
            "Prefer event-order or ownership constraints over scalar values. The safe condition should describe synchronization, not a lucky timing constant."
        ),
        "patch_hint": (
            "Prefer repairing lock boundaries, atomic ordering, or check-use atomicity. Avoid overfitting to one observed schedule."
        ),
        "repair_locations": ["shared access", "critical section boundary", "check-use pair", "lifetime/destruction synchronization"],
        "forbidden_patch_patterns": ["schedule_specific_timing_hack", "ad_hoc_sleep_based_fix"],
        "validation_obligations": ["TSan clean if available", "no deadlock regression", "shared-state invariant preserved"],
        "spec_text": "Shared-state accesses must satisfy the intended synchronization and happens-before protocol.",
    },
    "resource_leak": {
        "display_name": "resource leak / eventual release failure",
        "signals": ["leaksanitizer", "resource exhaustion", "timeout", "leak"],
        "angelic_shape": "lifecycle_or_eventual_release",
        "debug_hint": (
            "Look for typed angelic evidence as release/cleanup events on success and error paths. Focus on ownership transfer, cleanup blocks, and destructors."
        ),
        "constraint_hint": (
            "Prefer lifecycle and eventual-release invariants over single-path branch hacks."
        ),
        "patch_hint": (
            "Prefer repairing cleanup/error paths, ownership transfer, or destructor coverage. Avoid disabling allocations or short-circuiting work merely to avoid the leak in one path."
        ),
        "repair_locations": ["error path cleanup", "central cleanup block", "ownership transfer site", "destructor/RAII wrapper"],
        "forbidden_patch_patterns": ["skip_work_to_avoid_leak", "delete_release_without_ownership_reason"],
        "validation_obligations": ["original POC passes", "LSan clean", "normal and error paths release resources"],
        "spec_text": "Owned resources must eventually be released on every exit path unless ownership is explicitly transferred.",
    },
    "unknown": {
        "display_name": "unknown crash type",
        "signals": [],
        "angelic_shape": "generic_state_or_relation",
        "debug_hint": (
            "Look for the smallest typed intervention that turns the failing execution safe: scalar, relation, pointer-state, initialization-state, ownership event, or state-machine step."
        ),
        "constraint_hint": (
            "Prefer relations and invariants over concrete values. Use the crash report and debug summary to infer whether the true evidence is about bounds, initialization, ownership, or state transitions."
        ),
        "patch_hint": (
            "Prefer repairing the earliest invariant-restoring location in the causal chain and avoid overfitting to the current PoC's concrete values or exact crash site."
        ),
        "repair_locations": ["earliest invariant-restoring site"],
        "forbidden_patch_patterns": ["poc_specific_branch", "crash_site_guard_only"],
        "validation_obligations": ["original POC passes", "sanitizer output clean if available"],
        "spec_text": "Restore the earliest program invariant whose violation leads to the observed crash.",
    },
}


def _normalize_text(*parts: Any) -> str:
    return " ".join(str(part or "") for part in parts).lower()


def _classify_bug_type_from_text(text: str) -> str:
    bug_type = "unknown"
    if any(tok in text for tok in ("heap-use-after-free", "use after free")):
        bug_type = "use_after_free"
    elif any(tok in text for tok in ("attempting double-free", "double-free")):
        bug_type = "double_free"
    elif any(tok in text for tok in ("invalid-free", "bad-free")):
        bug_type = "invalid_free"
    elif any(tok in text for tok in ("use-of-uninitialized-value", "memorysanitizer", "uninitialized")):
        bug_type = "uninitialized_use"
    elif any(tok in text for tok in ("signed integer overflow", "integer overflow", "wraparound", "size overflow")):
        bug_type = "integer_overflow"
    elif any(tok in text for tok in ("divide by zero", "sigfpe", "floating point exception")):
        bug_type = "divide_by_zero"
    elif any(tok in text for tok in ("assertion failed", "sigabrt", "abort")):
        bug_type = "assertion_failure"
    elif any(tok in text for tok in ("threadsanitizer", "data race")):
        bug_type = "data_race"
    elif any(tok in text for tok in ("leaksanitizer", "resource exhaustion")):
        bug_type = "resource_leak"
    elif any(tok in text for tok in ("stack-overflow", "stack overflow", "recursion")):
        bug_type = "stack_overflow"
    elif any(tok in text for tok in ("heap corruption", "malloc crash", "corrupted allocator", "allocator corruption")):
        bug_type = "heap_corruption_later_crash"
    elif any(tok in text for tok in ("heap-buffer-overflow", "stack-buffer-overflow", "global-buffer-overflow", "out of bounds", "oob")):
        bug_type = "out_of_bounds"
    elif any(tok in text for tok in ("null pointer", "null dereference", "load of null", "store to null")) or re.search(r"\b0x0+\b", text):
        bug_type = "null_dereference"
    elif "segv" in text or "sigsegv" in text or "bus error" in text or "invalid access" in text:
        bug_type = "invalid_pointer"
    return bug_type


def _root_cause_override(text: str) -> str | None:
    overflow_phrases = (
        "buffer overflow",
        "heap buffer overflow",
        "heap-buffer-overflow",
        "stack-buffer-overflow",
        "global-buffer-overflow",
        "out of bounds",
        "oversized copy",
        "copies more than",
        "copying more than",
        "exceeds max",
        "exceeds capacity",
        "beyond the buffer",
        "overflowing the",
    )
    if any(phrase in text for phrase in overflow_phrases):
        if "memcpy" in text or "memmove" in text or "memset" in text or "copy" in text or "write" in text:
            return "out_of_bounds"
    if any(tok in text for tok in ("use after free", "heap-use-after-free")):
        return "use_after_free"
    if any(tok in text for tok in ("double-free", "attempting double-free")):
        return "double_free"
    if any(tok in text for tok in ("invalid-free", "bad-free", "free offset pointer")):
        return "invalid_free"
    if any(tok in text for tok in ("use-of-uninitialized-value", "memorysanitizer", "uninitialized")):
        return "uninitialized_use"
    return None


def _selective_generalization_for(
    bug_type: str,
    angelic_shape: str,
    text: str,
) -> dict[str, Any]:
    lowered = str(text or "").lower()
    operational_tokens = {
        "allocation": ("alloc", "malloc", "calloc", "realloc", "sizeof", "extent", "capacity"),
        "read_size": ("read size", "copy size", "memcpy", "memmove", "fread", "read ", "bytes", "sizeof"),
        "initialization": ("initialize", "initializ", "memset", "zero", "constructor", "uninitialized"),
        "lifetime": ("free", "release", "ownership", "lifetime", "use after free", "double-free", "cleanup"),
        "state_transition": ("state transition", "state machine", "flag", "transition", "restore", "update state"),
    }
    operational_bug_types = {
        "use_after_free": "operational_lifetime",
        "double_free": "operational_lifetime",
        "invalid_free": "operational_lifetime",
        "uninitialized_use": "operational_initialization",
        "assertion_failure": "operational_state_transition",
        "data_race": "operational_state_transition",
        "resource_leak": "operational_lifetime",
    }
    predicate_bug_types = {
        "out_of_bounds": "predicate_bounds",
        "integer_overflow": "predicate_arithmetic",
        "null_dereference": "predicate_state",
        "invalid_pointer": "predicate_pointer",
        "divide_by_zero": "predicate_arithmetic",
        "stack_overflow": "predicate_state",
        "heap_corruption_later_crash": "predicate_bounds",
    }

    if bug_type in operational_bug_types:
        kind = operational_bug_types[bug_type]
        return {
            "evidence_family": "operational",
            "evidence_kind": kind,
            "generalization_target": "repair_intent",
            "constraint_required": False,
            "reason": f"{bug_type} evidence usually describes a program action or state transition.",
        }

    if any(token in lowered for token in operational_tokens["allocation"]):
        return {
            "evidence_family": "operational",
            "evidence_kind": "operational_allocation_size",
            "generalization_target": "repair_intent",
            "constraint_required": False,
            "reason": "Allocation or sizeof evidence is an operational size/layout repair, not a scalar guard.",
        }
    if any(token in lowered for token in operational_tokens["read_size"]):
        return {
            "evidence_family": "operational",
            "evidence_kind": "operational_read_size",
            "generalization_target": "repair_intent",
            "constraint_required": False,
            "reason": "Read/copy-size evidence should repair the operation's byte extent directly.",
        }
    if any(token in lowered for token in operational_tokens["initialization"]):
        return {
            "evidence_family": "operational",
            "evidence_kind": "operational_initialization",
            "generalization_target": "repair_intent",
            "constraint_required": False,
            "reason": "Initialization evidence should repair the missing state setup directly.",
        }
    if any(token in lowered for token in operational_tokens["lifetime"]):
        return {
            "evidence_family": "operational",
            "evidence_kind": "operational_lifetime",
            "generalization_target": "repair_intent",
            "constraint_required": False,
            "reason": "Lifetime or ownership evidence should repair ownership semantics directly.",
        }
    if bug_type not in predicate_bug_types and any(token in lowered for token in operational_tokens["state_transition"]):
        return {
            "evidence_family": "operational",
            "evidence_kind": "operational_state_transition",
            "generalization_target": "repair_intent",
            "constraint_required": False,
            "reason": "State-machine evidence should restore the missing transition directly.",
        }

    kind = predicate_bug_types.get(bug_type, "predicate_state")
    return {
        "evidence_family": "predicate",
        "evidence_kind": kind,
        "generalization_target": "constraint",
        "constraint_required": True,
        "reason": f"{angelic_shape} evidence can be generalized as a runtime predicate.",
    }


def infer_bug_type_profile(
    profile: dict[str, Any] | Any | None = None,
    reproduce_result: dict[str, Any] | None = None,
    suspect_object: dict[str, Any] | None = None,
    debug_summary: str = "",
    function_body: str = "",
    error_text: str = "",
    classification_mode: str = "root_cause",
) -> dict[str, Any]:
    profile_dict = profile if isinstance(profile, dict) else getattr(profile, "__dict__", {}) or {}
    surface_text = _normalize_text(
        error_text,
        profile_dict.get("error", ""),
        profile_dict.get("asan_type", ""),
        profile_dict.get("bug_type", ""),
        (reproduce_result or {}).get("error", ""),
        (reproduce_result or {}).get("stderr", ""),
        (reproduce_result or {}).get("stdout", ""),
    )
    root_cause_text = _normalize_text(
        debug_summary,
        function_body[:1200],
        suspect_object or {},
    )
    if classification_mode == "surface":
        text = surface_text
        bug_type = _classify_bug_type_from_text(text)
    else:
        text = _normalize_text(surface_text, root_cause_text)
        bug_type = _classify_bug_type_from_text(text)
        override = _root_cause_override(root_cause_text)
        if override:
            bug_type = override

    spec = TYPE_SPECS[bug_type]
    evidence_text = _normalize_text(
        debug_summary,
        function_body[:1200],
        (suspect_object or {}).get("debug_summary", ""),
        (reproduce_result or {}).get("error", ""),
        error_text,
    )
    selective = _selective_generalization_for(bug_type, spec["angelic_shape"], evidence_text)
    return {
        "bug_type": bug_type,
        "classification_mode": classification_mode,
        "display_name": spec["display_name"],
        "angelic_shape": spec["angelic_shape"],
        **selective,
        "signals": list(spec["signals"]),
        "debug_hint": spec["debug_hint"],
        "constraint_hint": spec["constraint_hint"],
        "patch_hint": spec["patch_hint"],
        "repair_locations": list(spec.get("repair_locations", [])),
        "forbidden_patch_patterns": list(spec.get("forbidden_patch_patterns", [])),
        "validation_obligations": list(spec.get("validation_obligations", [])),
        "spec_text": str(spec.get("spec_text", "")),
        "classification_basis": text[:600],
    }


def build_stage_prompt_overlay(stage: str, profile: dict[str, Any]) -> str:
    if not profile:
        return ""
    bug_type = profile.get("bug_type", "unknown")
    display = profile.get("display_name", bug_type.replace("_", " "))
    angelic_shape = profile.get("angelic_shape", "generic_state_or_relation")
    hint_key = {
        "debug": "debug_hint",
        "constraint": "constraint_hint",
        "patch": "patch_hint",
    }.get(stage, "patch_hint")
    hint = str(profile.get(hint_key, "")).strip()
    if not hint:
        return ""
    return (
        "\n\n"
        f"**Typed Angelic Evidence Profile ({stage})**\n"
        f"- Classified bug type: `{bug_type}` ({display})\n"
        f"- Target angelic evidence shape: `{angelic_shape}`\n"
        f"- Stage guidance: {hint}\n"
    )


def build_typed_angelic_evidence(
    bug_type_profile: dict[str, Any],
    suspect_object: dict[str, Any] | None,
    angelic_values: list,
    demonic_values: list,
    trace_pairs: list[dict[str, Any]] | None = None,
    minimal_deltas: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    trace_pairs = trace_pairs or []
    minimal_deltas = minimal_deltas or []
    bug_type = bug_type_profile.get("bug_type", "unknown")
    display_name = bug_type_profile.get("display_name", bug_type.replace("_", " "))
    angelic_shape = bug_type_profile.get("angelic_shape", "generic_state_or_relation")
    spec_text = bug_type_profile.get("spec_text", "")
    selective = _selective_generalization_for(
        str(bug_type),
        str(angelic_shape),
        _normalize_text(
            bug_type_profile.get("classification_basis", ""),
            (suspect_object or {}).get("debug_summary", ""),
            trace_pairs[:2],
            minimal_deltas[:2],
        ),
    )
    demonic_trace_summary = {
        "bug_type": bug_type,
        "display_name": display_name,
        "unsafe_examples": [str(v) for v in demonic_values[:4]],
        "trace_pair_count": len(trace_pairs),
        "minimal_delta_count": len(minimal_deltas),
        "focus_variables": list((suspect_object or {}).get("variable_names", [])[:4]),
    }
    if trace_pairs:
        first = trace_pairs[0]
        demonic_trace_summary["first_outcome"] = first.get("outcome", {})
        demonic_trace_summary["first_path_delta"] = first.get("path_delta", {})
    validated_examples: list[dict[str, Any]] = []
    for value in angelic_values[:5]:
        validated_examples.append(
            {
                "raw_value": value,
                "evidence_shape": angelic_shape,
                "effect_summary": f"Counterfactual intervention of shape `{angelic_shape}` turned the failing execution safe.",
            }
        )
    if not validated_examples and minimal_deltas:
        for delta in minimal_deltas[:3]:
            validated_examples.append(
                {
                    "raw_value": delta.get("intervention", {}),
                    "evidence_shape": angelic_shape,
                    "effect_summary": "Minimal path delta associated with safe execution.",
                }
            )
    return {
        "bug_type": bug_type,
        "angelic_type": angelic_shape,
        **selective,
        "display_name": display_name,
        "demonic_trace_summary": demonic_trace_summary,
        "validated_angelic_examples": validated_examples,
        "generalized_spec": {
            "type": f"{bug_type}_repair_spec",
            "text": spec_text,
        },
        "repair_locations": list(bug_type_profile.get("repair_locations", [])),
        "forbidden_patch_patterns": list(bug_type_profile.get("forbidden_patch_patterns", [])),
        "validation_obligations": list(bug_type_profile.get("validation_obligations", [])),
    }
