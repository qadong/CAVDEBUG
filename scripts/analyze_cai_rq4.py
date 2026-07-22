#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


SSC_LABELS = {"Reference-equivalent", "Alternative secure"}
OVERFIT_LABELS = {"Overfitting/masking", "Crash-site mitigation", "Partial repair"}


def read_json_or_jsonl(path: Path | None) -> Any:
    if path is None:
        return None
    text = path.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return []
    if text[0] in "[{":
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def load_candidate_ids(path: Path | None) -> list[str] | None:
    if path is None:
        return None
    data = read_json_or_jsonl(path)
    ids: list[str] = []
    for item in data if isinstance(data, list) else [data]:
        if not isinstance(item, dict):
            continue
        instance_id = item.get("instance_id") or item.get("id") or item.get("tag")
        if instance_id:
            ids.append(str(instance_id))
    return ids


def load_instance_ids(path: Path | None) -> list[str] | None:
    if path is None:
        return None
    data = read_json_or_jsonl(path)
    ids: list[str] = []
    for item in data if isinstance(data, list) else [data]:
        if not isinstance(item, dict):
            continue
        instance_id = item.get("instance_id") or item.get("id") or item.get("tag")
        if instance_id:
            ids.append(str(instance_id))
    return ids


def load_ssc(path: Path | None) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    data = read_json_or_jsonl(path)
    if not data:
        return rows
    for item in data:
        if not isinstance(item, dict):
            continue
        instance_id = item.get("instance_id")
        verdict = item.get("verdict") or {}
        if not instance_id:
            continue
        label = verdict.get("label") if isinstance(verdict, dict) else None
        rows[str(instance_id)] = {
            "ssc_label": label or "",
            "counts_for_ssc": bool(verdict.get("counts_for_ssc")) if isinstance(verdict, dict) else False,
            "counts_for_overfit_rate": (
                bool(verdict.get("counts_for_overfit_rate")) if isinstance(verdict, dict) else False
            ),
        }
    return rows


def load_validation(path: Path | None) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    data = read_json_or_jsonl(path)
    if not data:
        return rows
    for item in data:
        if isinstance(item, dict) and item.get("instance_id"):
            rows[str(item["instance_id"])] = {
                "validation_success": bool(item.get("success")),
                "validation_reason": item.get("reason") or "",
            }
    return rows


def extract_submitted_contracts(trace_path: Path) -> list[dict[str, Any]]:
    trace = json.loads(trace_path.read_text(encoding="utf-8", errors="replace"))
    contracts: list[dict[str, Any]] = []
    for message in trace.get("history", []) if isinstance(trace, dict) else []:
        if not isinstance(message, dict):
            continue
        for tool_call in message.get("tool_calls", []) or []:
            function = tool_call.get("function") or {}
            name = function.get("name")
            if name not in {"submit_counterfactual_invariant", "submit_counterfactual_contract"}:
                continue
            arguments = function.get("arguments") or "{}"
            try:
                contract = json.loads(arguments)
            except json.JSONDecodeError:
                continue
            if isinstance(contract, dict):
                contract["_submit_tool"] = name
                contracts.append(contract)
    return contracts


def norm_text(*values: Any) -> str:
    return " ".join(str(value or "").lower().replace("-", "_") for value in values)


def cai_class(contract: dict[str, Any]) -> str:
    audit = contract.get("boundary_audit") if isinstance(contract.get("boundary_audit"), dict) else {}
    text = norm_text(
        contract.get("repair_class"),
        contract.get("bug_type"),
        contract.get("counterfactual_kind"),
        contract.get("evidence_family"),
        audit.get("derived_from"),
        contract.get("boundary_summary"),
        contract.get("repair_invariant"),
    )

    if re.search(r"\b(lifetime|ownership|use_after_free|double_free|alias|free|cleanup|cache)\b", text):
        return "Lifetime and ownership"
    if re.search(r"\b(type|tag|union|dispatch|api_contract|object_or_type)\b", text):
        return "Type and tag consistency"
    if re.search(r"\b(state|protocol|parser|format|transition|phase|fsm)\b", text):
        return "Protocol and state consistency"
    if re.search(r"\b(init|initiali[sz]ation|null|nonnull|uninitialized|ready|callback)\b", text):
        return "Initialization and nullness"
    if re.search(r"\b(integer|overflow|underflow|truncate|wrap|size_max|arithmetic)\b", text):
        return "Arithmetic safety"
    if re.search(
        r"\b(bound|boundary|capacity|buffer|heap_buffer|stack_buffer|out_of_bounds|extent|length|len|index|offset|"
        r"read|write|copy|allocation|alloc|memory_safety|crash_site_memory_capacity|crash_avoidance)\b",
        text,
    ):
        return "Boundary and capacity"
    return "Other/unknown"


def semantic_status(contract: dict[str, Any]) -> str:
    audit = contract.get("boundary_audit") if isinstance(contract.get("boundary_audit"), dict) else {}
    return str(contract.get("semantic_repair_status") or audit.get("semantic_repair_status") or "unknown")


def bool_rate(num: int, den: int) -> str:
    if den == 0:
        return "0.0"
    return f"{100.0 * num / den:.1f}"


def summarize(rows: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[str(row.get(key) or "unknown")].append(row)
    out: list[dict[str, Any]] = []
    for value, items in sorted(grouped.items(), key=lambda pair: (-len(pair[1]), pair[0])):
        n = len(items)
        validation = sum(1 for item in items if item.get("validation_success") == "true")
        ssc = sum(1 for item in items if item.get("counts_for_ssc") == "true")
        overfit = sum(1 for item in items if item.get("counts_for_overfit_rate") == "true")
        out.append(
            {
                key: value,
                "n": n,
                "validation_success": validation,
                "validation_success_rate": bool_rate(validation, n),
                "ssc": ssc,
                "ssc_rate": bool_rate(ssc, n),
                "overfit_num": overfit,
                "overfit_rate": bool_rate(overfit, n),
            }
        )
    return out


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fieldnames = list(rows[0].keys())
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def result_dir_for_instance(results_dir: Path, instance_id: str, result_prefix: str) -> Path:
    direct = results_dir / instance_id
    if direct.exists():
        return direct
    if result_prefix == "secbench" and "." in instance_id:
        repo, rest = instance_id.split(".", 1)
        secbench_dir = results_dir / f"secbench_{repo}_{rest}"
        if secbench_dir.exists():
            return secbench_dir
    return direct


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze CAI classes and repair outcomes for RQ4.")
    parser.add_argument("--results-dir", type=Path, default=Path("workspace/results"))
    parser.add_argument(
        "--result-prefix",
        choices=["none", "secbench"],
        default="none",
        help="Map benchmark instance ids to result directory names.",
    )
    parser.add_argument("--instance-jsonl", type=Path, help="Optional full benchmark instance JSON/JSONL.")
    parser.add_argument("--patch-json", type=Path, help="Optional candidate patch JSON/JSONL used to select instances.")
    parser.add_argument("--ssc-summary", type=Path, help="Semantic-security judge summary.json.")
    parser.add_argument("--validation-report", type=Path, help="Validation report JSONL.")
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()

    candidate_ids = load_candidate_ids(args.patch_json) or []
    candidate_id_set = set(candidate_ids)
    instance_ids = load_instance_ids(args.instance_jsonl)
    if instance_ids is None:
        instance_ids = candidate_ids or sorted(path.name for path in args.results_dir.iterdir() if path.is_dir())
    ssc = load_ssc(args.ssc_summary)
    validation = load_validation(args.validation_report)

    rows: list[dict[str, Any]] = []
    unreadable = []
    missing_cai = []
    for instance_id in instance_ids:
        has_candidate_patch = instance_id in candidate_id_set if candidate_id_set else True
        result_dir = result_dir_for_instance(args.results_dir, instance_id, args.result_prefix)
        trace_paths = sorted(
            (result_dir / "chat").glob("counterfactual-agent-hyp-*.json"),
            key=lambda path: path.stat().st_mtime,
        )
        contracts: list[tuple[Path, dict[str, Any]]] = []
        for trace_path in trace_paths:
            try:
                contracts.extend((trace_path, contract) for contract in extract_submitted_contracts(trace_path))
            except (OSError, json.JSONDecodeError) as exc:
                unreadable.append({"instance_id": instance_id, "path": str(trace_path), "error": str(exc)})
        if not contracts:
            missing_cai.append(instance_id)
            rows.append(
                {
                    "instance_id": instance_id,
                    "has_candidate_patch": str(has_candidate_patch).lower(),
                    "repair_outcome": "candidate_patch_available" if has_candidate_patch else "no_valid_crash_free_patch",
                    "cai_trace_count": len(trace_paths),
                    "selected_trace": "",
                    "cai_class": "No submitted CAI",
                    "repair_class": "",
                    "bug_type": "",
                    "counterfactual_kind": "",
                    "evidence_family": "",
                    "boundary_audit_derived_from": "",
                    "semantic_repair_status": "no_submitted_cai",
                    "only_sufficient_to_avoid_current_crash": "",
                    "explains_invalid_state_producer": "",
                    "stricter_semantic_contract": "",
                    "enforcement_roles": "",
                    "primary_enforcement_role": "",
                    "angelic_count": 0,
                    "demonic_count": 0,
                    "has_angelic_and_demonic": "false",
                    "validation_success": "false",
                    "validation_reason": "not_evaluated_no_candidate_patch" if not has_candidate_patch else "",
                    "ssc_label": "No valid patch" if not has_candidate_patch else "",
                    "counts_for_ssc": "false",
                    "counts_for_overfit_rate": "false",
                }
            )
            continue
        trace_path, contract = contracts[-1]
        audit = contract.get("boundary_audit") if isinstance(contract.get("boundary_audit"), dict) else {}
        ssc_row = ssc.get(instance_id, {})
        validation_row = validation.get(instance_id, {})
        angelic = contract.get("angelic_observations") if isinstance(contract.get("angelic_observations"), list) else []
        demonic = contract.get("demonic_observations") if isinstance(contract.get("demonic_observations"), list) else []
        roles = contract.get("enforcement_role_preference")
        if not isinstance(roles, list):
            roles = []
        rows.append(
            {
                "instance_id": instance_id,
                "has_candidate_patch": str(has_candidate_patch).lower(),
                "repair_outcome": "candidate_patch_available" if has_candidate_patch else "no_valid_crash_free_patch",
                "cai_trace_count": len(trace_paths),
                "selected_trace": str(trace_path),
                "cai_class": cai_class(contract),
                "repair_class": str(contract.get("repair_class") or ""),
                "bug_type": str(contract.get("bug_type") or ""),
                "counterfactual_kind": str(contract.get("counterfactual_kind") or ""),
                "evidence_family": str(contract.get("evidence_family") or ""),
                "boundary_audit_derived_from": str(audit.get("derived_from") or ""),
                "semantic_repair_status": semantic_status(contract),
                "only_sufficient_to_avoid_current_crash": str(
                    audit.get("only_sufficient_to_avoid_current_crash", "")
                ).lower(),
                "explains_invalid_state_producer": str(audit.get("explains_invalid_state_producer", "")).lower(),
                "stricter_semantic_contract": str(audit.get("stricter_semantic_contract", "")),
                "enforcement_roles": ";".join(str(role) for role in roles),
                "primary_enforcement_role": str(roles[0]) if roles else "",
                "angelic_count": len(angelic),
                "demonic_count": len(demonic),
                "has_angelic_and_demonic": str(bool(angelic and demonic)).lower(),
                "validation_success": str(bool(validation_row.get("validation_success"))).lower()
                if validation_row
                else "false",
                "validation_reason": str(
                    validation_row.get("validation_reason")
                    or ("not_evaluated_no_candidate_patch" if not has_candidate_patch else "")
                ),
                "ssc_label": str(ssc_row.get("ssc_label") or ("No valid patch" if not has_candidate_patch else "")),
                "counts_for_ssc": str(bool(ssc_row.get("counts_for_ssc"))).lower() if ssc_row else "false",
                "counts_for_overfit_rate": str(bool(ssc_row.get("counts_for_overfit_rate"))).lower()
                if ssc_row
                else "false",
            }
        )

    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(args.output_dir / "cai_instances.csv", rows)
    write_csv(args.output_dir / "cai_class_summary.csv", summarize(rows, "cai_class"))
    write_csv(args.output_dir / "semantic_status_summary.csv", summarize(rows, "semantic_repair_status"))
    write_csv(args.output_dir / "boundary_source_summary.csv", summarize(rows, "boundary_audit_derived_from"))
    write_csv(args.output_dir / "enforcement_role_summary.csv", summarize(rows, "primary_enforcement_role"))

    label_counts = Counter(row["ssc_label"] for row in rows)
    metadata = {
        "candidate_instances": len(candidate_ids),
        "total_instances": len(instance_ids),
        "instances_without_candidate_patch": sorted(set(instance_ids) - candidate_id_set) if candidate_id_set else [],
        "instances_with_cai": sum(1 for row in rows if row.get("cai_class") != "No submitted CAI"),
        "missing_cai": missing_cai,
        "unreadable_traces": unreadable,
        "ssc_label_counts": dict(label_counts),
        "outputs": {
            "instances": str(args.output_dir / "cai_instances.csv"),
            "class_summary": str(args.output_dir / "cai_class_summary.csv"),
            "semantic_status_summary": str(args.output_dir / "semantic_status_summary.csv"),
            "boundary_source_summary": str(args.output_dir / "boundary_source_summary.csv"),
            "enforcement_role_summary": str(args.output_dir / "enforcement_role_summary.csv"),
        },
    }
    (args.output_dir / "summary.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    print(
        f"analyzed {len(rows)}/{len(instance_ids)} instances; candidate patches {len(candidate_ids)}; "
        f"missing {len(missing_cai)}; unreadable {len(unreadable)}; output {args.output_dir}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
