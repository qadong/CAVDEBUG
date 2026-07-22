#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any


def load_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            return json.load(f)
    except Exception:
        return None


def infer_failure(meta: dict, report: dict | None) -> str:
    if report and isinstance(report.get("items"), list) and report["items"]:
        last = report["items"][-1]
        status = last.get("status") or last.get("error_signature")
        if status:
            return str(status)
    failure = meta.get("failure") or {}
    if failure.get("reason"):
        return str(failure["reason"])
    if meta.get("patch"):
        return "pass"
    if meta.get("reproduced") is False:
        return "not_reproduced"
    return "unknown"


def summarize_result_dir(result_dir: Path) -> dict[str, Any]:
    meta = load_json(result_dir / "meta.json") or {}
    interaction = load_json(result_dir / "interaction_state.json") or meta.get("interaction_state") or {}
    report = load_json(result_dir / "patches_poc_report.json")
    constraints = interaction.get("constraint_candidates") or meta.get("constraints") or []
    counterfactual_contracts_raw = (
        meta.get("counterfactual_contracts")
        if isinstance(meta.get("counterfactual_contracts"), dict)
        else interaction.get("counterfactual_contracts", {})
    )
    counterfactual_contracts = list(counterfactual_contracts_raw.values()) if isinstance(counterfactual_contracts_raw, dict) else []
    counterfactual_observations = [
        observation
        for contract in counterfactual_contracts
        if isinstance(contract, dict)
        for observation in (contract.get("angelic_observations", []) or []) + (contract.get("demonic_observations", []) or [])
        if isinstance(observation, dict)
    ]
    patches = interaction.get("patch_candidates") or meta.get("patch_candidates") or []
    fuzz = interaction.get("fuzz_result") or {}
    verification_items = []
    if report and isinstance(report.get("items"), list):
        verification_items = report["items"]
    elif isinstance(meta.get("verification_feedback"), list):
        verification_items = meta["verification_feedback"]
    elif isinstance(interaction.get("verification_feedback"), list):
        verification_items = interaction["verification_feedback"]
    champion_patch = meta.get("patch") or interaction.get("champion_patch") or {}
    champion_feedback = champion_patch.get("verification_feedback") or interaction.get("champion_feedback") or {}
    champion_details = champion_feedback.get("details") or {}
    return {
        "id": result_dir.name,
        "reproduced": bool(meta.get("reproduced")),
        "usable_debug": bool(interaction.get("suspects") or meta.get("root_cause")),
        "contract_generated": bool(counterfactual_contracts),
        "target_crash_disappeared": any(
            item.get("target_crash_status") == "disappeared"
            for item in counterfactual_observations
        ),
        "angelic_found": bool(fuzz.get("angelic_values")),
        "constraint_validated": any(c.get("status") in {"validated", "needs_source_check"} for c in constraints),
        "patch_generated": bool(patches or meta.get("patch")),
        "poc_pass": bool(meta.get("patch")),
        "failure": infer_failure(meta, report),
        "verification_count": len(verification_items),
        "champion_confidence": champion_details.get("verification_confidence"),
        "residual_risk": champion_details.get("residual_risk") or "",
        "patch_strategies": [
            p.get("strategy") or (p.get("metadata") or {}).get("strategy") or "unknown"
            for p in patches
        ],
        "counterfactual_boundary_kinds": [
            contract.get("boundary_kind", "unknown")
            for contract in counterfactual_contracts
            if isinstance(contract, dict)
        ],
    }


def pct(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return round((numerator / denominator) * 100.0, 2)


def main() -> int:
    parser = argparse.ArgumentParser(description="Summarize Angelic Agent method metrics.")
    parser.add_argument("results", nargs="?", default="workspace/results", help="Results root directory")
    parser.add_argument("--out", default="method_metrics.json", help="Output JSON path")
    parser.add_argument("--markdown", default="method_metrics.md", help="Output markdown path")
    args = parser.parse_args()

    root = Path(args.results)
    items = []
    for child in sorted(root.iterdir() if root.exists() else []):
        if child.is_dir() and (child / "meta.json").exists():
            items.append(summarize_result_dir(child))

    counters = {
        "total": len(items),
        "reproduced": sum(1 for item in items if item["reproduced"]),
        "usable_debug": sum(1 for item in items if item["usable_debug"]),
        "contract_generated": sum(1 for item in items if item["contract_generated"]),
        "target_crash_disappeared": sum(1 for item in items if item["target_crash_disappeared"]),
        "angelic_found": sum(1 for item in items if item["angelic_found"]),
        "constraint_validated": sum(1 for item in items if item["constraint_validated"]),
        "patch_generated": sum(1 for item in items if item["patch_generated"]),
        "poc_pass": sum(1 for item in items if item["poc_pass"]),
    }
    failures = Counter(item["failure"] for item in items)
    strategies = Counter(strategy for item in items for strategy in item["patch_strategies"])
    boundary_kinds = Counter(kind for item in items for kind in item["counterfactual_boundary_kinds"])
    residual_risks = Counter(item["residual_risk"] for item in items if item["residual_risk"])
    champion_confidences = [
        float(item["champion_confidence"])
        for item in items
        if item["champion_confidence"] is not None
    ]
    summary_rates = {
        "reproduced_pct": pct(counters["reproduced"], counters["total"]),
        "usable_debug_pct": pct(counters["usable_debug"], counters["total"]),
        "contract_generated_pct": pct(counters["contract_generated"], counters["total"]),
        "target_crash_disappeared_pct": pct(counters["target_crash_disappeared"], counters["total"]),
        "angelic_found_pct": pct(counters["angelic_found"], counters["total"]),
        "constraint_validated_pct": pct(counters["constraint_validated"], counters["total"]),
        "patch_generated_pct": pct(counters["patch_generated"], counters["total"]),
        "poc_pass_pct": pct(counters["poc_pass"], counters["total"]),
        "avg_champion_confidence": round(sum(champion_confidences) / len(champion_confidences), 3)
        if champion_confidences
        else 0.0,
    }
    failure_rows = [
        {"failure": key, "count": value, "pct": pct(value, counters["total"])}
        for key, value in failures.most_common()
    ]
    strategy_rows = [
        {"strategy": key, "count": value, "pct": pct(value, max(1, sum(strategies.values())))}
        for key, value in strategies.most_common()
    ]
    residual_rows = [
        {"residual_risk": key, "count": value, "pct": pct(value, counters["total"])}
        for key, value in residual_risks.most_common()
    ]
    payload = {
        "summary": counters,
        "summary_rates": summary_rates,
        "failure_taxonomy": dict(failures),
        "failure_rows": failure_rows,
        "patch_strategy_distribution": dict(strategies),
        "counterfactual_boundary_kind_distribution": dict(boundary_kinds),
        "patch_strategy_rows": strategy_rows,
        "residual_risk_distribution": dict(residual_risks),
        "residual_risk_rows": residual_rows,
        "items": items,
    }

    Path(args.out).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    lines = ["# Method Metrics", "", "## Summary", ""]
    lines.extend([f"- {key}: {value}" for key, value in counters.items()])
    lines.extend([f"- {key}: {value}%" for key, value in summary_rates.items()])
    lines.extend(["", "## Failure Taxonomy", ""])
    lines.append("| failure | count | pct |")
    lines.append("| --- | ---: | ---: |")
    lines.extend([f"| {row['failure']} | {row['count']} | {row['pct']}% |" for row in failure_rows])
    lines.extend(["", "## Patch Strategies", ""])
    lines.append("| strategy | count | pct |")
    lines.append("| --- | ---: | ---: |")
    lines.extend([f"| {row['strategy']} | {row['count']} | {row['pct']}% |" for row in strategy_rows])
    lines.extend(["", "## Counterfactual Boundary Kinds", ""])
    lines.append("| boundary_kind | count |")
    lines.append("| --- | ---: |")
    lines.extend([f"| {key} | {value} |" for key, value in boundary_kinds.most_common()])
    lines.extend(["", "## Residual Risk", ""])
    lines.append("| residual_risk | count | pct |")
    lines.append("| --- | ---: | ---: |")
    lines.extend([f"| {row['residual_risk']} | {row['count']} | {row['pct']}% |" for row in residual_rows])
    Path(args.markdown).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {args.out} and {args.markdown}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
