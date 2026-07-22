#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from stalker.judge.semantic_security import aggregate_verdicts


def parse_vote_spec(value: str) -> tuple[str, Path]:
    name, separator, path = value.partition("=")
    if not separator or not name or not path:
        raise argparse.ArgumentTypeError("--vote must use NAME=SUMMARY_JSON syntax")
    return name, Path(path)


def load_summary(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"Summary must be a JSON list: {path}")
    return data


def aggregate_panel(vote_specs: list[tuple[str, Path]]) -> tuple[list[dict[str, Any]], int]:
    if not vote_specs:
        raise ValueError("At least one vote summary is required")
    names = [name for name, _ in vote_specs]
    if len(names) != len(set(names)):
        raise ValueError("Judge names must be unique")

    summaries: dict[str, dict[str, dict[str, Any]]] = {}
    order: list[str] = []
    for index, (name, path) in enumerate(vote_specs):
        rows = load_summary(path)
        by_id: dict[str, dict[str, Any]] = {}
        for row in rows:
            instance_id = str(row.get("instance_id") or "")
            if not instance_id:
                raise ValueError(f"Missing instance_id in {path}")
            if instance_id in by_id:
                raise ValueError(f"Duplicate instance_id {instance_id} in {path}")
            by_id[instance_id] = row
        summaries[name] = by_id
        if index == 0:
            order = list(by_id)

    all_ids = set().union(*(set(rows) for rows in summaries.values()))
    for instance_id in sorted(all_ids - set(order)):
        order.append(instance_id)

    output: list[dict[str, Any]] = []
    incomplete = 0
    for instance_id in order:
        panel_votes = []
        verdicts = []
        errors = []
        for name, path in vote_specs:
            row = summaries[name].get(instance_id)
            if row is None:
                errors.append({"judge": name, "error": "missing instance"})
                continue
            if row.get("error"):
                errors.append({"judge": name, "error": str(row["error"])})
                continue
            verdict = row.get("verdict")
            if not isinstance(verdict, dict):
                errors.append({"judge": name, "error": "missing verdict"})
                continue
            if verdict.get("vote_errors"):
                errors.append({"judge": name, "error": "single-model run contains vote errors"})
                continue
            label = str(verdict.get("label") or "Inconclusive")
            panel_votes.append({"judge": name, "label": label, "summary": str(path)})
            verdicts.append(verdict)

        if errors or len(verdicts) != len(vote_specs):
            incomplete += 1
            output.append(
                {
                    "instance_id": instance_id,
                    "verdict": None,
                    "error": "incomplete judge panel",
                    "panel_errors": errors,
                    "panel_votes": panel_votes,
                }
            )
            continue

        verdict = aggregate_verdicts(verdicts)
        verdict["panel_judges"] = names
        verdict["panel_votes"] = panel_votes
        verdict["panel_vote_summary"] = dict(Counter(vote["label"] for vote in panel_votes))
        output.append({"instance_id": instance_id, "verdict": verdict})
    return output, incomplete


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Aggregate independent SSC judge model votes.")
    parser.add_argument(
        "--vote",
        action="append",
        required=True,
        type=parse_vote_spec,
        metavar="NAME=SUMMARY_JSON",
    )
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args(argv)

    summary, incomplete = aggregate_panel(args.vote)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    output_path = args.output_dir / "summary.json"
    output_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    verdicts = [item["verdict"] for item in summary if item.get("verdict")]
    ssc = sum(bool(verdict.get("counts_for_ssc")) for verdict in verdicts)
    inconclusive = sum(verdict.get("label") == "Inconclusive" for verdict in verdicts)
    print(
        f"aggregated {len(summary)} instances; verdicts {len(verdicts)}; "
        f"ssc {ssc}; inconclusive {inconclusive}; incomplete {incomplete}; summary {output_path}"
    )
    return 1 if incomplete else 0


if __name__ == "__main__":
    raise SystemExit(main())
