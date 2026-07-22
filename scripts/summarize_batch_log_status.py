#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path


SUCCESS_MARKER = "[INFO] Champion patch selected."


def has_success_marker(path: Path, marker: str) -> bool:
    with path.open("r", encoding="utf-8", errors="replace") as f:
        return any(marker in line for line in f)


def iter_log_files(root: Path) -> list[Path]:
    if not root.exists():
        return []
    return sorted(path for path in root.rglob("*.txt") if path.is_file())


def summarize(root: Path, marker: str) -> list[dict[str, str]]:
    rows = []
    for path in iter_log_files(root):
        passed = has_success_marker(path, marker)
        relative_path = path.relative_to(root)
        group = str(relative_path.parent) if relative_path.parent != Path(".") else "."
        rows.append(
            {
                "id": path.stem,
                "status": "passed" if passed else "failed",
                "group": group,
                "path": str(relative_path),
            }
        )
    return rows


def write_csv(path: Path, rows: list[dict[str, str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["id", "status", "group", "path"])
        writer.writeheader()
        writer.writerows(rows)


def write_json(path: Path, rows: list[dict[str, str]]) -> None:
    path.write_text(json.dumps(rows, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def print_summary(rows: list[dict[str, str]]) -> None:
    groups: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        groups[row["group"]].append(row)

    total = len(rows)
    passed = sum(1 for row in rows if row["status"] == "passed")
    failed = total - passed
    print(f"total={total} passed={passed} failed={failed}")

    for group in sorted(groups):
        group_rows = groups[group]
        group_passed = sum(1 for row in group_rows if row["status"] == "passed")
        group_failed = len(group_rows) - group_passed
        print(f"{group}: total={len(group_rows)} passed={group_passed} failed={group_failed}")

    if passed:
        print("\npassed ids:")
        for row in rows:
            if row["status"] == "passed":
                print(row["id"])

    if failed:
        print("\nfailed ids:")
        for row in rows:
            if row["status"] == "failed":
                print(row["id"])


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Summarize workspace/batch_logs txt files by Champion patch selection."
    )
    parser.add_argument(
        "root",
        nargs="?",
        default="workspace/batch_logs",
        help="Root directory containing batch log txt files.",
    )
    parser.add_argument(
        "--marker",
        default=SUCCESS_MARKER,
        help="Log marker that means the example passed.",
    )
    parser.add_argument("--csv", help="Optional CSV output path.")
    parser.add_argument("--json", help="Optional JSON output path.")
    args = parser.parse_args()

    root = Path(args.root)
    rows = summarize(root, args.marker)

    print_summary(rows)
    if args.csv:
        write_csv(Path(args.csv), rows)
        print(f"\nwrote csv: {args.csv}")
    if args.json:
        write_json(Path(args.json), rows)
        print(f"wrote json: {args.json}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
