#!/usr/bin/env python3
"""Summarize ARVO patch status from batch per-instance logs."""

from __future__ import annotations

import argparse
import csv
from collections import Counter
from pathlib import Path


PASS_MARKER = "Champion patch selected."
FAIL_MARKER = "Failed to generate a valid patch."


def _read_tags(path: Path) -> list[str]:
    tags = [line.strip() for line in path.read_text().splitlines() if line.strip()]
    seen: set[str] = set()
    duplicates: list[str] = []
    for tag in tags:
        if tag in seen:
            duplicates.append(tag)
        seen.add(tag)
    if duplicates:
        raise SystemExit(f"Duplicate tags in {path}: {', '.join(duplicates[:10])}")
    return tags


def _classify_log(path: Path | None) -> str:
    if path is None:
        return "missing"
    text = path.read_text(errors="replace")
    if PASS_MARKER in text:
        return "pass"
    if FAIL_MARKER in text:
        return "fail"
    return "unknown"


def _latest_logs(tags: list[str], dirs: list[Path]) -> dict[str, Path]:
    logs: dict[str, Path] = {}
    tag_set = set(tags)
    for directory in dirs:
        if not directory.exists():
            raise SystemExit(f"Log directory does not exist: {directory}")
        for path in directory.glob("*.txt"):
            if path.stem in tag_set:
                logs[path.stem] = path
    return logs


def _print_method(name: str, rows: list[dict[str, str]]) -> None:
    counts = Counter(row[f"{name}_status"] for row in rows)
    print(f"[{name}]")
    print(f"  pass: {counts['pass']}")
    print(f"  fail: {counts['fail']}")
    print(f"  unknown: {counts['unknown']}")
    print(f"  missing: {counts['missing']}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag-file", default="datasets/tags/408/final_200.txt")
    parser.add_argument("--full-dir", action="append", default=[], help="Full-pipeline batch log dir. Can be repeated; later dirs override earlier dirs for the same tag.")
    parser.add_argument("--lldb-dir", action="append", default=[], help="LLDB-only batch log dir. Can be repeated; later dirs override earlier dirs for the same tag.")
    parser.add_argument("--csv-out", help="Optional per-instance CSV output path.")
    args = parser.parse_args()

    if not args.full_dir:
        raise SystemExit("Provide at least one --full-dir")
    if not args.lldb_dir:
        raise SystemExit("Provide at least one --lldb-dir")

    tags = _read_tags(Path(args.tag_file))
    full_logs = _latest_logs(tags, [Path(p) for p in args.full_dir])
    lldb_logs = _latest_logs(tags, [Path(p) for p in args.lldb_dir])

    rows: list[dict[str, str]] = []
    for tag in tags:
        full_log = full_logs.get(tag)
        lldb_log = lldb_logs.get(tag)
        rows.append(
            {
                "instance_id": tag,
                "full_status": _classify_log(full_log),
                "lldb_status": _classify_log(lldb_log),
                "full_log": str(full_log) if full_log else "",
                "lldb_log": str(lldb_log) if lldb_log else "",
            }
        )

    print(f"tag_file: {args.tag_file}")
    print(f"total_tags: {len(tags)}")
    print(f"full_log_dirs: {', '.join(args.full_dir)}")
    print(f"lldb_log_dirs: {', '.join(args.lldb_dir)}")
    print()
    _print_method("full", rows)
    _print_method("lldb", rows)

    pairs = Counter((row["full_status"], row["lldb_status"]) for row in rows)
    print("[comparison]")
    for (full_status, lldb_status), count in sorted(pairs.items()):
        print(f"  full={full_status:7s} lldb={lldb_status:7s}: {count}")

    both_pass = [row["instance_id"] for row in rows if row["full_status"] == "pass" and row["lldb_status"] == "pass"]
    full_only = [row["instance_id"] for row in rows if row["full_status"] == "pass" and row["lldb_status"] != "pass"]
    lldb_only = [row["instance_id"] for row in rows if row["lldb_status"] == "pass" and row["full_status"] != "pass"]
    neither = [row["instance_id"] for row in rows if row["full_status"] != "pass" and row["lldb_status"] != "pass"]
    print("[pass_sets]")
    print(f"  both_pass: {len(both_pass)}")
    print(f"  full_only_pass: {len(full_only)}")
    print(f"  lldb_only_pass: {len(lldb_only)}")
    print(f"  neither_pass: {len(neither)}")

    missing_full = [row["instance_id"] for row in rows if row["full_status"] == "missing"]
    missing_lldb = [row["instance_id"] for row in rows if row["lldb_status"] == "missing"]
    if missing_full:
        print("missing_full_ids:", " ".join(missing_full))
    if missing_lldb:
        print("missing_lldb_ids:", " ".join(missing_lldb))
    if lldb_only:
        print("lldb_only_pass_ids:", " ".join(lldb_only))
    if full_only:
        print("full_only_pass_ids:", " ".join(full_only))

    if args.csv_out:
        out = Path(args.csv_out)
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["instance_id", "full_status", "lldb_status", "full_log", "lldb_log"])
            writer.writeheader()
            writer.writerows(rows)
        print(f"csv_out: {out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
