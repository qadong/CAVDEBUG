#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


def read_tags(path: Path) -> list[str]:
    return [line.strip() for line in path.read_text().splitlines() if line.strip()]


def github_commit_parts(url: str) -> tuple[str, str]:
    match = re.search(r"github\.com/([^/]+/[^/]+)/commit/([0-9a-fA-F]+)", url)
    if not match:
        return "", ""
    return match.group(1), match.group(2)


def fetch_commit_diff(url: str) -> str:
    diff_url = url.rstrip("/") + ".diff"
    return subprocess.check_output(
        [
            "curl",
            "-L",
            "--fail",
            "--retry",
            "5",
            "--retry-delay",
            "3",
            "--connect-timeout",
            "20",
            "--max-time",
            "180",
            diff_url,
        ],
        text=True,
        stderr=subprocess.DEVNULL,
    )


def read_patch(path: Path) -> str:
    if not path.exists() or path.stat().st_size == 0:
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def normalize_unified_diff_hunk_counts(diff: str) -> tuple[str, bool]:
    lines = diff.splitlines(keepends=True)
    changed = False
    index = 0
    while index < len(lines):
        header = lines[index].rstrip("\r\n")
        match = re.match(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)$", header)
        if not match:
            index += 1
            continue
        old_count = 0
        new_count = 0
        end = index + 1
        while end < len(lines) and not lines[end].startswith(("@@ ", "diff --git ")):
            body = lines[end]
            if body.startswith("\\ No newline at end of file"):
                end += 1
                continue
            if body.startswith("-"):
                old_count += 1
            elif body.startswith("+"):
                new_count += 1
            else:
                old_count += 1
                new_count += 1
            end += 1
        expected_old = int(match.group(2) or 1)
        expected_new = int(match.group(4) or 1)
        if (expected_old, expected_new) != (old_count, new_count):
            newline = "\r\n" if lines[index].endswith("\r\n") else "\n"
            lines[index] = (
                f"@@ -{match.group(1)},{old_count} +{match.group(3)},{new_count} @@{match.group(5)}{newline}"
            )
            changed = True
        index = end
    return "".join(lines), changed


def build_raw_row(instance_id: str, data: dict[str, Any], golden_diff: str) -> dict[str, Any]:
    repo, commit = github_commit_parts(str(data.get("patch") or ""))
    project = repo.split("/")[-1] if repo else Path(str(data.get("src") or "")).name
    constraint = str(data.get("constraint") or "")
    return {
        "instance_id": instance_id,
        "project_name": project,
        "repo": repo,
        "base_commit": f"{commit}^" if commit else "",
        "fix_commit": commit,
        "bug_description": constraint,
        "bug_report": constraint,
        "sanitizer": "",
        "sanitizer_report": "",
        "functions": data.get("functions") or [],
        "src": data.get("src") or "",
        "file": data.get("file") or "",
        "args": data.get("args") or [],
        "env": data.get("env") or {},
        "build": data.get("build") or "",
        "pre_build": data.get("pre_build") or [],
        "post_build": data.get("post_build") or [],
        "patch": golden_diff,
        "golden_patch_note": (
            "Golden/reference patch is the upstream fixing commit from ARVO. "
            "It may include unrelated maintenance or refactoring changes; use it as semantic evidence for the "
            "vulnerability condition, not as a requirement that every hunk or file be matched."
        ),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Prepare ARVO inputs for semantic security judge.")
    parser.add_argument("--tag-file", default="datasets/tags/408/final_200.txt", type=Path)
    parser.add_argument("--datasets-dir", default="datasets", type=Path)
    parser.add_argument("--results-dir", default="workspace/results", type=Path)
    parser.add_argument("--output-dir", default="workspace/arvo/semantic_judge", type=Path)
    parser.add_argument("--skip-golden-fetch", action="store_true", help="Reuse existing raw rows when possible.")
    args = parser.parse_args(argv)

    raw_dir = args.output_dir / "raw"
    patch_dir = args.output_dir / "patches"
    raw_dir.mkdir(parents=True, exist_ok=True)
    patch_dir.mkdir(parents=True, exist_ok=True)

    tags = read_tags(args.tag_file)
    raw_rows = []
    full_patches = []
    lldb_patches = []
    errors = []

    existing_raw: dict[str, dict[str, Any]] = {}
    raw_path = raw_dir / "final_200.jsonl"
    if args.skip_golden_fetch and raw_path.exists():
        for line in raw_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                row = json.loads(line)
                existing_raw[str(row.get("instance_id"))] = row

    for instance_id in tags:
        dataset_path = args.datasets_dir / f"{instance_id}.json"
        data = json.loads(dataset_path.read_text(encoding="utf-8"))
        if instance_id in existing_raw and existing_raw[instance_id].get("patch"):
            golden_diff = str(existing_raw[instance_id].get("patch") or "")
        else:
            try:
                golden_diff = fetch_commit_diff(str(data.get("patch") or ""))
            except Exception as exc:
                golden_diff = ""
                errors.append({"instance_id": instance_id, "stage": "golden_fetch", "error": f"{exc.__class__.__name__}: {exc}"})
        raw_rows.append(build_raw_row(instance_id, data, golden_diff))

        for suffix, patches in (("", full_patches), ("_lldb_only", lldb_patches)):
            diff, repaired = normalize_unified_diff_hunk_counts(
                read_patch(args.results_dir / f"{instance_id}{suffix}" / "patch.diff")
            )
            if diff:
                patches.append(
                    {
                        "instance_id": instance_id,
                        "model_patch": diff,
                        "metadata": {
                            "result_dir": str(args.results_dir / f"{instance_id}{suffix}"),
                            "diff_hunk_counts_repaired": repaired,
                        },
                    }
                )

    raw_path.write_text("\n".join(json.dumps(row, ensure_ascii=False) for row in raw_rows) + "\n", encoding="utf-8")
    (patch_dir / "full_pipeline_patch.json").write_text(json.dumps(full_patches, indent=2, ensure_ascii=False), encoding="utf-8")
    (patch_dir / "lldb_only_patch.json").write_text(json.dumps(lldb_patches, indent=2, ensure_ascii=False), encoding="utf-8")
    (args.output_dir / "prepare_errors.json").write_text(json.dumps(errors, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"raw {raw_path} {len(raw_rows)}")
    print(f"full patches {patch_dir / 'full_pipeline_patch.json'} {len(full_patches)}")
    print(f"lldb patches {patch_dir / 'lldb_only_patch.json'} {len(lldb_patches)}")
    if errors:
        print(f"errors {len(errors)}; see {args.output_dir / 'prepare_errors.json'}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
