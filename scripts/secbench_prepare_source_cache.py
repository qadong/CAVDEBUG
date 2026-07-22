#!/usr/bin/env python3
from __future__ import annotations

import argparse
import concurrent.futures
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from stalker.judge.semantic_security import read_json_or_jsonl, source_cache_key


def repo_cache_key(repo: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", repo.strip().strip("/"))


def load_rows(path: Path, instance_ids: set[str] | None) -> list[dict[str, Any]]:
    rows = []
    for row in read_json_or_jsonl(path):
        instance_id = str(row.get("instance_id") or "")
        if not instance_id:
            continue
        if instance_ids is not None and instance_id not in instance_ids:
            continue
        rows.append(row)
    return rows


def run_git(args: list[str], cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", *args], cwd=cwd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def git_error(exc: Exception) -> str:
    if isinstance(exc, subprocess.CalledProcessError):
        command = " ".join(str(part) for part in exc.cmd)
        return (
            f"git command failed: {command}\n"
            f"exit_code: {exc.returncode}\n"
            f"stdout:\n{exc.stdout or ''}\n"
            f"stderr:\n{exc.stderr or ''}"
        )
    return f"{exc.__class__.__name__}: {exc}"


def prepare_repo_mirror(repo: str, output_dir: Path, remote_template: str, force: bool) -> Path:
    output_dir = output_dir.resolve()
    repos_dir = output_dir / "_repos"
    repos_dir.mkdir(parents=True, exist_ok=True)
    mirror = repos_dir / f"{repo_cache_key(repo)}.git"
    remote = remote_template.format(repo=repo)
    if mirror.exists():
        if force:
            run_git(["remote", "update", "--prune"], cwd=mirror)
    else:
        run_git(["clone", "--mirror", remote, str(mirror)])
    return mirror


def checkout_head(path: Path) -> str | None:
    if not path.exists() or not (path / ".git").exists():
        return None
    try:
        result = run_git(["rev-parse", "HEAD"], cwd=path)
    except subprocess.CalledProcessError:
        return None
    return result.stdout.strip()


def prepare_checkout(
    repo: str,
    base_commit: str,
    output_dir: Path,
    mirror: Path,
    remote_template: str,
    force: bool,
) -> dict[str, Any]:
    output_dir = output_dir.resolve()
    mirror = mirror.resolve()
    key = source_cache_key(repo, base_commit)
    if not key:
        raise ValueError(f"Cannot build source cache key for repo={repo!r}, base_commit={base_commit!r}")
    dest = output_dir / key
    remote = remote_template.format(repo=repo)

    if dest.exists():
        if checkout_head(dest) == base_commit and not force:
            return {"repo": repo, "base_commit": base_commit, "source_dir": str(dest), "remote": remote, "cache_mode": "existing"}
        if force:
            shutil.rmtree(dest)
        else:
            run_git(["checkout", "--force", base_commit], cwd=dest)
            return {"repo": repo, "base_commit": base_commit, "source_dir": str(dest), "remote": remote, "cache_mode": "existing-reset"}

    dest.parent.mkdir(parents=True, exist_ok=True)
    run_git(["worktree", "prune"], cwd=mirror)
    run_git(["worktree", "add", "--detach", str(dest), base_commit], cwd=mirror)
    return {"repo": repo, "base_commit": base_commit, "source_dir": str(dest), "remote": remote, "cache_mode": "worktree"}


def run_cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Prepare reusable source checkouts for SEC-bench SSC judge context.")
    parser.add_argument("--secbench-raw", required=True, type=Path, help="SEC-bench raw JSON/JSONL.")
    parser.add_argument("--output-dir", required=True, type=Path, help="Source cache directory.")
    parser.add_argument("--instance-id", action="append", help="Instance id to prepare. May be repeated. Defaults to all rows.")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--force", action="store_true", help="Fetch and reset existing checkouts before checkout.")
    parser.add_argument("--remote-template", default="https://github.com/{repo}.git")
    args = parser.parse_args(argv)

    instance_ids = set(args.instance_id) if args.instance_id else None
    rows = load_rows(args.secbench_raw, instance_ids)
    jobs: dict[tuple[str, str], list[str]] = {}
    for row in rows:
        repo = str(row.get("repo") or "")
        base_commit = str(row.get("base_commit") or "")
        if repo and base_commit:
            jobs.setdefault((repo, base_commit), []).append(str(row.get("instance_id")))

    args.output_dir.mkdir(parents=True, exist_ok=True)
    manifest: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    workers = max(1, int(args.workers or 1))

    mirrors: dict[str, Path] = {}
    for repo in sorted({repo for repo, _ in jobs}):
        try:
            mirrors[repo] = prepare_repo_mirror(repo, args.output_dir, args.remote_template, args.force)
        except Exception as exc:
            for (job_repo, base_commit), ids in jobs.items():
                if job_repo == repo:
                    errors.append(
                        {
                            "repo": repo,
                            "base_commit": base_commit,
                            "instance_ids": ids,
                            "error": git_error(exc),
                        }
                    )

    runnable_jobs = [(job, ids) for job, ids in jobs.items() if job[0] in mirrors]

    def prepare(item: tuple[tuple[str, str], list[str]]) -> dict[str, Any]:
        (repo, base_commit), ids = item
        result = prepare_checkout(repo, base_commit, args.output_dir, mirrors[repo], args.remote_template, args.force)
        result["instance_ids"] = ids
        return result

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_job = {executor.submit(prepare, item): item for item in sorted(runnable_jobs)}
        for future in concurrent.futures.as_completed(future_to_job):
            (repo, base_commit), ids = future_to_job[future]
            try:
                manifest.append(future.result())
            except Exception as exc:
                errors.append(
                    {
                        "repo": repo,
                        "base_commit": base_commit,
                        "instance_ids": ids,
                        "error": git_error(exc),
                    }
                )

    manifest.sort(key=lambda item: (item["repo"], item["base_commit"]))
    errors.sort(key=lambda item: (item["repo"], item["base_commit"]))
    (args.output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    (args.output_dir / "errors.json").write_text(json.dumps(errors, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"prepared {len(manifest)} source checkouts in {args.output_dir}")
    if errors:
        print(f"errors {len(errors)}; see {args.output_dir / 'errors.json'}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(run_cli())
