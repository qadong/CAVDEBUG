#!/usr/bin/env python3
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import re
import shlex
import subprocess
import tempfile
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
SANITIZER_PATTERN = re.compile(r"(?:ERROR|SUMMARY):\s*(?:Address|Leak|Memory|UndefinedBehavior|Thread)Sanitizer", re.I)


def read_json_or_jsonl(path: Path) -> list[dict[str, Any]]:
    if path.suffix == ".jsonl":
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    data = json.loads(path.read_text(encoding="utf-8"))
    return data if isinstance(data, list) else [data]


def safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value)


def image_for(instance_id: str, template: str, extended_template: str) -> str:
    selected = extended_template if instance_id.startswith("e") else template
    return selected.format(instance_id=instance_id)


def stage_script(
    profile: dict[str, Any],
    patch_path: str,
    replay_timeout: int,
    result_path: str | None = None,
) -> str:
    src = shlex.quote(str(profile.get("src") or ""))
    patch = shlex.quote(patch_path)
    pre_build = [str(item) for item in profile.get("pre_build") or []]
    post_build = [
        str(item) for item in profile.get("post_build") or [] if "compile_commands.json" not in str(item)
    ]
    build = str(profile.get("build") or "CFLAGS='-O0 -g' CXXFLAGS='-O0 -g' arvo compile")
    build = re.sub(r"\bbear\s+", "", build)
    build_steps = [*pre_build, build, *post_build]
    build_command = " && ".join(f"({step})" for step in build_steps)
    environment = "\n".join(
        f"export {key}={shlex.quote(str(value))}"
        for key, value in (profile.get("env") or {}).items()
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", str(key))
    )
    result_redirect = f" > {shlex.quote(result_path)} 2>&1" if result_path else ""
    return f"""
set +e
{environment}
cd {src} || exit 90
git apply --check {patch} > /tmp/ssc-apply.log 2>&1
apply_rc=$?
if [ "$apply_rc" -eq 0 ]; then
  git apply {patch} >> /tmp/ssc-apply.log 2>&1
  apply_rc=$?
fi
build_rc=99
replay_rc=99
if [ "$apply_rc" -eq 0 ]; then
  bash -lc {shlex.quote(build_command)} > /tmp/ssc-build.log 2>&1
  build_rc=$?
fi
if [ "$build_rc" -eq 0 ]; then
  timeout {int(replay_timeout)} arvo > /tmp/ssc-replay.log 2>&1
  replay_rc=$?
fi
{{
  printf '\n__SSC_APPLY_RC=%s\n__SSC_BUILD_RC=%s\n__SSC_REPLAY_RC=%s\n' "$apply_rc" "$build_rc" "$replay_rc"
  printf '\n===== APPLY =====\n'; cat /tmp/ssc-apply.log 2>/dev/null
  printf '\n===== BUILD =====\n'; cat /tmp/ssc-build.log 2>/dev/null
  printf '\n===== REPLAY =====\n'; cat /tmp/ssc-replay.log 2>/dev/null
}}{result_redirect}
exit 0
"""


def parse_stage_code(output: str, stage: str) -> int | None:
    match = re.search(rf"__SSC_{stage}_RC=(-?\d+)", output)
    return int(match.group(1)) if match else None


def validation_result(instance_id: str, output: str, docker_rc: int) -> dict[str, Any]:
    apply_rc = parse_stage_code(output, "APPLY")
    build_rc = parse_stage_code(output, "BUILD")
    replay_rc = parse_stage_code(output, "REPLAY")
    sanitizer = bool(SANITIZER_PATTERN.search(output))
    success = docker_rc == 0 and apply_rc == 0 and build_rc == 0 and replay_rc == 0 and not sanitizer
    if docker_rc != 0:
        reason = "container_failed"
    elif None in (apply_rc, build_rc, replay_rc):
        reason = "validation_protocol_error"
    elif apply_rc != 0:
        reason = "patch_apply_failed"
    elif build_rc != 0:
        reason = "compile_failed"
    elif replay_rc != 0 or sanitizer:
        reason = "poc_reproduced_or_sanitizer_reported"
    else:
        reason = "compile_and_poc_replay_passed"
    compile_marker = "SUCCESS: Compile passed" if build_rc == 0 else "BUILD FAILED"
    if len(output) > 120000:
        output = output[:60000] + "\n...[validation log truncated]...\n" + output[-60000:]
    return {
        "instance_id": instance_id,
        "success": success,
        "reason": reason,
        "exit_code": replay_rc,
        "sanitizer_report": sanitizer,
        "apply_exit_code": apply_rc,
        "compile_exit_code": build_rc,
        "docker_exit_code": docker_rc,
        "logs": f"{compile_marker}\n{output}",
    }


def tty_fallback_command(command: list[str], script: str) -> list[str]:
    tty_command = command.copy()
    tty_command.insert(tty_command.index("--rm"), "-t")
    if tty_command[-2:] != ["bash", "-s"]:
        raise ValueError("TTY fallback expects a docker command ending in `bash -s`")
    tty_command[-2:] = ["bash", "-lc", script]
    return ["script", "-q", "-e", "-c", shlex.join(tty_command), "/dev/null"]


def validate_one(
    instance_id: str,
    profile: dict[str, Any],
    patch: str,
    output_dir: Path,
    image_template: str,
    extended_image_template: str,
    replay_timeout: int,
    container_timeout: int,
) -> dict[str, Any]:
    patch_dir = output_dir / "patches"
    patch_dir.mkdir(parents=True, exist_ok=True)
    patch_file = patch_dir / f"{safe_name(instance_id)}.diff"
    patch_file.write_text(patch, encoding="utf-8")
    relative_patch = patch_file.resolve().relative_to(REPO_ROOT.resolve())
    container_patch = f"/root/repo/{relative_patch}"
    container_log_dir = output_dir / "container-logs"
    container_log_dir.mkdir(parents=True, exist_ok=True)
    host_container_log = container_log_dir / f"{safe_name(instance_id)}.log"
    host_container_log.unlink(missing_ok=True)
    relative_log = host_container_log.resolve().relative_to(REPO_ROOT.resolve())
    container_log = f"/root/repo/{relative_log}"
    image = image_for(instance_id, image_template, extended_image_template)
    container_name = f"arvo-ssc-{safe_name(instance_id)}-{os.getpid()}"
    command = [
        "docker",
        "run",
        "-i",
        "--rm",
        "--privileged",
        "--network=host",
        "--name",
        container_name,
        "-v",
        f"{REPO_ROOT.resolve()}:/root/repo",
        image,
        "bash",
        "-s",
    ]
    script_input = stage_script(profile, container_patch, replay_timeout, result_path=container_log).encode("utf-8")

    def run_container(
        container_command: list[str],
        input_bytes: bytes | None,
    ) -> tuple[subprocess.CompletedProcess[bytes], str]:
        with tempfile.TemporaryFile() as output_file:
            process = subprocess.run(
                container_command,
                input=input_bytes,
                stdout=output_file,
                stderr=subprocess.STDOUT,
                timeout=container_timeout,
                check=False,
            )
            output_file.seek(0)
            output = output_file.read().decode("utf-8", errors="replace")
        return process, output

    try:
        process, output = run_container(command, script_input)
        if process.returncode == 0 and not host_container_log.exists():
            fallback_command = tty_fallback_command(command, script_input.decode("utf-8"))
            process, output = run_container(fallback_command, None)
        if host_container_log.exists():
            output = host_container_log.read_bytes().decode("utf-8", errors="replace")
        result = validation_result(instance_id, output, process.returncode)
    except subprocess.TimeoutExpired as exc:
        subprocess.run(
            ["docker", "rm", "-f", container_name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        output = str(exc.stdout or "")
        result = validation_result(instance_id, output, -66)
        result["reason"] = "container_timeout"
    result["image"] = image
    result["patch_sha256"] = hashlib.sha256(patch.encode("utf-8")).hexdigest()
    (output_dir / f"{safe_name(instance_id)}.json").write_text(
        json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Independently apply, compile, and replay ARVO candidate patches.")
    parser.add_argument("--arvo-raw", required=True, type=Path)
    parser.add_argument("--patch-json", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--instance-id", action="append")
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--resume", action="store_true", help="Reuse existing per-instance JSON results in output-dir.")
    parser.add_argument("--replay-timeout", type=int, default=60)
    parser.add_argument("--container-timeout", type=int, default=3600)
    parser.add_argument(
        "--image-template",
        default="n132/arvo:{instance_id}-vul",
    )
    parser.add_argument(
        "--extended-image-template",
        default="registry.cn-wulanchabu.aliyuncs.com/dockmoil/arvo:{instance_id}-vul",
    )
    args = parser.parse_args(argv)

    output_dir = args.output_dir.resolve()
    try:
        output_dir.relative_to(REPO_ROOT.resolve())
    except ValueError:
        parser.error(f"--output-dir must be under {REPO_ROOT}")
    output_dir.mkdir(parents=True, exist_ok=True)
    rows = {str(row.get("instance_id")): row for row in read_json_or_jsonl(args.arvo_raw)}
    patches = {
        str(item.get("instance_id")): str(item.get("model_patch") or item.get("git_patch") or "")
        for item in read_json_or_jsonl(args.patch_json)
    }
    instance_ids = args.instance_id or sorted(patches)
    tasks = []
    results = []
    for instance_id in instance_ids:
        if instance_id not in rows or not patches.get(instance_id):
            raise KeyError(f"Missing ARVO row or candidate patch for {instance_id}")
        existing_path = output_dir / f"{safe_name(instance_id)}.json"
        if args.resume and existing_path.exists():
            results.append(json.loads(existing_path.read_text(encoding="utf-8")))
            continue
        tasks.append((instance_id, rows[instance_id], patches[instance_id]))

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        futures = {
            executor.submit(
                validate_one,
                instance_id,
                row,
                patch,
                output_dir,
                args.image_template,
                args.extended_image_template,
                args.replay_timeout,
                args.container_timeout,
            ): instance_id
            for instance_id, row, patch in tasks
        }
        for future in concurrent.futures.as_completed(futures):
            instance_id = futures[future]
            try:
                results.append(future.result())
            except Exception as exc:
                result = {
                    "instance_id": instance_id,
                    "success": False,
                    "reason": "validator_exception",
                    "exit_code": None,
                    "sanitizer_report": False,
                    "logs": f"{exc.__class__.__name__}: {exc}",
                }
                (output_dir / f"{safe_name(instance_id)}.json").write_text(
                    json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8"
                )
                results.append(result)
    order = {instance_id: index for index, instance_id in enumerate(instance_ids)}
    results.sort(key=lambda item: order[item["instance_id"]])
    report = output_dir / "report.jsonl"
    report.write_text("".join(json.dumps(item, ensure_ascii=False) + "\n" for item in results), encoding="utf-8")
    print(f"validated {len(results)} patches; success {sum(bool(item['success']) for item in results)}; report {report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
