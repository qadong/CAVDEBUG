#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import re
import shlex
import urllib.request
from pathlib import Path
from typing import Any


CVE_URL = "https://huggingface.co/datasets/SEC-bench/SEC-bench/raw/main/data/eval-cve.jsonl"
SEC_BENCH_DEBUG_CFLAGS = (
    "-O0 -g -Wno-error -Wno-strict-prototypes "
    "-Wno-incompatible-function-pointer-types -Wno-implicit-function-declaration "
    "-Wno-deprecated-non-prototype -Wno-int-conversion "
    "-Wno-unused-but-set-variable -Wno-error=unused-but-set-variable "
    "-Wno-single-bit-bitfield-constant-conversion "
    "-Wno-error=single-bit-bitfield-constant-conversion"
)
SEC_BENCH_DEBUG_CXXFLAGS = (
    "-O0 -g -Wno-error -Wno-incompatible-function-pointer-types "
    "-Wno-deprecated-declarations -Wno-register -Wno-c++11-narrowing "
    "-Wno-unused-but-set-variable -Wno-error=unused-but-set-variable "
    "-Wno-single-bit-bitfield-constant-conversion "
    "-Wno-error=single-bit-bitfield-constant-conversion -std=gnu++14"
)
SEC_BENCH_AUTOCONF_CACHE_ENV = (
    "ac_cv_func_malloc_0_nonnull=yes "
    "ac_cv_func_realloc_0_nonnull=yes "
)


def safe_tag(instance_id: str) -> str:
    return "secbench_" + re.sub(r"[^A-Za-z0-9_.-]+", "_", instance_id).replace(".", "_")


def ensure_raw_jsonl(path: Path, url: str) -> None:
    if path.exists() and path.stat().st_size > 0:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(url, timeout=60) as response:
        path.write_bytes(response.read())


def load_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def repro_body(secb_sh: str) -> str:
    match = re.search(r"repro\(\)\s*\{(?P<body>.*?)(?:\n\}\n\npatch\(\)|\n\})", secb_sh, flags=re.S)
    return match.group("body") if match else ""


def _is_env_assignment(token: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", token))


def _looks_like_target_command(token: str) -> bool:
    return token.startswith("/") or token.startswith("./") or "/" in token


def parse_repro_command(row: dict[str, Any]) -> tuple[str, list[str], str, dict[str, str]]:
    work_dir = str(row.get("work_dir") or "")
    cwd = work_dir
    env: dict[str, str] = {}
    body = repro_body(str(row.get("secb_sh") or ""))
    ignored_commands = {"echo", "cd", "export", "sleep", "kill", "bash", "nc", "true", "false", "touch"}
    for raw_line in body.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        line = line.split("#", 1)[0].strip()
        line = line.split("||", 1)[0].strip()
        if "|" in line:
            line = line.rsplit("|", 1)[1].strip()
        if line.startswith("echo "):
            continue
        if line.endswith("&"):
            line = line[:-1].strip()
        if line.startswith("cd "):
            try:
                parts = shlex.split(line)
            except ValueError:
                continue
            if len(parts) >= 2:
                cwd = parts[1]
            continue
        try:
            parts = shlex.split(line)
        except ValueError:
            continue
        if not parts:
            continue
        while parts and _is_env_assignment(parts[0]):
            key, value = parts.pop(0).split("=", 1)
            env[key] = value
        if len(parts) >= 3 and parts[0] == "timeout":
            parts = parts[2:]
        if not parts:
            continue
        if parts[0] in ignored_commands:
            continue
        if not _looks_like_target_command(parts[0]):
            continue
        executable = parts[0]
        if executable.startswith("./"):
            executable = str(Path(cwd) / executable[2:])
        elif not executable.startswith("/"):
            executable = str(Path(cwd) / executable)
        if not executable.startswith("/"):
            continue
        return executable, parts[1:], cwd, env
    return "", [], cwd, env


def extract_markdown_code_blocks(text: str) -> list[str]:
    return [match.group(1).strip("\n") for match in re.finditer(r"```(?:[A-Za-z0-9_+-]+)?\n(.*?)```", text, flags=re.S)]


def likely_source_poc(block: str) -> bool:
    lowered = block.lower()
    bad_tokens = ("addresssanitizer", "summary:", "==", "commit", "build", "environment", "$ ")
    good_tokens = ("function ", "var ", "const ", "1.times", "def ", "times{", "#include")
    return any(token in lowered for token in good_tokens) and not any(token in lowered for token in bad_tokens)


def write_best_effort_testcase(row: dict[str, Any], case_dir: Path, args: list[str]) -> dict[str, Any]:
    testcase_dir = case_dir / "testcase"
    testcase_dir.mkdir(parents=True, exist_ok=True)
    bug_report = str(row.get("bug_report") or "")
    written: list[str] = []

    for arg in args:
        if not arg.startswith("/testcase/"):
            continue
        rel = arg.removeprefix("/testcase/")
        target = testcase_dir / rel
        target.parent.mkdir(parents=True, exist_ok=True)

        base64_match = re.search(r'echo\s+-ne\s+"([^"]+)"\s*\|\s*base64\s+-d\s*>\s*' + re.escape(rel), bug_report)
        if base64_match:
            target.write_bytes(base64.b64decode(base64_match.group(1)))
            written.append(rel)
            continue

        blocks = [block for block in extract_markdown_code_blocks(bug_report) if likely_source_poc(block)]
        if blocks and target.suffix in {".js", ".rb", ".c", ".cc", ".cpp", ""}:
            target.write_text(blocks[0].rstrip() + "\n", encoding="utf-8")
            written.append(rel)

    if not written:
        (case_dir / "MISSING_TESTCASE.md").write_text(
            "No testcase file was embedded in the Hugging Face row.\n"
            "Create the files referenced by the repro command under this directory's `testcase/` folder.\n",
            encoding="utf-8",
        )

    return {"written_testcases": written, "missing_testcase": not bool(written)}


def normalize_dockerfile(dockerfile: str) -> str:
    proxy_reset = "ENV http_proxy= https_proxy= HTTP_PROXY= HTTPS_PROXY= all_proxy= ALL_PROXY= no_proxy= NO_PROXY="
    unset_proxy = "unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY all_proxy ALL_PROXY no_proxy NO_PROXY;"
    lines = dockerfile.splitlines()
    for index, line in enumerate(lines):
        stripped = line.strip()
        if line.strip().upper().startswith("FROM "):
            if index + 1 >= len(lines) or lines[index + 1] != proxy_reset:
                lines.insert(index + 1, proxy_reset)
            break
    for index, line in enumerate(lines):
        stripped = line.lstrip()
        indent = line[: len(line) - len(stripped)]
        if stripped.startswith("RUN ") and "apt-get" in stripped and unset_proxy not in stripped:
            lines[index] = f"{indent}RUN {unset_proxy} {stripped.removeprefix('RUN ')}"
        elif stripped.startswith("RUN git ") and unset_proxy not in stripped:
            lines[index] = f"{indent}RUN {unset_proxy} {stripped.removeprefix('RUN ')}"
    return "\n".join(lines) + "\n"


def prepare_case(row: dict[str, Any], root: Path, profiles_dir: Path) -> dict[str, Any]:
    tag = safe_tag(str(row["instance_id"]))
    case_dir = root / "cases" / tag
    case_dir.mkdir(parents=True, exist_ok=True)

    executable, args, cwd, env = parse_repro_command(row)
    (case_dir / "Dockerfile").write_text(normalize_dockerfile(str(row.get("dockerfile") or "")), encoding="utf-8")
    (case_dir / "build.sh").write_text(str(row.get("build_sh") or ""), encoding="utf-8")
    (case_dir / "secb").write_text(str(row.get("secb_sh") or ""), encoding="utf-8")
    patch_text = str(row.get("patch") or "")
    (case_dir / "model_patch.diff").write_text(patch_text, encoding="utf-8")
    (case_dir / "row.json").write_text(json.dumps(row, indent=2, ensure_ascii=False), encoding="utf-8")

    testcase_info = write_best_effort_testcase(row, case_dir, args)
    (case_dir / "testcase" / "model_patch.diff").write_text(patch_text, encoding="utf-8")
    build_cmd = (
        "if [ -d src ] && grep -Rqs -- '-Werror' src 2>/dev/null "
        "&& grep -Rqs 'UPX' src 2>/dev/null; then "
        "find src -maxdepth 3 -type f \\( -name 'Makefile*' -o -name '*.mk' \\) "
        "-exec sed -i 's/[[:space:]]-Werror/ -Wno-error/g' {} +; "
        "fi; "
        "if [ -f main/reentrancy.c ] && grep -q 'readdir_r(dirp, entry);' main/reentrancy.c; then "
        "perl -0pi -e 's/readdir_r\\(dirp, entry\\);/"
        "{ struct dirent *result = NULL; "
        "if (readdir_r(dirp, entry, \\&result) != 0) return NULL; "
        "if (result == NULL) return NULL; }/g' main/reentrancy.c; "
        "fi; "
        "for _secb_build_sh in build.sh /src/build.sh; do "
        "if [ -f \"$_secb_build_sh\" ]; then "
        "if ! grep -q CMAKE_CXX_STANDARD_REQUIRED \"$_secb_build_sh\"; then "
        "perl -0pi -e 's/(^|[;&|]\\s*)(cmake)(\\s+)/$1$2 "
        "-DCMAKE_CXX_STANDARD=14 -DCMAKE_CXX_STANDARD_REQUIRED=ON$3/gm' \"$_secb_build_sh\"; "
        "fi; "
        "if ! grep -q CMAKE_COMPILE_WARNING_AS_ERROR \"$_secb_build_sh\"; then "
        "perl -0pi -e 's/(^|[;&|]\\s*)(cmake)(\\s+)/$1$2 "
        "-DCMAKE_COMPILE_WARNING_AS_ERROR=OFF -DENABLE_WERROR=OFF -DWERROR=OFF "
        "-DWARNINGS_AS_ERRORS=OFF$3/gm' \"$_secb_build_sh\"; "
        "fi; "
        "fi; "
        "done; "
        "git submodule update --init --recursive || true; " +
        SEC_BENCH_AUTOCONF_CACHE_ENV +
        f"CMAKE_C_FLAGS='{SEC_BENCH_DEBUG_CFLAGS}' "
        f"CMAKE_CXX_FLAGS='{SEC_BENCH_DEBUG_CXXFLAGS}' "
        "CMAKE_CXX_STANDARD=14 "
        f"CFLAGS='{SEC_BENCH_DEBUG_CFLAGS}' "
        f"CXXFLAGS='{SEC_BENCH_DEBUG_CXXFLAGS}' "
        "bear /usr/local/bin/compile"
    )
    profile = {
        "runner": "secbench",
        "src": row.get("work_dir") or cwd,
        "file": executable,
        "args": args,
        "env": env,
        "functions": [],
        "build": build_cmd,
        "secbench": {
            "instance_id": row.get("instance_id"),
            "repo": row.get("repo"),
            "project_name": row.get("project_name"),
            "sanitizer": row.get("sanitizer"),
            "base_commit": row.get("base_commit"),
            "case_dir": str(case_dir),
            **testcase_info,
        },
        "bug_description": row.get("bug_description") or "",
        "bug_report": row.get("bug_report") or "",
        "constraint": "",
        "patch": "gold patch stored in SEC-bench row",
    }
    profiles_dir.mkdir(parents=True, exist_ok=True)
    (profiles_dir / f"{tag}.json").write_text(json.dumps(profile, indent=2, ensure_ascii=False), encoding="utf-8")
    return {"tag": tag, "instance_id": row.get("instance_id"), "profile": str(profiles_dir / f"{tag}.json"), **testcase_info}


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare SEC-bench CVE cases for local Angelic Agent adaptation.")
    parser.add_argument("--raw", default="workspace/secbench/raw/eval-cve.jsonl")
    parser.add_argument("--output", default="workspace/secbench")
    parser.add_argument("--profiles", default="workspace/profiles")
    parser.add_argument("--limit", type=int, default=5)
    parser.add_argument("--offset", type=int, default=0)
    args = parser.parse_args()

    raw_path = Path(args.raw)
    ensure_raw_jsonl(raw_path, CVE_URL)
    rows = load_rows(raw_path)
    selected = rows[args.offset : args.offset + args.limit]
    output_root = Path(args.output)
    profiles_dir = Path(args.profiles)
    prepared = [prepare_case(row, output_root, profiles_dir) for row in selected]

    tags_dir = output_root / "tags"
    tags_dir.mkdir(parents=True, exist_ok=True)
    tag_file = tags_dir / f"cve_{args.offset}_{args.offset + len(prepared)}.txt"
    tag_file.write_text("\n".join(item["tag"] for item in prepared) + "\n", encoding="utf-8")
    (output_root / f"prepared_cve_{args.offset}_{args.offset + len(prepared)}.json").write_text(
        json.dumps(prepared, indent=2),
        encoding="utf-8",
    )

    print(f"Prepared {len(prepared)} SEC-bench CVE cases")
    print(f"Tag file: {tag_file}")
    for item in prepared:
        status = "missing testcase" if item.get("missing_testcase") else "testcase extracted"
        print(f"- {item['tag']} ({item['instance_id']}): {status}")


if __name__ == "__main__":
    main()
