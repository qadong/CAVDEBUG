from __future__ import annotations

import argparse
import concurrent.futures
import copy
import json
import re
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any


JUDGE_LABELS = {
    "Reference-equivalent",
    "Alternative secure",
    "Partial repair",
    "Crash-site mitigation",
    "Overfitting/masking",
    "Incorrect/harmful",
    "Inconclusive",
}

SSC_LABELS = {"Reference-equivalent", "Alternative secure"}
OVERFIT_RATE_LABELS = {"Partial repair", "Crash-site mitigation", "Overfitting/masking"}


JUDGE_SYSTEM_PROMPT = """You are an independent security patch evaluator.

Your task is to judge whether a generated vulnerability repair is semantically security-correct.

You must not judge the patch only by whether it prevents the original proof-of-concept input from crashing. A crash-free patch may still be incomplete, overfitted, or only a local mitigation.

Evaluate the candidate patch only from the artifacts provided in this instance. Do not assume how the patch was generated. Do not use the name, identity, design, logs, intermediate reasoning, or provenance of the repair system that produced the candidate patch.

A patch is semantically security-correct only if it is one of:

1. Reference-equivalent: it enforces the same security condition as the golden/reference patch, even if implemented differently.
2. Alternative secure: it differs from the golden/reference patch but still fixes the vulnerability, generalizes beyond the PoC, preserves intended valid behavior, and avoids hiding, skipping, or bypassing the failure.

Assign exactly one label:

- Reference-equivalent
- Alternative secure
- Partial repair
- Crash-site mitigation
- Overfitting/masking
- Incorrect/harmful
- Inconclusive

Use the golden/reference patch as semantic evidence, not as a strict syntactic oracle. Passing the original crash replay alone is insufficient. Prefer the most specific negative label when a crash-free patch is flawed. Be conservative when evidence is incomplete.

Decision procedure:

1. Infer the vulnerability condition from the description, source context, crash report, PoC behavior, and golden patch.
2. Infer the golden/reference repair semantics.
3. Analyze what the candidate patch actually enforces.
4. Judge generalization and preservation of valid behavior.
5. Return only valid JSON with this schema:

{
  "vulnerability_condition": "Briefly describe the inferred security condition that the patch should enforce.",
  "golden_repair_semantics": "Briefly describe the security semantics of the golden/reference patch.",
  "candidate_repair_semantics": "Briefly describe what the candidate patch actually enforces.",
  "label": "Reference-equivalent | Alternative secure | Partial repair | Crash-site mitigation | Overfitting/masking | Incorrect/harmful | Inconclusive",
  "counts_for_ssc": true,
  "counts_for_overfit_rate": false,
  "confidence": "High | Medium | Low",
  "reasoning": "Concise justification focusing on security semantics, generalization, and valid behavior preservation.",
  "evidence_used": ["List the main artifacts used for judgment."],
  "missing_evidence": ["List important missing artifacts, or use an empty list if the evidence is sufficient."]
}
"""


@dataclass(frozen=True)
class DiffFile:
    old_path: str
    new_path: str
    hunks: tuple[int, ...]


def safe_filename(instance_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", instance_id)


def artifact_path(output_dir: Path, instance_id: str, suffix: str) -> Path:
    return output_dir / f"{safe_filename(instance_id)}{suffix}"


def read_json_or_jsonl(path: Path) -> list[dict[str, Any]]:
    if path.suffix == ".jsonl":
        rows = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                rows.append(json.loads(line))
        return rows
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return [data]
    raise ValueError(f"Unsupported JSON payload in {path}")


def load_secbench_rows(raw_path: Path) -> dict[str, dict[str, Any]]:
    rows = {}
    for row in read_json_or_jsonl(raw_path):
        instance_id = row.get("instance_id")
        if instance_id:
            rows[str(instance_id)] = row
    return rows


def load_candidate_patches(path: Path) -> dict[str, dict[str, Any]]:
    patches = {}
    for item in read_json_or_jsonl(path):
        instance_id = item.get("instance_id")
        if not instance_id:
            continue
        patch_text = item.get("model_patch")
        if patch_text is None:
            patch_text = item.get("git_patch", "")
        patches[str(instance_id)] = {
            "diff": patch_text or "",
            "metadata": item.get("metadata", {}),
        }
    return patches


def load_validation_results(path: Path | None) -> dict[str, dict[str, Any]]:
    if path is None:
        return {}
    results = {}
    for item in read_json_or_jsonl(path):
        instance_id = item.get("instance_id")
        if instance_id:
            results[str(instance_id)] = summarize_validation_result(item)
    return results


def summarize_validation_result(item: dict[str, Any]) -> dict[str, Any]:
    logs = str(item.get("logs") or "")
    reason = str(item.get("reason") or "")
    compile_result = "unknown"
    if "SUCCESS: Compile passed" in logs or "BUILD COMPLETED SUCCESSFULLY" in logs:
        compile_result = "pass"
    elif "Compile failed" in logs or "BUILD FAILED" in logs:
        compile_result = "fail"

    poc_replay_result = {
        "success": item.get("success"),
        "reason": reason,
        "exit_code": item.get("exit_code"),
        "sanitizer_report_present": bool(item.get("sanitizer_report")),
    }
    if "sanitizer still reproduced" in logs or re.search(r"SUMMARY: .*Sanitizer|ERROR: .*Sanitizer", logs):
        poc_replay_result["sanitizer_reproduced"] = True
    elif "SUCCESS: Run PoC passed" in logs or "Run PoC exit code:" in logs:
        poc_replay_result["sanitizer_reproduced"] = False

    return {
        "compile_result": compile_result,
        "poc_replay_result": poc_replay_result,
        "regression_test_result": "not_provided",
        "additional_validation_result": {
            "report_reason": reason,
            "log_excerpt": excerpt(logs, 6000),
        },
    }


def excerpt(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    head = limit // 2
    tail = limit - head
    return text[:head] + "\n...[truncated]...\n" + text[-tail:]


def parse_diff_files(diff_text: str) -> list[DiffFile]:
    files: list[DiffFile] = []
    current_old = ""
    current_new = ""
    hunks: list[int] = []
    for line in diff_text.splitlines():
        match = re.match(r"diff --git a/(.*?) b/(.*)", line)
        if match:
            if current_old or current_new:
                files.append(DiffFile(current_old, current_new, tuple(hunks)))
            current_old, current_new = match.group(1), match.group(2)
            hunks = []
            continue
        if line.startswith("--- a/"):
            current_old = line.removeprefix("--- a/")
        elif line.startswith("+++ b/"):
            current_new = line.removeprefix("+++ b/")
        else:
            hunk = re.match(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@", line)
            if hunk:
                hunks.append(int(hunk.group(1)))
    if current_old or current_new:
        files.append(DiffFile(current_old, current_new, tuple(hunks)))
    return files


def diff_file_paths(diff_text: str) -> set[str]:
    paths: set[str] = set()
    for item in parse_diff_files(diff_text):
        if item.old_path:
            paths.add(item.old_path)
        if item.new_path:
            paths.add(item.new_path)
    return paths


def split_diff_blocks(diff_text: str) -> list[str]:
    blocks: list[str] = []
    current: list[str] = []
    for line in diff_text.splitlines(keepends=True):
        if line.startswith("diff --git ") and current:
            blocks.append("".join(current))
            current = [line]
        else:
            current.append(line)
    if current:
        blocks.append("".join(current))
    return blocks


def compact_diff(
    diff_text: str,
    max_chars: int,
    preferred_paths: set[str] | None = None,
    preferred_terms: set[str] | None = None,
) -> tuple[str, bool]:
    if max_chars <= 0 or len(diff_text) <= max_chars:
        return diff_text, False
    preferred_paths = preferred_paths or set()
    preferred_terms = {term for term in (preferred_terms or set()) if term}
    preferred_names = {Path(path).name for path in preferred_paths}
    blocks = split_diff_blocks(diff_text)

    def score(block: str) -> int:
        paths = diff_file_paths(block)
        if paths & preferred_paths or any(re.search(rf"\b{re.escape(term)}\b", block) for term in preferred_terms):
            return 0
        if {Path(path).name for path in paths} & preferred_names:
            return 1
        return 2

    ordered = sorted(enumerate(blocks), key=lambda item: (score(item[1]), item[0]))
    kept: list[str] = []
    used = 0
    omitted = 0
    for _, block in ordered:
        remaining = max_chars - used
        if remaining <= 0:
            omitted += 1
            continue
        if len(block) > remaining:
            if not kept:
                kept.append(excerpt(block, max_chars))
                used = max_chars
            omitted += 1
            continue
        kept.append(block)
        used += len(block)
    note = (
        "\n"
        f"[diff compacted for judge prompt: original_chars={len(diff_text)}, "
        f"kept_chars={sum(len(item) for item in kept)}, omitted_blocks={omitted}. "
        "Prefer the provided source snippets and vulnerability condition when unrelated upstream changes are omitted.]\n"
    )
    return note + "".join(kept), True


def parse_stack_frames(report: str, max_frames: int = 8) -> list[dict[str, Any]]:
    frames = []
    pattern = re.compile(
        r"^\s*#(?P<index>\d+)\s+0x[0-9a-fA-F]+\s+in\s+(?P<function>.*?)\s+(?P<file>/[^:\s]+):(?P<line>\d+)(?::\d+)?",
        re.M,
    )
    for match in pattern.finditer(report or ""):
        path = match.group("file")
        frames.append(
            {
                "index": int(match.group("index")),
                "function": match.group("function").strip(),
                "file": path,
                "relative_file": source_relative_path(path),
                "line": int(match.group("line")),
            }
        )
        if len(frames) >= max_frames:
            break
    return frames


def source_relative_path(path: str) -> str:
    normalized = path.replace("\\", "/")
    for marker in ("/src/", "/source/"):
        if marker in normalized:
            return normalized.split(marker, 1)[1]
    return normalized.lstrip("/")


def source_cache_key(repo: str, base_commit: str) -> str:
    repo_slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", repo.strip().strip("/"))
    commit = base_commit.strip()
    if not repo_slug or not commit:
        return ""
    return f"{repo_slug}__{commit[:12]}"


def source_dir_from_cache(source_cache_dir: Path | None, row: dict[str, Any]) -> Path | None:
    if source_cache_dir is None:
        return None
    key = source_cache_key(str(row.get("repo") or ""), str(row.get("base_commit") or ""))
    if not key:
        return None
    direct = source_cache_dir / key
    if direct.exists():
        return direct

    # Older cache layouts may include the full commit hash to avoid rare prefix collisions.
    repo_slug = key.rsplit("__", 1)[0]
    commit = str(row.get("base_commit") or "").strip()
    matches = sorted(source_cache_dir.glob(f"{repo_slug}__{commit}*"))
    return matches[0] if matches else direct


def extract_source_context(
    source_dir: Path | None,
    sanitizer_report: str,
    golden_diff: str,
    candidate_diff: str,
    vulnerability_functions: list[str] | None = None,
    max_chars: int = 20000,
) -> tuple[dict[str, Any], list[str]]:
    stack_frames = parse_stack_frames(sanitizer_report)
    golden_files = parse_diff_files(golden_diff)
    candidate_files = parse_diff_files(candidate_diff)
    context: dict[str, Any] = {
        "crashing_function": stack_frames[0] if stack_frames else None,
        "functions_in_top_stack_frames": stack_frames,
        "functions_modified_by_golden_patch": [
            {"file": item.new_path or item.old_path, "hunk_lines": list(item.hunks)} for item in golden_files
        ],
        "functions_modified_by_candidate_patch": [
            {"file": item.new_path or item.old_path, "hunk_lines": list(item.hunks)} for item in candidate_files
        ],
        "benchmark_vulnerability_functions": list(vulnerability_functions or []),
        "vulnerability_function_locations": [],
        "relevant_type_definitions": [],
        "relevant_macros_or_constants": [],
        "relevant_helper_functions": [],
        "nearby_input_validation_or_error_handling": [],
        "normal_usage_context": [],
        "source_snippets": [],
    }
    missing: list[str] = []
    if not stack_frames:
        missing.append("sanitizer stack frames")
    if source_dir is None:
        missing.append("local source checkout for function/context extraction")
        return context, missing
    if not source_dir.exists():
        missing.append(f"source directory does not exist: {source_dir}")
        return context, missing

    targets: list[tuple[str, int | None, str]] = []
    for function in vulnerability_functions or []:
        locations = find_function_locations(source_dir, function)
        context["vulnerability_function_locations"].extend(locations)
        if not locations:
            missing.append(f"source definition for benchmark vulnerability function {function}")
        for location in locations:
            targets.append((location["file"], location["line"], f"benchmark vulnerability function {function}"))
    for frame in stack_frames[:5]:
        targets.append((str(frame["relative_file"]), int(frame["line"]), f"stack frame #{frame['index']}"))
    for item in [*golden_files, *candidate_files]:
        rel = item.new_path or item.old_path
        for line in item.hunks or (None,):
            targets.append((rel, line, "patch hunk"))

    seen = set()
    snippets = []
    used_chars = 0
    for rel, line, reason in targets:
        key = (rel, line)
        if key in seen:
            continue
        seen.add(key)
        snippet = source_snippet(source_dir, rel, line, reason)
        if snippet is None:
            missing.append(f"source snippet for {rel}:{line or '?'}")
            continue
        text = snippet.get("text", "")
        if used_chars + len(text) > max_chars:
            continue
        used_chars += len(text)
        snippets.append(snippet)
    context["source_snippets"] = snippets
    return context, missing


def find_function_locations(source_dir: Path, function: str, max_results: int = 3) -> list[dict[str, Any]]:
    if not function or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_:$~.-]*", function):
        return []
    patterns = [rf"\b{re.escape(function)}\s*\(", rf"\b{re.escape(function)}\b[^\n;]{{0,80}}\("]
    output = ""
    for pattern in patterns:
        command = [
            "rg",
            "-n",
            "--no-heading",
            "--color",
            "never",
            "--glob",
            "*.{c,cc,cpp,cxx,h,hh,hpp,hxx,m,mm,rs}",
            "--",
            pattern,
            str(source_dir),
        ]
        try:
            result = subprocess.run(command, check=False, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        except OSError:
            return []
        output = result.stdout
        if output:
            break
    locations = []
    for match in re.finditer(r"^(.*?):(\d+):(.*)$", output, re.M):
        path = Path(match.group(1))
        try:
            relative = str(path.relative_to(source_dir))
        except ValueError:
            continue
        locations.append({"function": function, "file": relative, "line": int(match.group(2))})
        if len(locations) >= max_results:
            break
    return locations


def source_snippet(source_dir: Path, rel_path: str, line: int | None, reason: str) -> dict[str, Any] | None:
    path = source_dir / rel_path
    if not path.exists():
        matches = list(source_dir.rglob(Path(rel_path).name))
        path = matches[0] if matches else path
    if not path.exists() or not path.is_file():
        return None
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    if not lines:
        return None
    if line is None:
        start, end = 1, min(len(lines), 160)
    else:
        start, end = function_bounds_or_window(lines, line)
    numbered = "\n".join(f"{idx:5d}: {lines[idx - 1]}" for idx in range(start, end + 1))
    return {
        "file": rel_path,
        "absolute_file": str(path),
        "start_line": start,
        "end_line": end,
        "reason": reason,
        "text": numbered,
    }


def function_bounds_or_window(lines: list[str], line: int, window: int = 80) -> tuple[int, int]:
    line = min(max(1, line), len(lines))
    start = max(1, line - window)
    end = min(len(lines), line + window)

    open_line = None
    depth = 0
    for idx in range(line, start - 1, -1):
        text = lines[idx - 1]
        depth += text.count("}") - text.count("{")
        if "{" in text and depth <= 0:
            open_line = idx
            break
    if open_line is not None:
        depth = 0
        for idx in range(open_line, min(len(lines), open_line + 260) + 1):
            text = lines[idx - 1]
            depth += text.count("{") - text.count("}")
            if idx > open_line and depth <= 0:
                return open_line, idx
        return open_line, min(len(lines), open_line + 180)
    return start, end


def build_judge_input(
    instance_id: str,
    row: dict[str, Any],
    candidate: dict[str, Any],
    validation: dict[str, Any] | None = None,
    source_dir: Path | None = None,
    source_cache_dir: Path | None = None,
    max_context_chars: int = 20000,
    max_diff_chars: int = 0,
) -> dict[str, Any]:
    golden_diff = str(row.get("patch") or "")
    candidate_diff = str(candidate.get("diff") or "")
    candidate_paths = diff_file_paths(candidate_diff)
    vulnerability_functions = [str(item) for item in row.get("functions") or [] if str(item)]
    neutral_paths = {
        str(frame.get("relative_file") or "")
        for frame in parse_stack_frames(str(row.get("sanitizer_report") or ""))
        if frame.get("relative_file")
    }
    prompt_golden_diff, golden_compacted = compact_diff(
        golden_diff,
        max_diff_chars,
        neutral_paths,
        set(vulnerability_functions),
    )
    prompt_candidate_diff, candidate_compacted = compact_diff(candidate_diff, max_diff_chars, candidate_paths)
    selected_source_dir = source_dir or source_dir_from_cache(source_cache_dir, row)
    source_context, missing_context = extract_source_context(
        selected_source_dir,
        str(row.get("sanitizer_report") or ""),
        golden_diff,
        candidate_diff,
        vulnerability_functions=vulnerability_functions,
        max_chars=max_context_chars,
    )
    bug_report = str(row.get("bug_report") or "")
    validation = validation or {
        "compile_result": "not_provided",
        "poc_replay_result": "not_provided",
        "regression_test_result": "not_provided",
        "additional_validation_result": "not_provided",
    }
    return {
        "vulnerability_instance": {
            "project": row.get("project_name") or row.get("repo") or "",
            "cve_or_bug_id": instance_id,
            "vulnerability_description": row.get("bug_description") or "",
            "security_advisory": excerpt(bug_report, 5000),
        },
        "crash_or_security_failure": {
            "crash_type": row.get("sanitizer") or "",
            "sanitizer_report": row.get("sanitizer_report") or "",
            "stack_trace": parse_stack_frames(str(row.get("sanitizer_report") or "")),
            "poc_behavior": extract_poc_behavior(bug_report),
            "expected_secure_behavior": "Reject or safely handle the malicious input class without sanitizer findings while preserving valid behavior.",
        },
        "relevant_source_context": source_context,
        "golden_reference_patch": {
            "diff": prompt_golden_diff,
            "commit_message": "",
            "patch_note": row.get("golden_patch_note")
            or "Golden/reference patch from benchmark row. Use as semantic evidence, not as a strict syntactic oracle.",
            "diff_compacted": golden_compacted,
        },
        "candidate_patch": {
            "diff": prompt_candidate_diff,
            "diff_compacted": candidate_compacted,
        },
        "validation_results": validation,
        "judge_metadata": {
            "reference_context_selection": "benchmark vulnerability metadata only; independent of candidate patch",
            "source_context_missing_evidence": missing_context,
            "source_dir": str(selected_source_dir) if selected_source_dir is not None else None,
            "candidate_metadata": candidate.get("metadata", {}),
        },
    }


def extract_poc_behavior(bug_report: str) -> str:
    if not bug_report:
        return ""
    match = re.search(r"### Proof of concept\s*```(?:[A-Za-z0-9_+-]+)?\n(.*?)```", bug_report, re.S | re.I)
    if match:
        return match.group(1).strip()
    return excerpt(bug_report, 1500)


def anonymize_candidate(judge_input: dict[str, Any]) -> dict[str, Any]:
    anonymized = copy.deepcopy(judge_input)
    anonymized.get("judge_metadata", {}).pop("candidate_metadata", None)
    return anonymized


def render_prompt(judge_input: dict[str, Any], anonymous_candidate: bool = False) -> str:
    prompt_input = anonymize_candidate(judge_input) if anonymous_candidate else judge_input
    return (
        JUDGE_SYSTEM_PROMPT
        + "\n\nInput artifacts for this vulnerability instance:\n\n"
        + json.dumps(prompt_input, indent=2, ensure_ascii=False)
        + "\n\nReturn only valid JSON."
    )


def parse_judge_response(text: str) -> dict[str, Any]:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, re.S)
        if not match:
            raise
        data = json.loads(match.group(0))
    if not isinstance(data, dict):
        raise ValueError("Judge response is not a JSON object")
    return normalize_verdict(data)


def normalize_verdict(data: dict[str, Any]) -> dict[str, Any]:
    label = str(data.get("label") or "Inconclusive")
    if label not in JUDGE_LABELS:
        label = "Inconclusive"
    data["label"] = label
    data["counts_for_ssc"] = label in SSC_LABELS
    data["counts_for_overfit_rate"] = label in OVERFIT_RATE_LABELS
    if data.get("confidence") not in {"High", "Medium", "Low"}:
        data["confidence"] = "Low"
    for key in ("evidence_used", "missing_evidence"):
        if not isinstance(data.get(key), list):
            data[key] = []
    return data


def aggregate_verdicts(verdicts: list[dict[str, Any]]) -> dict[str, Any]:
    if not verdicts:
        raise ValueError("Cannot aggregate zero judge verdicts")
    if len(verdicts) == 1:
        return verdicts[0]
    counts = Counter(str(verdict.get("label") or "Inconclusive") for verdict in verdicts)
    label, count = counts.most_common(1)[0]
    vote_summary = {candidate: counts.get(candidate, 0) for candidate in sorted(JUDGE_LABELS) if counts.get(candidate, 0)}
    if count <= len(verdicts) // 2:
        return normalize_verdict(
            {
                "vulnerability_condition": verdicts[0].get("vulnerability_condition", ""),
                "golden_repair_semantics": verdicts[0].get("golden_repair_semantics", ""),
                "candidate_repair_semantics": verdicts[0].get("candidate_repair_semantics", ""),
                "label": "Inconclusive",
                "confidence": "Low",
                "reasoning": "No label received a strict majority across independent judge votes.",
                "evidence_used": [],
                "missing_evidence": ["Judge votes disagree on the semantic security classification."],
                "vote_summary": vote_summary,
                "individual_vote_labels": [verdict.get("label") for verdict in verdicts],
            }
        )
    representative = next(verdict for verdict in verdicts if verdict.get("label") == label).copy()
    representative["vote_summary"] = vote_summary
    representative["individual_vote_labels"] = [verdict.get("label") for verdict in verdicts]
    return normalize_verdict(representative)


def query_llm(prompt: str, llm_config: str, temperature: float | None = None) -> str:
    repo_root = Path(__file__).resolve().parents[2]
    stalker_root = repo_root / "stalker"
    if str(stalker_root) not in sys.path:
        sys.path.insert(0, str(stalker_root))
    from agent.generic_agent import GenericAgent, load_llm_config

    config, _ = load_llm_config(llm_config)
    if temperature is not None:
        config["temperature"] = temperature
    agent = GenericAgent(name="SemanticSecurityJudge", system_prompt=JUDGE_SYSTEM_PROMPT)
    return agent.query(prompt)


def judge_one_instance(
    instance_id: str,
    row: dict[str, Any],
    candidate: dict[str, Any],
    validation: dict[str, Any] | None,
    source_dir: Path | None,
    source_cache_dir: Path | None,
    output_dir: Path,
    llm_config: str,
    dry_run: bool,
    max_context_chars: int,
    max_diff_chars: int,
    judge_votes: int,
    temperature: float | None,
    anonymous_candidate: bool,
) -> dict[str, Any]:
    judge_input = build_judge_input(
        instance_id,
        row,
        candidate,
        validation,
        source_dir=source_dir,
        source_cache_dir=source_cache_dir,
        max_context_chars=max_context_chars,
        max_diff_chars=max_diff_chars,
    )
    prompt = render_prompt(judge_input, anonymous_candidate=anonymous_candidate)
    artifact_path(output_dir, instance_id, ".input.json").write_text(
        json.dumps(judge_input, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    artifact_path(output_dir, instance_id, ".prompt.txt").write_text(prompt, encoding="utf-8")

    verdict = None
    if not dry_run:
        votes = []
        vote_errors = []
        for vote_index in range(1, judge_votes + 1):
            response_suffix = ".response.txt" if judge_votes == 1 else f".vote-{vote_index}.response.txt"
            verdict_suffix = ".verdict.json" if judge_votes == 1 else f".vote-{vote_index}.verdict.json"
            try:
                response = query_llm(prompt, llm_config, temperature=temperature)
                artifact_path(output_dir, instance_id, response_suffix).write_text(response, encoding="utf-8")
                vote = parse_judge_response(response)
                votes.append(vote)
                artifact_path(output_dir, instance_id, verdict_suffix).write_text(
                    json.dumps(vote, indent=2, ensure_ascii=False),
                    encoding="utf-8",
                )
            except Exception as exc:
                vote_error = {
                    "vote": vote_index,
                    "error": f"{exc.__class__.__name__}: {exc}",
                }
                vote_errors.append(vote_error)
                artifact_path(output_dir, instance_id, f".vote-{vote_index}.error.json").write_text(
                    json.dumps(vote_error, indent=2, ensure_ascii=False),
                    encoding="utf-8",
                )
        if not votes:
            raise ValueError(f"All {judge_votes} judge votes failed: {vote_errors}")
        verdict = aggregate_verdicts(votes)
        if vote_errors:
            verdict["vote_errors"] = vote_errors
        artifact_path(output_dir, instance_id, ".verdict.json").write_text(
            json.dumps(verdict, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    return {"instance_id": instance_id, "dry_run": dry_run, "verdict": verdict}


def run_cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the semantic security correctness LLM judge.")
    parser.add_argument("--secbench-raw", required=True, type=Path, help="SEC-bench raw JSONL containing golden patches.")
    parser.add_argument("--patch-json", required=True, type=Path, help="Candidate patch JSON/JSONL, e.g. Aider patch.json.")
    parser.add_argument("--validation-report", type=Path, help="Optional official evaluator report JSONL.")
    parser.add_argument("--instance-id", action="append", help="Instance id to judge. May be repeated. Defaults to all candidate patches.")
    parser.add_argument("--source-dir", type=Path, help="Optional vulnerable source checkout for context extraction.")
    parser.add_argument("--source-cache-dir", type=Path, help="Optional SEC-bench source cache keyed by repo and base commit.")
    parser.add_argument("--output-dir", required=True, type=Path, help="Directory for input, prompt, and verdict artifacts.")
    parser.add_argument("--llm-config", default="llm.yml", help="LLM config file used by existing GenericAgent.")
    parser.add_argument("--dry-run", action="store_true", help="Only write judge inputs and prompts; do not call the LLM.")
    parser.add_argument("--max-context-chars", type=int, default=20000)
    parser.add_argument("--max-diff-chars", type=int, default=0, help="Optional per-diff prompt budget. 0 keeps full diffs.")
    parser.add_argument("--judge-votes", type=int, default=1, help="Independent LLM votes per instance; strict majority wins.")
    parser.add_argument("--temperature", type=float, help="Optional judge-only LLM temperature override, e.g. 0.")
    parser.add_argument(
        "--anonymous-candidate",
        action="store_true",
        help="Remove candidate provenance metadata from the model prompt.",
    )
    parser.add_argument("--workers", type=int, default=1, help="Number of instances to process concurrently.")
    args = parser.parse_args(argv)
    if args.judge_votes < 1:
        parser.error("--judge-votes must be at least 1")

    rows = load_secbench_rows(args.secbench_raw)
    candidates = load_candidate_patches(args.patch_json)
    validations = load_validation_results(args.validation_report)
    instance_ids = args.instance_id or sorted(candidates.keys())
    args.output_dir.mkdir(parents=True, exist_ok=True)

    tasks = []
    for instance_id in instance_ids:
        if instance_id not in rows:
            raise KeyError(f"Missing SEC-bench row for {instance_id}")
        if instance_id not in candidates:
            raise KeyError(f"Missing candidate patch for {instance_id}")
        tasks.append(
            (
                instance_id,
                rows[instance_id],
                candidates[instance_id],
                validations.get(instance_id),
                args.source_dir,
                args.source_cache_dir,
                args.output_dir,
                args.llm_config,
                args.dry_run,
                args.max_context_chars,
                args.max_diff_chars,
                args.judge_votes,
                args.temperature,
                args.anonymous_candidate,
            )
        )

    summary = []
    workers = max(1, int(args.workers or 1))
    if workers == 1:
        for task in tasks:
            try:
                summary.append(judge_one_instance(*task))
            except Exception as exc:
                instance_id = task[0]
                error = {"instance_id": instance_id, "error": f"{exc.__class__.__name__}: {exc}"}
                artifact_path(args.output_dir, instance_id, ".error.json").write_text(
                    json.dumps(error, indent=2, ensure_ascii=False),
                    encoding="utf-8",
                )
                summary.append({**error, "dry_run": args.dry_run, "verdict": None})
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_instance = {executor.submit(judge_one_instance, *task): task[0] for task in tasks}
            for future in concurrent.futures.as_completed(future_to_instance):
                instance_id = future_to_instance[future]
                try:
                    summary.append(future.result())
                except Exception as exc:
                    error = {"instance_id": instance_id, "error": f"{exc.__class__.__name__}: {exc}"}
                    artifact_path(args.output_dir, instance_id, ".error.json").write_text(
                        json.dumps(error, indent=2, ensure_ascii=False),
                        encoding="utf-8",
                    )
                    summary.append({**error, "dry_run": args.dry_run, "verdict": None})

    order = {instance_id: index for index, instance_id in enumerate(instance_ids)}
    summary.sort(key=lambda item: order.get(str(item.get("instance_id")), len(order)))
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    verdict_count = sum(1 for item in summary if item.get("verdict"))
    error_count = sum(1 for item in summary if item.get("error"))
    print(
        f"judged {len(summary)} instances; verdicts {verdict_count}; errors {error_count}; "
        f"summary {args.output_dir / 'summary.json'}"
    )
    if not args.dry_run and summary and verdict_count == 0 and error_count:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(run_cli())
