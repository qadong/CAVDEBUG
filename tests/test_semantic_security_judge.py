import json
import importlib
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STALKER_SCRIPT_PATH = str(ROOT / "stalker")
sys.path = [item for item in sys.path if item != STALKER_SCRIPT_PATH and item != str(ROOT)]
sys.path.insert(0, str(ROOT))
if "stalker" in sys.modules and not hasattr(sys.modules["stalker"], "__path__"):
    del sys.modules["stalker"]
importlib.invalidate_caches()

from stalker.judge.semantic_security import (
    aggregate_verdicts,
    build_judge_input,
    compact_diff,
    load_candidate_patches,
    normalize_verdict,
    parse_diff_files,
    parse_stack_frames,
    run_cli,
    source_cache_key,
    summarize_validation_result,
)
from scripts.secbench_prepare_source_cache import prepare_checkout, repo_cache_key
from scripts.arvo_validate_patches import stage_script, tty_fallback_command, validation_result
from scripts.arvo_prepare_semantic_judge_inputs import normalize_unified_diff_hunk_counts


class SemanticSecurityJudgeTests(unittest.TestCase):
    def test_normalize_unified_diff_repairs_missing_blank_context_count(self):
        malformed = (
            "diff --git a/a.c b/a.c\n"
            "--- a/a.c\n+++ b/a.c\n"
            "@@ -10,3 +10,3 @@\n"
            " context\n-old\n+new\n"
        )
        repaired, changed = normalize_unified_diff_hunk_counts(malformed)
        self.assertTrue(changed)
        self.assertIn("@@ -10,2 +10,2 @@", repaired)

    def test_arvo_validation_result_rejects_sanitizer_output(self):
        output = (
            "__SSC_APPLY_RC=0\n__SSC_BUILD_RC=0\n__SSC_REPLAY_RC=0\n"
            "ERROR: AddressSanitizer: heap-buffer-overflow\n"
        )
        result = validation_result("arvo-1", output, 0)
        self.assertFalse(result["success"])
        self.assertEqual(result["reason"], "poc_reproduced_or_sanitizer_reported")

    def test_arvo_validation_result_does_not_misclassify_missing_markers_as_apply_failure(self):
        result = validation_result("arvo-1", "container returned no stage markers", 0)
        self.assertFalse(result["success"])
        self.assertEqual(result["reason"], "validation_protocol_error")

    def test_arvo_validation_stage_uses_profile_build_and_environment(self):
        script = stage_script(
            {
                "src": "/src/demo",
                "env": {"DEMO_MODE": "strict"},
                "pre_build": ["prepare"],
                "build": "bear make all",
                "post_build": ["mv ../compile_commands.json .", "finish"],
            },
            "/root/workspace/candidate.diff",
            30,
        )
        self.assertIn("export DEMO_MODE=strict", script)
        self.assertIn("(prepare) && (make all) && (finish)", script)
        self.assertNotIn("compile_commands.json", script)
        self.assertIn("timeout 30 arvo", script)

        redirected = stage_script({"src": "/src/demo"}, "/tmp/p.diff", 30, "/root/workspace/result.log")
        self.assertIn("} > /root/workspace/result.log 2>&1", redirected)

    def test_arvo_tty_fallback_does_not_wait_for_stdin(self):
        command = [
            "docker", "run", "-i", "--rm", "--name", "arvo-test",
            "image", "bash", "-s",
        ]

        fallback = tty_fallback_command(command, "printf 'ran\\n' > /tmp/result")

        self.assertEqual(fallback[:4], ["script", "-q", "-e", "-c"])
        rendered = fallback[4]
        self.assertIn("docker run -i -t --rm", rendered)
        self.assertIn("bash -lc", rendered)
        self.assertIn("printf", rendered)
        self.assertNotIn("bash -s", rendered)

    def test_parse_diff_files_collects_paths_and_hunk_lines(self):
        diff = """diff --git a/src/a.c b/src/a.c
--- a/src/a.c
+++ b/src/a.c
@@ -10,6 +12,8 @@ f()
 line
diff --git a/include/a.h b/include/a.h
--- a/include/a.h
+++ b/include/a.h
@@ -1 +3 @@
"""
        files = parse_diff_files(diff)
        self.assertEqual(files[0].new_path, "src/a.c")
        self.assertEqual(files[0].hunks, (12,))
        self.assertEqual(files[1].new_path, "include/a.h")
        self.assertEqual(files[1].hunks, (3,))

    def test_parse_stack_frames_extracts_function_file_line(self):
        report = """
==1==ERROR: AddressSanitizer: heap-buffer-overflow
    #0 0x1234 in parse_header /src/project/src/parser.c:42:9
    #1 0x5678 in main /src/project/main.c:7:3
"""
        frames = parse_stack_frames(report)
        self.assertEqual(frames[0]["function"], "parse_header")
        self.assertEqual(frames[0]["line"], 42)
        self.assertEqual(frames[0]["relative_file"], "project/src/parser.c")

    def test_summarize_validation_result_marks_sanitizer_reproduction(self):
        result = summarize_validation_result(
            {
                "success": False,
                "reason": "strict failure",
                "exit_code": 1,
                "logs": "SUCCESS: Compile passed\nSUMMARY: AddressSanitizer: heap-buffer-overflow\n",
            }
        )
        self.assertEqual(result["compile_result"], "pass")
        self.assertTrue(result["poc_replay_result"]["sanitizer_reproduced"])

    def test_normalize_verdict_sets_metric_flags_from_label(self):
        verdict = normalize_verdict({"label": "Crash-site mitigation", "confidence": "certain"})
        self.assertFalse(verdict["counts_for_ssc"])
        self.assertTrue(verdict["counts_for_overfit_rate"])
        self.assertEqual(verdict["confidence"], "Low")

        secure = normalize_verdict({"label": "Alternative secure", "confidence": "High"})
        self.assertTrue(secure["counts_for_ssc"])
        self.assertFalse(secure["counts_for_overfit_rate"])

    def test_compact_diff_prefers_candidate_paths(self):
        diff = (
            "diff --git a/unrelated.c b/unrelated.c\n"
            "--- a/unrelated.c\n+++ b/unrelated.c\n"
            + "-x\n+y\n" * 200
            + "diff --git a/src/vuln.c b/src/vuln.c\n"
            "--- a/src/vuln.c\n+++ b/src/vuln.c\n"
            "@@ -1 +1 @@\n-old\n+new\n"
        )
        compacted, changed = compact_diff(diff, 500, {"src/vuln.c"})
        self.assertTrue(changed)
        self.assertIn("src/vuln.c", compacted)
        self.assertIn("diff compacted", compacted)

    def test_golden_compaction_is_independent_of_candidate_paths(self):
        golden = (
            "diff --git a/unrelated.c b/unrelated.c\n--- a/unrelated.c\n+++ b/unrelated.c\n"
            + "-x\n+y\n" * 200
            + "diff --git a/src/vuln.c b/src/vuln.c\n--- a/src/vuln.c\n+++ b/src/vuln.c\n"
            "@@ -1 +1 @@ vulnerable_parse\n-old\n+new\n"
        )
        row = {"patch": golden, "functions": ["vulnerable_parse"]}
        first = build_judge_input(
            "demo-1",
            row,
            {"diff": "diff --git a/first.c b/first.c\n@@ -1 +1 @@\n-a\n+b\n"},
            max_diff_chars=500,
        )
        second = build_judge_input(
            "demo-1",
            row,
            {"diff": "diff --git a/second.c b/second.c\n@@ -1 +1 @@\n-a\n+b\n"},
            max_diff_chars=500,
        )
        self.assertEqual(first["golden_reference_patch"]["diff"], second["golden_reference_patch"]["diff"])
        self.assertIn("src/vuln.c", first["golden_reference_patch"]["diff"])

    def test_aggregate_verdicts_requires_strict_majority(self):
        votes = [
            normalize_verdict({"label": "Alternative secure", "confidence": "High"}),
            normalize_verdict({"label": "Partial repair", "confidence": "High"}),
            normalize_verdict({"label": "Incorrect/harmful", "confidence": "High"}),
        ]
        result = aggregate_verdicts(votes)
        self.assertEqual(result["label"], "Inconclusive")
        self.assertFalse(result["counts_for_ssc"])

        majority = aggregate_verdicts([votes[0], votes[0], votes[1]])
        self.assertEqual(majority["label"], "Alternative secure")
        self.assertTrue(majority["counts_for_ssc"])

    def test_build_judge_input_uses_source_snippets_when_available(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "src"
            src.mkdir()
            (src / "parser.c").write_text(
                "int helper(void) { return 0; }\n\n"
                "int parse_header(char *p, int n) {\n"
                "  if (n < 0) return -1;\n"
                "  return p[n];\n"
                "}\n",
                encoding="utf-8",
            )
            row = {
                "instance_id": "demo.cve-1",
                "project_name": "demo",
                "bug_description": "OOB read in parse_header.",
                "sanitizer": "address",
                "sanitizer_report": "    #0 0x1234 in parse_header /src/demo/src/parser.c:5:10\n",
                "bug_report": "### Proof of concept\n```c\npoc();\n```",
                "patch": "diff --git a/src/parser.c b/src/parser.c\n@@ -3,3 +3,4 @@ parse_header\n",
            }
            data = build_judge_input(
                "demo.cve-1",
                row,
                {"diff": "diff --git a/src/parser.c b/src/parser.c\n@@ -5 +5 @@\n"},
                source_dir=root,
            )
            snippets = data["relevant_source_context"]["source_snippets"]
            self.assertTrue(snippets)
            self.assertIn("parse_header", snippets[0]["text"])

    def test_build_judge_input_locates_benchmark_vulnerability_function(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "src"
            src.mkdir()
            (src / "parser.c").write_text(
                "int vulnerable_parse(char *p, int n) {\n"
                "  return p[n];\n"
                "}\n",
                encoding="utf-8",
            )
            data = build_judge_input(
                "arvo-1",
                {"functions": ["vulnerable_parse"], "patch": ""},
                {"diff": ""},
                source_dir=root,
            )
            context = data["relevant_source_context"]
            self.assertEqual(context["vulnerability_function_locations"][0]["file"], "src/parser.c")
            self.assertIn("vulnerable_parse", context["source_snippets"][0]["text"])

    def test_build_judge_input_locates_macro_wrapped_function(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src = root / "src"
            src.mkdir()
            (src / "api.c").write_text(
                "int H3_EXPORT(cellToVertex)(int cell) {\n"
                "  return cell;\n"
                "}\n",
                encoding="utf-8",
            )
            data = build_judge_input(
                "arvo-2",
                {"functions": ["cellToVertex"], "patch": ""},
                {"diff": ""},
                source_dir=root,
            )
            locations = data["relevant_source_context"]["vulnerability_function_locations"]
            self.assertEqual(locations[0]["file"], "src/api.c")

    def test_build_judge_input_uses_source_cache_dir(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cache = root / "cache"
            key = source_cache_key("owner/demo", "0123456789abcdef")
            checkout = cache / key
            src = checkout / "src"
            src.mkdir(parents=True)
            (src / "parser.c").write_text(
                "int parse_header(char *p, int n) {\n"
                "  if (n < 0) return -1;\n"
                "  return p[n];\n"
                "}\n",
                encoding="utf-8",
            )
            row = {
                "instance_id": "demo.cve-1",
                "repo": "owner/demo",
                "base_commit": "0123456789abcdef",
                "sanitizer_report": "    #0 0x1234 in parse_header /src/demo/src/parser.c:3:10\n",
                "patch": "diff --git a/src/parser.c b/src/parser.c\n@@ -2,3 +2,4 @@ parse_header\n",
            }
            data = build_judge_input(
                "demo.cve-1",
                row,
                {"diff": "diff --git a/src/parser.c b/src/parser.c\n@@ -3 +3 @@\n"},
                source_cache_dir=cache,
            )
            self.assertEqual(data["judge_metadata"]["source_dir"], str(checkout))
            snippets = data["relevant_source_context"]["source_snippets"]
            self.assertTrue(snippets)
            self.assertIn("parse_header", snippets[0]["text"])

    def test_cli_dry_run_writes_input_and_prompt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            raw = root / "raw.jsonl"
            patch_json = root / "patch.json"
            out = root / "out"
            row = {
                "instance_id": "demo.cve-1",
                "project_name": "demo",
                "bug_description": "bug",
                "sanitizer_report": "    #0 0x1234 in f /src/demo/a.c:1:1\n",
                "patch": "diff --git a/a.c b/a.c\n@@ -1 +1 @@\n",
            }
            raw.write_text(json.dumps(row) + "\n", encoding="utf-8")
            patch_json.write_text(
                json.dumps([{"instance_id": "demo.cve-1", "model_patch": "diff --git a/a.c b/a.c\n@@ -1 +1 @@\n"}]),
                encoding="utf-8",
            )

            code = run_cli(
                [
                    "--secbench-raw",
                    str(raw),
                    "--patch-json",
                    str(patch_json),
                    "--instance-id",
                    "demo.cve-1",
                    "--output-dir",
                    str(out),
                    "--workers",
                    "2",
                    "--dry-run",
                ]
            )
            self.assertEqual(code, 0)
            self.assertTrue((out / "demo.cve-1.input.json").exists())
            self.assertTrue((out / "demo.cve-1.prompt.txt").exists())

    def test_cli_anonymous_candidate_removes_metadata_from_prompt_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            raw = root / "raw.jsonl"
            patch_json = root / "patch.json"
            out = root / "out"
            raw.write_text(
                json.dumps({"instance_id": "demo.cve-1", "patch": "golden"}) + "\n",
                encoding="utf-8",
            )
            patch_json.write_text(
                json.dumps(
                    [
                        {
                            "instance_id": "demo.cve-1",
                            "model_patch": "candidate",
                            "metadata": {"source": "full-pipeline-secret"},
                        }
                    ]
                ),
                encoding="utf-8",
            )

            code = run_cli(
                [
                    "--secbench-raw",
                    str(raw),
                    "--patch-json",
                    str(patch_json),
                    "--output-dir",
                    str(out),
                    "--anonymous-candidate",
                    "--dry-run",
                ]
            )

            self.assertEqual(code, 0)
            saved_input = json.loads((out / "demo.cve-1.input.json").read_text(encoding="utf-8"))
            self.assertEqual(saved_input["judge_metadata"]["candidate_metadata"]["source"], "full-pipeline-secret")
            prompt = (out / "demo.cve-1.prompt.txt").read_text(encoding="utf-8")
            self.assertNotIn("candidate_metadata", prompt)
            self.assertNotIn("full-pipeline-secret", prompt)

    def test_load_candidate_patches_supports_aider_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "patch.json"
            path.write_text(
                json.dumps([{"instance_id": "x", "model_patch": "diff", "metadata": {"tag": "t"}}]),
                encoding="utf-8",
            )
            patches = load_candidate_patches(path)
            self.assertEqual(patches["x"]["diff"], "diff")
            self.assertEqual(patches["x"]["metadata"]["tag"], "t")

    def test_source_cache_repo_key_and_existing_checkout_fast_path(self):
        self.assertEqual(repo_cache_key("owner/name"), "owner_name")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            commit = "0123456789abcdef"
            dest = root / source_cache_key("owner/name", commit)
            (dest / ".git").mkdir(parents=True)
            with mock.patch("scripts.secbench_prepare_source_cache.checkout_head", return_value=commit), mock.patch(
                "scripts.secbench_prepare_source_cache.run_git"
            ) as run_git:
                result = prepare_checkout(
                    "owner/name",
                    commit,
                    root,
                    root / "_repos" / "owner_name.git",
                    "https://example.invalid/{repo}.git",
                    force=False,
                )
            self.assertEqual(result["cache_mode"], "existing")
            run_git.assert_not_called()

    def test_source_cache_worktree_destination_is_absolute(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output_dir = root / "relative-cache"
            mirror = output_dir / "_repos" / "owner_name.git"
            mirror.mkdir(parents=True)
            commit = "0123456789abcdef"

            with mock.patch("scripts.secbench_prepare_source_cache.run_git") as run_git:
                result = prepare_checkout(
                    "owner/name",
                    commit,
                    output_dir,
                    mirror,
                    "https://example.invalid/{repo}.git",
                    force=False,
                )

            expected = (output_dir / source_cache_key("owner/name", commit)).resolve()
            self.assertEqual(result["source_dir"], str(expected))
            self.assertEqual(run_git.call_args_list[-1].args[0][-2:], [str(expected), commit])


if __name__ == "__main__":
    unittest.main()
