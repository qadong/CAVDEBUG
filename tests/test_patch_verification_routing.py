import pathlib
import sys
import types
import unittest
from types import SimpleNamespace
from unittest.mock import patch


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "stalker"))
sys.modules.setdefault("coloredlogs", types.SimpleNamespace(install=lambda *a, **k: None))
sys.modules.setdefault(
    "autogen",
    types.SimpleNamespace(
        ConversableAgent=object,
        register_function=lambda *a, **k: None,
    ),
)
sys.modules.setdefault("yaml", types.SimpleNamespace(load=lambda *a, **k: {}, FullLoader=object))

from agent import patch_agent  # noqa: E402
from agent import generic_agent  # noqa: E402
from agent.layer_verify import classify_verification_outcome  # noqa: E402
from utils import verification  # noqa: E402


class PatchVerificationRoutingTests(unittest.TestCase):
    def setUp(self):
        patch_agent.reset_global_state()
        generic_agent.LLM_CONFIG = None

    def test_check_patch_uses_verify_patch_contract(self):
        patch_agent.GLOBAL_STATE["patches"] = [
            {
                "file": "/tmp/example.c",
                "start_line": 10,
                "end_line": 10,
                "patch": "if (x >= y) {",
            }
        ]
        patch_agent.GLOBAL_STATE["strategy"] = {
            "strategy": "fix_upstream_invariant",
            "location_type": "same_site",
            "rationale": "off-by-one guard",
            "semantic_risk": "low",
            "requires_regression_check": False,
        }
        patch_agent.GLOBAL_STATE["session"] = SimpleNamespace(
            _input=SimpleNamespace(
                profile={"id": "p1", "llm_verifier_enabled": True},
                constraint="x < y",
                suspect_object={
                    "debug_summary": "x should stay below y",
                    "file": "/src/example.c",
                    "line": 42,
                    "function_name": "foo",
                    "bug_type_profile": {"bug_type": "out_of_bounds"},
                    "typed_angelic_evidence": {"kind": "boundary_relation"},
                    "root_cause_report": {"preferred_repair_stage": "state_update"},
                },
            )
        )

        seen = {}

        def _fake_verify_patch_feedback(contract, expected_file=None, expected_line=None, logger=None):
            seen["contract"] = contract
            seen["expected_file"] = expected_file
            seen["expected_line"] = expected_line
            return {"status": "semantic_regression", "message": "semantic failure", "details": {}}

        with patch("agent.patch_agent.verify_patch_feedback", side_effect=_fake_verify_patch_feedback):
            ok, message = patch_agent.check_patch()

        self.assertFalse(ok)
        self.assertEqual(message, "semantic failure")
        self.assertEqual(seen["expected_file"], "/src/example.c")
        self.assertEqual(seen["expected_line"], 42)

    def test_state_only_no_angelic_submit_stops_after_three_failed_attempts(self):
        patch_agent.GLOBAL_STATE["session"] = SimpleNamespace(
            _input=SimpleNamespace(
                profile={"id": "p1", "ablation_mode": "state_only_no_angelic"},
                constraint="x < y",
                suspect_object={},
            )
        )

        raw_patch = "/tmp/example.c:10-10\nreturn -1;"
        with patch.object(patch_agent, "check_patch", return_value=(False, "still crashes")):
            first = patch_agent.submit([raw_patch])
            second = patch_agent.submit([raw_patch])
            third = patch_agent.submit([raw_patch])

        self.assertIn("Patch failed to fix the crash", first)
        self.assertIn("Patch failed to fix the crash", second)
        self.assertIn("after 3 attempts", third)
        self.assertTrue(patch_agent.GLOBAL_STATE["resign"])
        self.assertEqual(patch_agent.GLOBAL_STATE["retry"], 3)

    def test_budget_limited_full_pipeline_submit_stops_after_three_failed_attempts(self):
        patch_agent.GLOBAL_STATE["session"] = SimpleNamespace(
            _input=SimpleNamespace(
                profile={"id": "p1"},
                constraint="x < y",
                suspect_object={},
            )
        )

        raw_patch = "/tmp/example.c:10-10\nreturn -1;"
        with patch.object(patch_agent, "check_patch", return_value=(False, "still crashes")):
            first = patch_agent.submit([raw_patch])
            second = patch_agent.submit([raw_patch])
            third = patch_agent.submit([raw_patch])

        self.assertIn("Patch failed to fix the crash", first)
        self.assertIn("Patch failed to fix the crash", second)
        self.assertIn("after 3 attempts", third)
        self.assertTrue(patch_agent.GLOBAL_STATE["resign"])
        self.assertEqual(patch_agent.GLOBAL_STATE["retry"], 3)

    def test_patch_retry_feedback_includes_regression_output_tail(self):
        feedback = {
            "status": "semantic_regression",
            "message": "Patch fixes the original PoC but breaks regression inputs.",
            "blame_hint": "Patch likely changes behavior too aggressively.",
            "details": {
                "tiers": {
                    "tier3_regression": {
                        "status": "fail",
                        "items": [
                            {
                                "status": "fail",
                                "args": ["/tmp/benign"],
                                "command": "./tool /tmp/benign",
                                "return_code": 1,
                                "file": "/src/example.c",
                                "line": 17,
                                "runtime_output": "\n".join(f"line {i}" for i in range(60)),
                            }
                        ],
                    }
                }
            },
        }

        message = patch_agent._format_patch_feedback_for_retry(feedback)

        self.assertIn("Patch fixes the original PoC but breaks regression inputs.", message)
        self.assertIn("Failed replay tier: tier3_regression", message)
        self.assertIn("Failing replay args: ['/tmp/benign']", message)
        self.assertIn("Last 50 lines of failing replay output", message)
        self.assertIn("line 59", message)
        self.assertNotIn("line 0", message)

    def test_submit_success_instructs_terminate(self):
        patch_agent.GLOBAL_STATE["session"] = SimpleNamespace(
            _input=SimpleNamespace(
                profile={"id": "p1"},
                constraint="x < y",
                suspect_object={
                    "debug_summary": "x should stay below y",
                    "file": "/src/example.c",
                    "line": 42,
                    "function_name": "foo",
                },
            )
        )

        with patch("agent.patch_agent.check_patch", return_value=(True, "Patch successfully verified.")):
            message = patch_agent.submit(["/tmp/example.c:10-10\nif (x >= y) return -1;"])

        self.assertTrue(patch_agent.GLOBAL_STATE["valid"])
        self.assertIn("Patch successfully fixed the crash", message)
        self.assertIn("Patch successfully verified.", message)
        self.assertIn("MUST reply with TERMINATE", message)

    def test_successful_submit_cannot_be_overwritten_by_later_failure(self):
        patch_agent.GLOBAL_STATE["session"] = SimpleNamespace(
            _input=SimpleNamespace(
                profile={"id": "p1"},
                constraint="x < y",
                suspect_object={
                    "debug_summary": "x should stay below y",
                    "file": "/src/example.c",
                    "line": 42,
                    "function_name": "foo",
                },
            )
        )

        with patch("agent.patch_agent.check_patch", return_value=(True, "ok")) as check_patch:
            message = patch_agent.submit(["/tmp/example.c:10-10\nif (x >= y) return -1;"])
        self.assertTrue(patch_agent.GLOBAL_STATE["valid"])
        self.assertEqual(patch_agent.GLOBAL_STATE["retry"], 0)
        accepted = list(patch_agent.GLOBAL_STATE["patches"])
        self.assertIn("Patch successfully fixed the crash", message)

        with patch("agent.patch_agent.check_patch", return_value=(False, "bad")) as second_check:
            message = patch_agent.submit(["/tmp/example.c:11-11\nreturn 0;"])
        second_check.assert_not_called()
        self.assertTrue(patch_agent.GLOBAL_STATE["valid"])
        self.assertFalse(patch_agent.GLOBAL_STATE["resign"])
        self.assertEqual(patch_agent.GLOBAL_STATE["retry"], 0)
        self.assertEqual(patch_agent.GLOBAL_STATE["patches"], accepted)
        self.assertIn("already passed verification", message)
        check_patch.assert_called_once()

    def test_resign_after_success_is_ignored(self):
        patch_agent.GLOBAL_STATE["valid"] = True
        patch_agent.GLOBAL_STATE["patches"] = [
            {"file": "/tmp/example.c", "start_line": 10, "end_line": 10, "patch": "return -1;"}
        ]

        patch_agent.resign()

        self.assertFalse(patch_agent.GLOBAL_STATE["resign"])

    def test_direct_patch_assessment_prefers_llm_decision_when_available(self):
        with patch("utils.verification._judge_direct_patch_with_llm", return_value={
            "verdict": "weak",
            "recommended_next_actor": "layer2",
            "rationale": "LLM judge requested more evidence.",
            "verification_confidence": 0.61,
            "residual_risk": "needs_more_evidence",
            "root_cause_alignment": "partial",
            "source_status": "pass",
            "layer2_validation_required": True,
            "direct_patch_risk": "medium",
            "decision_source": "llm",
        }):
            assessment = verification._classify_direct_patch_assessment(
                patch={"semantic_risk": "low", "location_type": "same_site", "strategy": "fix_upstream_invariant"},
                status="pass",
                tier_report={"tier2_variants": {"status": "pass"}, "tier3_regression": {"status": "pass"}},
                obligation_summary={"unmet": [], "warnings": []},
                confidence=0.9,
                residual_risk="",
                default_next_actor="done",
                default_blame_hint="",
            )

        self.assertEqual(assessment["verdict"], "weak")
        self.assertEqual(assessment["decision_source"], "llm")

    def test_direct_patch_assessment_fails_closed_when_llm_unavailable(self):
        with patch("utils.verification._judge_direct_patch_with_llm", return_value=None):
            assessment = verification._classify_direct_patch_assessment(
                patch={
                    "semantic_risk": "low",
                    "location_type": "upstream",
                    "strategy": "fix_upstream_invariant",
                    "root_cause_report": {"direct_patch_risk": "low"},
                },
                status="pass",
                tier_report={"tier2_variants": {"status": "not_available"}, "tier3_regression": {"status": "regression_unavailable"}},
                obligation_summary={"unmet": [], "warnings": []},
                confidence=0.7,
                residual_risk="regression_unavailable",
                default_next_actor="done",
                default_blame_hint="",
            )

        self.assertEqual(assessment["decision_source"], "llm_unavailable")
        self.assertEqual(assessment["verdict"], "suspicious")
        self.assertEqual(assessment["recommended_next_actor"], "layer2")

    def test_layer_verify_respects_verifier_followup_actor(self):
        decision = classify_verification_outcome(
            candidate=None,
            feedback={
                "status": "runtime_failure",
                "recommended_next_actor": "debug",
                "blame_hint": "Need upstream root-cause review.",
            },
        )

        self.assertEqual(decision.next_actor, "debug")

    def test_collect_patch_evidence_returns_structured_failure(self):
        evidence = verification.collect_patch_evidence(
            patch={"repair_layer": "layer1"},
        )

        self.assertEqual(evidence["stage"], "invalid_patch")
        self.assertEqual(evidence["failure"]["status"], "apply_error")
        self.assertIn("patch", evidence["failure"]["recommended_next_actor"])

    def test_collect_patch_evidence_reports_missing_path_with_absolute_suggestion(self):
        submitted = "src/njs/src/njs_value.c"
        suggested = "/src/njs/src/njs_value.c"

        with patch.object(
            verification.os.path,
            "exists",
            side_effect=lambda path: path == suggested,
        ), patch.object(verification, "file_apply_patches") as apply_patches:
            evidence = verification.collect_patch_evidence(
                patch={
                    "profile": {"src": "/src/njs"},
                    "patches": [
                        {
                            "file": submitted,
                            "start_line": 1,
                            "end_line": 1,
                            "patch": "return;",
                        }
                    ],
                }
            )

        self.assertEqual(evidence["stage"], "apply_error")
        self.assertEqual(evidence["failure"]["error_signature"], "patch_file_not_found")
        self.assertIn(submitted, evidence["failure"]["message"])
        self.assertIn("current project root is /src/njs", evidence["failure"]["message"])
        self.assertIn(suggested, evidence["failure"]["message"])
        apply_patches.assert_not_called()

    def test_patch_prompts_require_exact_absolute_source_paths(self):
        system_prompt = " ".join(patch_agent.SYSTEM_PROMPT.split())
        lldb_prompt = " ".join(patch_agent.SYSTEM_PROMPT_LLDB_ONLY.split())
        self.assertIn("submitted filename is opened exactly as written", system_prompt)
        self.assertIn("submitted filename is opened exactly as written", lldb_prompt)
        self.assertIn("Do not turn `/src/<project>/...`", patch_agent.INITIAL_PROMPT)

    def test_judge_patch_evidence_applies_layer1_assessment(self):
        evidence = {
            "patch": {
                "repair_layer": "layer1",
                "semantic_risk": "low",
                "location_type": "upstream",
                "strategy": "fix_upstream_invariant",
                "root_cause_report": {"direct_patch_risk": "low"},
            },
            "bug_type_profile": {},
            "typed_angelic_evidence": {},
            "validation_obligations": [],
            "tier_report": {
                "tier1_original_poc": {"status": "pass"},
                "tier2_variants": {"status": "pass"},
                "tier3_regression": {"status": "pass"},
            },
            "obligation_summary": {"unmet": [], "warnings": []},
            "stage": "pass",
        }

        with patch("utils.verification._judge_direct_patch_with_llm", return_value={
            "verdict": "strong",
            "recommended_next_actor": "done",
            "rationale": "LLM accepted the direct patch.",
            "verification_confidence": 0.9,
            "residual_risk": "",
            "root_cause_alignment": "aligned",
            "source_status": "pass",
            "layer2_validation_required": False,
            "direct_patch_risk": "low",
            "decision_source": "llm",
        }):
            feedback = verification.judge_patch_evidence(evidence)

        self.assertEqual(feedback["status"], "pass")
        self.assertEqual(feedback["layer1_verdict"], "strong")
        self.assertEqual(feedback["direct_patch_assessment"]["decision_source"], "llm")
        self.assertEqual(feedback["recommended_next_actor"], "done")

    def test_load_llm_config_reuses_in_memory_config(self):
        generic_agent.LLM_CONFIG = {"model": "deepseek-chat", "temperature": 0.2, "reasoning_effort": "low"}

        with patch("agent.generic_agent._resolve_llm_config_path", side_effect=AssertionError("should not resolve path")):
            config, clean = generic_agent.load_llm_config()

        self.assertEqual(config["model"], "deepseek-chat")
        self.assertEqual(clean["reasoning_effort"], "low")

    def test_load_llm_config_resolves_repo_relative_workspace_path(self):
        fake_yaml = {
            "llm": {
                "select": "default",
                "profiles": [
                    {
                        "name": "default",
                        "model": "deepseek-chat",
                        "temperature": 0.2,
                        "reasoning_effort": "low",
                    }
                ],
            }
        }

        with patch("agent.generic_agent._resolve_llm_config_path", return_value="/repo/workspace/llm.yml"), \
             patch("builtins.open"), \
             patch("agent.generic_agent.yaml.load", return_value=fake_yaml):
            config, clean = generic_agent.load_llm_config()

        self.assertEqual(config["model"], "deepseek-chat")
        self.assertEqual(clean["temperature"], 0.2)

    def test_load_llm_config_resolves_api_key_from_environment(self):
        fake_yaml = {
            "llm": {
                "select": "openrouter",
                "profiles": [{
                    "name": "openrouter",
                    "base_url": "https://openrouter.ai/api/v1",
                    "api_key": "${OPENROUTER_API_KEY}",
                    "model": "deepseek/deepseek-v3.2",
                }],
            }
        }

        with patch("agent.generic_agent._resolve_llm_config_path", return_value="/repo/workspace/llm.yml"), \
             patch("builtins.open"), \
             patch("agent.generic_agent.yaml.load", return_value=fake_yaml), \
             patch.dict("agent.generic_agent.os.environ", {"OPENROUTER_API_KEY": "test-key"}):
            config, _ = generic_agent.load_llm_config()

        self.assertEqual(config["api_key"], "test-key")

    def test_load_llm_config_profile_can_be_overridden_by_environment(self):
        fake_yaml = {
            "llm": {
                "select": "openrouter",
                "profiles": [
                    {"name": "openrouter", "model": "deepseek/deepseek-v3.2"},
                    {"name": "siliconflow", "model": "Pro/deepseek-ai/DeepSeek-V3.2"},
                ],
            }
        }

        with patch("agent.generic_agent._resolve_llm_config_path", return_value="/repo/workspace/llm.yml"), \
             patch("builtins.open"), \
             patch("agent.generic_agent.yaml.load", return_value=fake_yaml), \
             patch.dict("agent.generic_agent.os.environ", {"LLM_PROFILE": "siliconflow"}):
            config, _ = generic_agent.load_llm_config()

        self.assertEqual(config["model"], "Pro/deepseek-ai/DeepSeek-V3.2")

    def test_load_llm_config_rejects_missing_environment_api_key(self):
        fake_yaml = {
            "llm": {
                "select": "openrouter",
                "profiles": [{
                    "name": "openrouter",
                    "api_key": "${OPENROUTER_API_KEY}",
                    "model": "deepseek/deepseek-v3.2",
                }],
            }
        }

        with patch("agent.generic_agent._resolve_llm_config_path", return_value="/repo/workspace/llm.yml"), \
             patch("builtins.open"), \
             patch("agent.generic_agent.yaml.load", return_value=fake_yaml), \
             patch.dict("agent.generic_agent.os.environ", {}, clear=True):
            with self.assertRaisesRegex(ValueError, "OPENROUTER_API_KEY"):
                generic_agent.load_llm_config()

    def test_cache_read_price_normalization_and_cost(self):
        config = generic_agent._normalize_llm_price_config({
            "model": "deepseek-v4-flash",
            "price": [0.1, 0.2],
            "cache_read_price": 0.01,
        })

        self.assertEqual(config["price"], [0.1, 0.2, 0.01])
        self.assertNotIn("cache_read_price", config)

        response = SimpleNamespace(
            usage=SimpleNamespace(
                prompt_tokens=1000,
                completion_tokens=100,
                prompt_tokens_details=SimpleNamespace(cached_tokens=800),
            )
        )
        prompt_tokens = generic_agent._usage_token_count(response, "prompt_tokens")
        completion_tokens = generic_agent._usage_token_count(response, "completion_tokens")
        cached_tokens = generic_agent._cached_prompt_tokens(response)
        cost = (
            (prompt_tokens - cached_tokens) * config["price"][0]
            + completion_tokens * config["price"][1]
            + cached_tokens * config["price"][2]
        ) / 1000

        self.assertAlmostEqual(cost, 0.048)

    def test_regression_inputs_require_explicit_profile_entries(self):
        self.assertEqual(
            verification._discover_regression_inputs({"src": "/tmp", "args": ["/tmp/poc"]}),
            [],
        )
        self.assertEqual(
            verification._discover_regression_inputs({"regression_inputs": ["/tmp/a", "/tmp/a", "/tmp/b"]}),
            ["/tmp/a", "/tmp/b"],
        )

    def test_step_clears_stale_error_after_successful_chat(self):
        class FakeProxy:
            def initiate_chat(self, *args, **kwargs):
                return SimpleNamespace(
                    chat_history=[{"name": "FuzzPlanner", "content": "DONE SUBMIT"}],
                    cost=0.0,
                )

        agent = generic_agent.GenericAgent.__new__(generic_agent.GenericAgent)
        agent._user_proxy = FakeProxy()
        agent._assistant = object()
        previous = {
            "history": [],
            "cost": "N/A",
            "error": "Connection error.",
        }

        updated = agent.step(previous, "retry", logger=SimpleNamespace(error=lambda *a, **k: None), max_turns=1)

        self.assertNotIn("error", updated)
        self.assertEqual(updated["history"][0]["content"], "DONE SUBMIT")

    def test_log_exception_records_full_traceback(self):
        class FakeLogger:
            def __init__(self):
                self.errors = []

            def error(self, *args, **kwargs):
                self.errors.append(args)

        fake_logger = FakeLogger()

        try:
            raise RuntimeError("transport dropped")
        except RuntimeError as exc:
            generic_agent._log_exception(fake_logger, "Step chat terminated with exception", exc)

        rendered = "\n".join(str(arg) for call in fake_logger.errors for arg in call)
        self.assertIn("RuntimeError", rendered)
        self.assertIn("Full traceback", rendered)
        self.assertIn("transport dropped", rendered)


if __name__ == "__main__":
    unittest.main()
