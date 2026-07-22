import json
import pathlib
import sys
import tempfile
import types
import unittest
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
sys.modules.setdefault("fuzzer", types.ModuleType("fuzzer"))
sys.modules.setdefault("fuzzer.mutators", types.ModuleType("fuzzer.mutators"))
base_module = types.ModuleType("fuzzer.mutators.base")
base_module.MutatorBase = object
sys.modules.setdefault("fuzzer.mutators.base", base_module)
blocks_module = sys.modules.setdefault("blocks", types.ModuleType("blocks"))
memory_module = sys.modules.setdefault("blocks.memory", types.ModuleType("blocks.memory"))
integer_module = sys.modules.setdefault("blocks.integer", types.ModuleType("blocks.integer"))
blocks_module.memory = memory_module
blocks_module.integer = integer_module

from agent import adapters  # noqa: E402
from agent.contracts import AgentMessage, ConstraintCandidate  # noqa: E402
from agent.state import BugHypothesisState  # noqa: E402
from utils.metrics import build_case_summary, write_case_summary  # noqa: E402


class CaseObservabilityTests(unittest.TestCase):
    def test_build_case_summary_aggregates_pipeline_metrics(self):
        meta = {
            "profile": {"id": "42508282", "result_dir": "/tmp/results"},
            "patch": {"patches": [{"file": "a.c"}]},
            "failure": {"stage": "orchestrator", "reason": "max_rounds_reached"},
            "constraints": [
                {
                    "constraint_status": "supported_and_executable",
                    "support_stats": {
                        "challenger_support_count": 2,
                        "challenger_counterexample_count": 0,
                        "eval_failures": 1,
                    },
                    "challenge_result": {"status": "supported"},
                },
                {
                    "constraint_status": "rejected",
                    "support_stats": {
                        "challenger_support_count": 0,
                        "challenger_counterexample_count": 1,
                        "eval_failures": 0,
                    },
                    "challenge_result": {"status": "falsified"},
                },
            ],
            "patch_candidates": [
                {"status": "validated"},
                {"status": "generated"},
            ],
            "counterfactual_contracts": {
                "hyp-1": {
                    "contract_id": "cfc-1",
                    "hypothesis_id": "hyp-1",
                    "bug_type": "out_of_bounds",
                    "boundary_kind": "strict_upper_bound",
                    "enforcement_priority": "producer",
                    "angelic_observations": [
                        {"outcome": "angelic", "target_crash_status": "disappeared"},
                        {"outcome": "inconclusive", "target_crash_status": "changed"},
                    ],
                    "demonic_observations": [
                        {"outcome": "demonic", "target_crash_status": "persisted"},
                    ],
                }
            },
            "verification_feedback": [
                {"status": "semantic_regression"},
                {"status": "pass", "layer1_verdict": "weak"},
                {"status": "pass", "layer1_verdict": "strong"},
            ],
        }
        interaction_state = {
            "max_rounds": 8,
            "next_actor": "done",
            "rounds_without_progress": 1,
            "analysis": [{"line": 10}, {"line": 11}],
            "suspects": [{"file": "a.c"}],
            "hypothesis_pool": [{"id": "hyp-1"}, {"id": "hyp-2"}],
            "fuzz_result": {
                "angelic_values": [1, 2],
                "demonic_values": [3],
                "trace_pairs": [{"kind": "angelic"}],
                "minimal_deltas": [{"kind": "assignment"}],
                "cost_stats": {
                    "budgets": {
                        "candidate_budget": 48,
                        "snapshot_expression_budget": 120,
                        "respawn_budget": 12,
                        "state_prepare_retry_budget": 4,
                        "force_respawn_every_n_candidates": 2,
                    },
                    "candidate_stats": {
                        "seen": 7,
                        "tested": 5,
                        "duplicate_skips": 1,
                        "pruned_skips": 2,
                        "budget_skips": 0,
                        "apply_failures": 1,
                    },
                    "snapshot_stats": {
                        "snapshots": 3,
                        "expression_evals": 11,
                        "budget_exhaustions": 0,
                    },
                    "debugger_stats": {
                        "prepare_calls": 4,
                        "prepare_failures": 1,
                        "respawns": 2,
                    },
                    "budget_exhausted": True,
                    "exhausted_budget": "candidate_budget",
                    "pruning_reasons": {"bug_type_target_mismatch": 2},
                    "debugger_runtime": {
                        "print_requests": 9,
                        "print_cache_hits": 3,
                        "print_cache_misses": 6,
                        "cache_invalidations": 4,
                        "state_epoch": 8,
                        "lldb": {
                            "eval_requests": 15,
                            "eval_timeouts": 2,
                            "eval_retries": 1,
                            "eval_errors": 0,
                            "assign_requests": 5,
                            "slow_evals": 1,
                            "total_eval_seconds": 2.75,
                        },
                    },
                },
            },
            "route_history": [
                {"round": 1, "actor": "debug", "hypothesis_id": "hyp-1"},
                {"round": 2, "actor": "counterfactual", "hypothesis_id": "hyp-1"},
                {"round": 3, "actor": "constraint", "hypothesis_id": "hyp-1"},
            ],
            "messages": [
                {
                    "actor": "debug",
                    "claims": ["debug claim"],
                    "recommended_next_actor": "counterfactual",
                    "artifacts": {"round_metrics": {"suspect_count": 1}},
                },
                {
                    "actor": "counterfactual",
                    "claims": ["contract claim"],
                    "recommended_next_actor": "patch",
                    "artifacts": {
                        "round_metrics": {
                            "contract_present": True,
                            "target_crash_status_counts": {"disappeared": 1},
                        }
                    },
                },
                {
                    "actor": "constraint",
                    "claims": ["constraint claim"],
                    "recommended_next_actor": "patch",
                    "artifacts": {"round_metrics": {"candidate_count": 2}},
                },
            ],
        }

        summary = build_case_summary(meta=meta, interaction_state=interaction_state)

        self.assertEqual(summary["project_id"], "42508282")
        self.assertEqual(summary["pipeline"]["round_count"], 3)
        self.assertEqual(summary["pipeline"]["actor_counts"]["debug"], 1)
        self.assertEqual(summary["pipeline"]["actor_counts"]["counterfactual"], 1)
        self.assertEqual(summary["constraints"]["status_counts"]["supported_and_executable"], 1)
        self.assertEqual(summary["constraints"]["challenge_status_counts"]["falsified"], 1)
        self.assertEqual(summary["constraints"]["challenger_supported_count"], 2)
        self.assertEqual(summary["verification"]["final_status"], "pass")
        self.assertEqual(summary["verification"]["layer1_verdict_counts"]["weak"], 1)
        self.assertEqual(summary["verification"]["layer1_verdict_counts"]["strong"], 1)
        self.assertEqual(summary["verification"]["verified_patch_count"], 1)
        self.assertEqual(summary["costs"]["fuzz"]["trace_pair_count"], 1)
        self.assertTrue(summary["costs"]["fuzz"]["budget_exhausted"])
        self.assertEqual(summary["costs"]["fuzz"]["candidate_tested"], 5)
        self.assertEqual(summary["costs"]["fuzz"]["debugger_print_cache_hits"], 3)
        self.assertEqual(summary["costs"]["fuzz"]["lldb_eval_timeouts"], 2)
        self.assertEqual(summary["counterfactual"]["contract_count"], 1)
        self.assertEqual(summary["counterfactual"]["boundary_kind_counts"]["strict_upper_bound"], 1)
        self.assertEqual(summary["counterfactual"]["target_crash_status_counts"]["disappeared"], 1)
        self.assertEqual(summary["counterfactual"]["target_crash_status_counts"]["persisted"], 1)
        self.assertEqual(summary["counterfactual"]["target_crash_status_counts"]["changed"], 1)
        self.assertEqual(summary["rounds"][1]["metrics"]["target_crash_status_counts"]["disappeared"], 1)
        self.assertEqual(summary["rounds"][2]["metrics"]["candidate_count"], 2)

    def test_fuzz_round_metrics_include_cost_stats(self):
        message = adapters.hydrate_fuzz_state(
            BugHypothesisState(profile={"id": "p"}),
            {
                "hypothesis_id": "hyp-1",
                "angelic_values": [1],
                "demonic_values": [2],
                "trace_pairs": [],
                "minimal_deltas": [],
                "cost_stats": {
                    "candidate_stats": {"tested": 3},
                    "budget_exhausted": False,
                    "debugger_runtime": {
                        "print_cache_hits": 4,
                        "lldb": {"eval_timeouts": 1},
                    },
                },
            },
        )

        metrics = message.artifacts["round_metrics"]
        self.assertEqual(metrics["costs"]["candidate_tested"], 3)
        self.assertEqual(metrics["costs"]["debugger_print_cache_hits"], 4)
        self.assertEqual(metrics["costs"]["lldb_eval_timeouts"], 1)

    def test_write_case_summary_persists_artifact(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            result_dir = pathlib.Path(tmpdir)
            chat_dir = result_dir / "chat"
            chat_dir.mkdir()
            meta_path = result_dir / "meta.json"
            interaction_path = result_dir / "interaction_state.json"
            meta_path.write_text(json.dumps({"profile": {"id": "tag-1", "result_dir": str(result_dir)}, "constraints": []}))
            interaction_path.write_text(json.dumps({"route_history": [], "messages": []}))
            (chat_dir / "debug.json").write_text(
                json.dumps(
                    {
                        "cost": {
                            "usage_including_cached_inference": {
                                "total_cost": 0.03,
                                "deepseek-chat": {
                                    "cost": 0.03,
                                    "prompt_tokens": 100,
                                    "completion_tokens": 20,
                                    "total_tokens": 120,
                                },
                            },
                            "usage_excluding_cached_inference": {
                                "total_cost": 0.02,
                                "deepseek-chat": {
                                    "cost": 0.02,
                                    "prompt_tokens": 80,
                                    "completion_tokens": 20,
                                    "total_tokens": 100,
                                },
                            },
                        }
                    }
                )
            )
            (chat_dir / "patch.json").write_text(
                json.dumps(
                    {
                        "cost": {
                            "usage_including_cached_inference": {
                                "total_cost": 0.04,
                                "deepseek-chat": {
                                    "cost": 0.04,
                                    "prompt_tokens": 200,
                                    "completion_tokens": 30,
                                    "total_tokens": 230,
                                    "cached_tokens": 10,
                                },
                            },
                            "usage_excluding_cached_inference": {
                                "total_cost": 0.03,
                                "deepseek-chat": {
                                    "cost": 0.03,
                                    "prompt_tokens": 160,
                                    "completion_tokens": 30,
                                    "total_tokens": 190,
                                },
                            },
                        }
                    }
                )
            )
            (chat_dir / "unpriced.json").write_text(json.dumps({"cost": "N/A"}))

            summary = write_case_summary(
                {
                    "id": "tag-1",
                    "result_dir": str(result_dir),
                    "meta_output": str(meta_path),
                }
            )

            self.assertIsNotNone(summary)
            persisted = json.loads((result_dir / "case_summary.json").read_text())
            self.assertEqual(persisted["project_id"], "tag-1")
            self.assertEqual(persisted["artifact_version"], "case_observability.v1")
            self.assertEqual(persisted["costs"]["llm"]["chat_file_count"], 3)
            self.assertEqual(persisted["costs"]["llm"]["available_cost_count"], 2)
            self.assertEqual(persisted["costs"]["llm"]["unavailable_cost_count"], 1)
            including = persisted["costs"]["llm"]["usage_including_cached_inference"]
            excluding = persisted["costs"]["llm"]["usage_excluding_cached_inference"]
            self.assertAlmostEqual(including["total_cost"], 0.07)
            self.assertEqual(including["prompt_tokens"], 300)
            self.assertEqual(including["completion_tokens"], 50)
            self.assertEqual(including["total_tokens"], 350)
            self.assertEqual(including["cached_tokens"], 10)
            self.assertAlmostEqual(including["model_costs"]["deepseek-chat"]["cost"], 0.07)
            self.assertAlmostEqual(excluding["total_cost"], 0.05)
            self.assertEqual(excluding["prompt_tokens"], 240)
            self.assertEqual(excluding["completion_tokens"], 50)
            self.assertEqual(excluding["total_tokens"], 290)

    def test_constraint_round_metrics_are_attached_without_changing_logic(self):
        candidate = ConstraintCandidate(
            constraint="x < len",
            constraint_status="supported_and_executable",
            support_stats={
                "challenger_support_count": 1,
                "challenger_counterexample_count": 0,
                "eval_failures": 2,
                "positive_examples_seen": 3,
                "negative_examples_seen": 1,
            },
            challenge_result={"status": "supported"},
        )
        message = AgentMessage(
            actor="constraint",
            claims=["constraint ok"],
            recommended_next_actor="patch",
            artifacts={"constraint_candidates": [candidate.__dict__]},
        )
        state = BugHypothesisState(profile={"id": "p"})

        with patch.object(adapters, "run_constraint_round", return_value=([candidate], message)):
            out = adapters.run_constraint_round_adapter(state, llm_agent=None)

        metrics = out.artifacts["round_metrics"]
        self.assertEqual(metrics["candidate_count"], 1)
        self.assertEqual(metrics["constraint_status_counts"]["supported_and_executable"], 1)
        self.assertEqual(metrics["challenge_status_counts"]["supported"], 1)
        self.assertEqual(metrics["eval_failure_count"], 2)
        self.assertEqual(state.constraint_candidates[0].constraint, "x < len")


if __name__ == "__main__":
    unittest.main()
