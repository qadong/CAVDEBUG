import pathlib
import inspect
import sys
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
from agent.contracts import ConstraintCandidate, PatchCandidate, RootCauseReport  # noqa: E402
from agent.layer2 import Layer2Orchestrator, decide_layer2_entry  # noqa: E402
from agent.layer_patch import plan_patch_round  # noqa: E402
from agent.layer_verify import classify_verification_outcome  # noqa: E402
from agent.state import BugHypothesisState  # noqa: E402
from agent.stalk_agent import _actor_consumes_round, _interaction_max_rounds, _route_legacy_layer2_actor  # noqa: E402
from utils.verification import _classify_direct_patch_assessment, verify_patch_feedback  # noqa: E402
from utils.seed_records import angelic_assignment_sets, angelic_seed_records, demonic_value_map  # noqa: E402


def _analysis_result(**overrides):
    result = {
        "file": "/tmp/a.c",
        "line": 42,
        "function_name": "parse_header",
        "variable_names": ["offset"],
        "debug_summary": "Offset must be normalized before the access.",
        "bug_type_profile": {"bug_type": "out_of_bounds"},
        "surface_bug_type_profile": {"bug_type": "out_of_bounds"},
        "preferred_repair_stage": "input_validation",
        "repair_topology": "single_site",
        "preferred_edit_location": {
            "file": "/tmp/a.c",
            "line": 40,
            "role": "root_cause_site",
            "patchability_score": 0.95,
        },
        "candidate_edit_locations": [
            {
                "file": "/tmp/a.c",
                "line": 40,
                "role": "root_cause_site",
                "patchability_score": 0.95,
            }
        ],
    }
    result.update(overrides)
    return result


class TwoLayerRoutingTests(unittest.TestCase):
    def _logger(self):
        return type(
            "L",
            (),
            {
                "error": lambda *a, **k: None,
                "debug": lambda *a, **k: None,
                "info": lambda *a, **k: None,
                "warning": lambda *a, **k: None,
            },
        )()

    def _build_counterfactual_contract(self, state, *, run_probes=False):
        return adapters.counterfactual_agent.build_counterfactual_contract(
            suspect=state.current_suspect(),
            root_cause_report=state.current_root_cause_report(),
            hypothesis_id=state.active_hypothesis_id,
            reproduce_result=state.reproduce_result,
            run_probes=run_probes,
            probe_budget=int(state.profile.get("counterfactual_probe_budget", 3)),
            logger=self._logger(),
        )

    def _run_counterfactual_round_with_submitted_contract(self, state):
        contract = self._build_counterfactual_contract(state)
        trace = {
            "system": "counterfactual system prompt",
            "history": [{"role": "assistant", "tool_calls": [{"function": {"name": "submit_counterfactual_contract"}}]}],
            "cost": 0,
        }
        with patch.object(
            adapters.counterfactual_agent,
            "run_counterfactual_agent",
            return_value=(contract, trace),
        ) as run_agent:
            message = adapters.run_counterfactual_round(state, logger=self._logger())
        return message, contract, trace, run_agent

    def test_debug_round_routes_to_counterfactual_contract_when_root_cause_is_local(self):
        state = BugHypothesisState(profile={"id": "p"})

        message = adapters.hydrate_debug_state(state, [_analysis_result()])

        self.assertEqual(message.recommended_next_actor, "counterfactual")
        self.assertIsNotNone(state.root_cause_report)
        self.assertTrue(state.root_cause_report.direct_patch_allowed)
        self.assertIn(state.active_hypothesis_id, state.root_cause_reports)
        self.assertIn("direct_patch_contract", message.artifacts["root_cause_report"])

    def test_no_cfc_debug_round_routes_directly_to_patch_without_disabling_angelic(self):
        state = BugHypothesisState(profile={"id": "p", "ablation_mode": "no_cfc"})

        message = adapters.hydrate_debug_state(state, [_analysis_result()])

        self.assertEqual(message.recommended_next_actor, "patch")
        self.assertTrue(state.root_cause_report.direct_patch_allowed)
        self.assertNotIn("observation-only", state.root_cause_report.direct_patch_reason)
        self.assertIn("angelic intervention evidence", message.questions_for_others[0].question)

    def test_debug_submit_records_angelic_and_demonic_seed_sites_per_variable(self):
        class FakeSession:
            _input = types.SimpleNamespace(profile={})

            def llm_print_value(self, variable):
                return {"offset": "64", "len": "64"}.get(variable, "0")

        adapters.debug_agent.reset_global_state()
        adapters.debug_agent.GLOBAL_STATE["session"] = FakeSession()
        adapters.debug_agent.GLOBAL_STATE["file"] = "/tmp/a.c"
        angelic_input = [
            {
                "site": {"file": "/tmp/producer.c", "line": 17},
                "variable": "offset",
                "value": "63",
            },
            {
                "site": {"file": "/tmp/a.c", "line": 42},
                "variable": "len",
                "value": "65",
            },
        ]

        with patch.object(adapters.debug_agent, "debugger_get_type", return_value="size_t"):
            adapters.debug_agent.submit(
                suspect_variable_names=["offset", "len"],
                context_variable_names=[],
                debug_summary="offset must remain below len",
                known_angelic_values=angelic_input,
                analysis_line=42,
            )

        suspect = adapters.debug_agent.GLOBAL_STATE["suspect_object"]
        self.assertEqual(suspect["angelic_seed_records"], [
            {
                "site": {"file": "/tmp/producer.c", "line": 17, "role": "counterfactual_probe_site"},
                "variable": "offset",
                "value": "63",
            },
            {
                "site": {"file": "/tmp/a.c", "line": 42, "role": "counterfactual_probe_site"},
                "variable": "len",
                "value": "65",
            },
        ])
        self.assertEqual(suspect["demonic_seed_records"][0], {
            "site": {"file": "/tmp/a.c", "line": 42, "role": "counterfactual_probe_site"},
            "variable": "offset",
            "value": "64",
        })

    def test_debug_legacy_angelic_seed_inherits_analysis_site(self):
        records, assignments, legacy = adapters.debug_agent._normalize_angelic_seed_records(
            ["7"],
            ["offset"],
            {"file": "/tmp/a.c", "line": 42, "role": "counterfactual_probe_site"},
        )

        self.assertEqual(records[0]["site"]["line"], 42)
        self.assertEqual(records[0]["variable"], "offset")
        self.assertEqual(records[0]["value"], "7")
        self.assertEqual(assignments, [{"offset": "7"}])
        self.assertEqual(legacy, ["7"])

    def test_seed_consumers_prefer_site_records_over_legacy_aliases(self):
        suspect = {
            "file": "/tmp/legacy.c",
            "line": 99,
            "variable_names": ["offset"],
            "angelic_seed_records": [
                {
                    "site": {"file": "/tmp/producer.c", "line": 17, "role": "counterfactual_probe_site"},
                    "variable": "offset",
                    "value": "63",
                }
            ],
            "demonic_seed_records": [
                {
                    "site": {"file": "/tmp/producer.c", "line": 17, "role": "counterfactual_probe_site"},
                    "variable": "offset",
                    "value": "64",
                }
            ],
            "known_angelic_assignments": [{"offset": "1"}],
            "demonic_seed_values": {"offset": "2"},
        }

        self.assertEqual(angelic_seed_records(suspect)[0]["site"]["line"], 17)
        self.assertEqual(angelic_assignment_sets(suspect), [{"offset": "63"}])
        self.assertEqual(demonic_value_map(suspect), {"offset": "64"})

    def test_pending_verify_is_not_blocked_by_max_rounds(self):
        state = BugHypothesisState(profile={"id": "p"}, max_rounds=8)
        state.round_index = 8
        state.next_actor = "verify"
        state.add_patch_candidates([PatchCandidate(patches=[{"file": "/tmp/a.c", "patch": "x"}])])

        self.assertFalse(state.should_stop())

        state.patch_candidates[0].status = "failed"
        self.assertTrue(state.should_stop())

    def test_patch_round_generates_layer1_direct_patch_candidate(self):
        state = BugHypothesisState(profile={"id": "p"})
        adapters.hydrate_debug_state(state, [_analysis_result()])

        with patch.object(
            adapters.patch_agent,
            "patch",
            return_value={
                "patches": [{"file": "/tmp/a.c", "start_line": 40, "end_line": 40, "patch": "return -1;"}],
                "strategy": "reject_invalid_input",
                "location_type": "upstream",
                "semantic_risk": "low",
                "requires_regression_check": False,
            },
        ):
            message = adapters.run_patch_round(state, llm_agent=None)

        self.assertEqual(message.recommended_next_actor, "verify")
        self.assertIn("direct patch", message.claims[0])
        self.assertEqual(state.patch_candidates[0].metadata["repair_layer"], "layer1")
        self.assertIn("direct_patch_contract", state.patch_candidates[0].metadata["root_cause_report"])

    def test_verify_round_escalates_weak_direct_patch_into_counterfactual(self):
        state = BugHypothesisState(profile={"id": "p"}, active_hypothesis_id="hyp-1")
        state.patch_candidates = [
            PatchCandidate(
                constraint="Reject malformed offset before use.",
                patches=[{"file": "/tmp/a.c", "start_line": 40, "end_line": 40, "patch": "return -1;"}],
                metadata={
                    "repair_layer": "layer1",
                    "hypothesis_id": "hyp-1",
                    "root_cause_report": {"bug_type": "out_of_bounds"},
                },
                strategy="reject_invalid_input",
                location_type="upstream",
                semantic_risk="low",
            )
        ]

        with patch.object(
            adapters,
            "verify_patch_feedback",
            return_value={
                "status": "pass",
                "message": "Direct patch passed replay but still needs angelic validation.",
                "error_signature": "",
                "old_site_vs_new_site": "fixed",
                "blame_hint": "Needs Layer 2 validation.",
                "recommended_next_actor": "counterfactual",
                "layer1_verdict": "weak",
                "direct_patch_assessment": {"verdict": "weak", "repair_layer": "layer1", "recommended_next_actor": "counterfactual"},
                "details": {"layer_verdict": "weak", "repair_layer": "layer1"},
            },
        ):
            message = adapters.run_verify_round(state)

        self.assertEqual(message.recommended_next_actor, "counterfactual")
        self.assertIsNone(state.champion_patch)
        self.assertEqual(state.verification_feedback[-1].status, "pass")
        self.assertEqual(state.verification_feedback[-1].layer1_verdict, "weak")
        self.assertEqual(state.patch_candidates[0].status, "weak_pass")

    def test_lldb_only_accepts_replay_passing_weak_direct_patch(self):
        state = BugHypothesisState(
            profile={"id": "p", "ablation_mode": "lldb_only"},
            active_hypothesis_id="hyp-1",
        )
        state.patch_candidates = [
            PatchCandidate(
                constraint="Repair stale stack pointer before reuse.",
                patches=[{"file": "/tmp/a.c", "start_line": 40, "end_line": 40, "patch": "ptr = base + off;"}],
                metadata={
                    "repair_layer": "layer1",
                    "hypothesis_id": "hyp-1",
                    "root_cause_report": {"bug_type": "use_after_free"},
                },
                strategy="null_or_lifetime_guard",
                location_type="same_site",
                semantic_risk="low",
            )
        ]

        with patch.object(
            adapters,
            "verify_patch_feedback",
            return_value={
                "status": "pass",
                "message": "Direct patch passed replay but requires Layer 2 validation.",
                "error_signature": "",
                "old_site_vs_new_site": "fixed",
                "blame_hint": "Needs Layer 2 validation.",
                "recommended_next_actor": "counterfactual",
                "layer1_verdict": "weak",
                "direct_patch_assessment": {"verdict": "weak", "repair_layer": "layer1", "recommended_next_actor": "counterfactual"},
                "details": {"layer_verdict": "weak", "repair_layer": "layer1", "verification_confidence": 0.6},
            },
        ):
            message = adapters.run_verify_round(state)

        self.assertEqual(message.recommended_next_actor, "done")
        self.assertEqual(state.patch_candidates[0].status, "validated")
        self.assertIn("LLDB-only", message.claims[0])
        self.assertEqual(message.artifacts["validated_patch_candidate"]["verification_feedback"]["layer1_verdict"], "weak")

    def test_verify_round_preserves_extra_runtime_feedback_without_crashing(self):
        state = BugHypothesisState(profile={"id": "p"}, active_hypothesis_id="hyp-1")
        state.patch_candidates = [
            PatchCandidate(
                constraint="Repair extent before use.",
                patches=[{"file": "/tmp/a.c", "start_line": 40, "end_line": 40, "patch": "return -1;"}],
                metadata={"hypothesis_id": "hyp-1"},
                strategy="reject_invalid_input",
                location_type="upstream",
                semantic_risk="low",
            )
        ]

        with patch.object(
            adapters,
            "verify_patch_feedback",
            return_value={
                "status": "runtime_failure",
                "message": "Runtime failed.",
                "error_signature": "nonzero",
                "old_site_vs_new_site": "unknown",
                "blame_hint": "Inspect runtime output.",
                "recommended_next_actor": "patch",
                "runtime_output": "stderr excerpt",
                "crash_site": {"file": "x.c", "line": 1},
                "frames": ["#0 f x.c:1"],
            },
        ):
            message = adapters.run_verify_round(state)

        feedback = state.verification_feedback[-1]
        self.assertEqual(message.recommended_next_actor, "patch")
        self.assertEqual(feedback.status, "runtime_failure")
        self.assertEqual(feedback.details["runtime_output"], "stderr excerpt")
        self.assertEqual(feedback.details["extra_feedback"]["crash_site"]["file"], "x.c")

    def test_verify_feedback_marks_same_site_direct_patch_as_suspicious(self):
        with patch("utils.verification.file_apply_patches", return_value=True), \
             patch("utils.verification.file_undo_patches", return_value=True), \
             patch("utils.verification.run_compile", return_value=(0, "", "")), \
             patch("utils.verification._run_primary_replay", return_value={"return_code": 0, "error": "", "command": "poc"}), \
             patch("utils.verification._run_variant_replay", return_value={"status": "pass", "input_count": 2, "items": []}), \
             patch("utils.verification._run_regression_replay", return_value={"status": "pass", "input_count": 2, "items": []}):
            feedback = verify_patch_feedback(
                {
                    "patches": [{"file": "/src/project/src/core.c", "line": 32, "patch": "guard"}],
                    "repair_layer": "layer1",
                    "strategy": "bounds_check_before_access",
                    "location_type": "same_site",
                    "semantic_risk": "medium",
                    "root_cause_report": {"direct_patch_risk": "medium", "preferred_repair_stage": "state_update"},
                    "typed_angelic_evidence": {"validation_obligations": ["ASan clean"]},
                },
                logger=self._logger(),
            )

        self.assertEqual(feedback["status"], "pass")
        self.assertEqual(feedback["layer1_verdict"], "suspicious")
        self.assertEqual(feedback["recommended_next_actor"], "layer2")

    def test_verify_feedback_accepts_strong_direct_patch(self):
        with patch("utils.verification.file_apply_patches", return_value=True), \
             patch("utils.verification.file_undo_patches", return_value=True), \
             patch("utils.verification.run_compile", return_value=(0, "", "")), \
             patch("utils.verification._run_primary_replay", return_value={"return_code": 0, "error": "", "command": "poc"}), \
             patch("utils.verification._run_variant_replay", return_value={"status": "pass", "input_count": 2, "items": []}), \
             patch("utils.verification._run_regression_replay", return_value={"status": "pass", "input_count": 2, "items": []}), \
             patch("utils.verification._judge_direct_patch_with_llm", return_value={
                 "verdict": "strong",
                 "recommended_next_actor": "done",
                 "rationale": "LLM accepted semantic error-path patch.",
                 "verification_confidence": 0.9,
                 "residual_risk": "",
                 "root_cause_alignment": "aligned",
                 "source_status": "pass",
                 "layer2_validation_required": False,
                 "direct_patch_risk": "low",
                 "decision_source": "llm",
             }):
            feedback = verify_patch_feedback(
                {
                    "patches": [{"file": "/src/project/src/core.c", "line": 12, "patch": "guard"}],
                    "repair_layer": "layer1",
                    "strategy": "reject_invalid_input",
                    "location_type": "upstream",
                    "semantic_risk": "low",
                    "root_cause_report": {"direct_patch_risk": "low", "preferred_repair_stage": "input_validation"},
                    "typed_angelic_evidence": {"validation_obligations": ["ASan clean"]},
                },
                logger=self._logger(),
            )

        self.assertEqual(feedback["status"], "pass")
        self.assertEqual(feedback["layer1_verdict"], "strong")
        self.assertEqual(feedback["recommended_next_actor"], "done")

    def test_direct_patch_classifier_marks_replay_only_success_as_weak(self):
        with patch("utils.verification._judge_direct_patch_with_llm", return_value={
            "verdict": "weak",
            "recommended_next_actor": "layer2",
            "rationale": "LLM requested Layer 2 because regression evidence is unavailable.",
            "verification_confidence": 0.82,
            "residual_risk": "regression_unavailable",
            "root_cause_alignment": "aligned",
            "source_status": "pass",
            "layer2_validation_required": True,
            "direct_patch_risk": "low",
            "decision_source": "llm",
        }):
            assessment = _classify_direct_patch_assessment(
                patch={
                    "strategy": "reject_invalid_input",
                    "location_type": "upstream",
                    "semantic_risk": "low",
                    "root_cause_report": {"direct_patch_risk": "low", "preferred_repair_stage": "input_validation"},
                },
                status="pass",
                tier_report={
                    "tier2_variants": {"status": "pass"},
                    "tier3_regression": {"status": "regression_unavailable"},
                },
                obligation_summary={"unmet": [], "warnings": []},
                confidence=0.82,
                residual_risk="regression_unavailable",
                default_next_actor="done",
                default_blame_hint="No further iteration required.",
            )

        self.assertEqual(assessment["verdict"], "weak")
        self.assertEqual(assessment["recommended_next_actor"], "layer2")
        self.assertIn("Layer 2", assessment["rationale"])

    def test_layer2_entry_routes_to_fuzz_without_evidence(self):
        state = BugHypothesisState(profile={"id": "p"}, active_hypothesis_id="hyp-1")

        message = adapters.run_layer2_entry_round(state)

        self.assertEqual(message.recommended_next_actor, "fuzz")
        self.assertIn("evidence gathering", message.claims[0])
        self.assertEqual(message.artifacts["layer2_entry"]["next_actor"], "fuzz")

    def test_layer2_entry_routes_to_constraint_with_existing_angelic_evidence(self):
        state = BugHypothesisState(
            profile={"id": "p"},
            active_hypothesis_id="hyp-1",
            fuzz_result={"hypothesis_id": "hyp-1", "angelic_values": [1], "demonic_values": [2]},
        )

        message = adapters.run_layer2_entry_round(state)

        self.assertEqual(message.recommended_next_actor, "constraint")
        self.assertIn("reusing existing angelic evidence", message.claims[0])

    def test_layer2_entry_routes_operational_evidence_directly_to_patch(self):
        state = BugHypothesisState(
            profile={"id": "p"},
            active_hypothesis_id="hyp-1",
            fuzz_result={
                "hypothesis_id": "hyp-1",
                "angelic_values": [{"len": "8"}],
                "typed_angelic_evidence": {
                    "evidence_family": "operational",
                    "evidence_kind": "operational_allocation_size",
                    "generalization_target": "repair_intent",
                    "constraint_required": False,
                    "reason": "Allocation-size evidence should repair sizeof usage directly.",
                },
            },
        )
        state.request_layer2_fuzz_refresh("verify:weak", hypothesis_id="hyp-1")

        message = adapters.run_layer2_entry_round(state)

        self.assertEqual(message.recommended_next_actor, "patch")
        self.assertIn("skip predicate constraint", message.claims[0])
        self.assertTrue(message.artifacts["layer2_entry"]["forced_fuzz_refresh"])
        self.assertEqual(message.artifacts["layer2_entry"]["evidence_family"], "operational")
        self.assertEqual(message.artifacts["layer2_entry"]["next_actor"], "patch")

    def test_layer2_entry_routes_to_patch_with_supported_constraints(self):
        state = BugHypothesisState(
            profile={"id": "p"},
            active_hypothesis_id="hyp-1",
            constraint_candidates=[
                ConstraintCandidate(
                    constraint="offset < len",
                    constraint_status="supported_and_executable",
                    challenge_status="supported",
                    overall_score=0.8,
                )
            ],
        )

        message = adapters.run_layer2_entry_round(state)

        self.assertEqual(message.recommended_next_actor, "patch")
        self.assertIn("supported constraints", message.claims[0])

    def test_layer2_policy_returns_named_decision(self):
        state = BugHypothesisState(
            profile={"id": "p"},
            active_hypothesis_id="hyp-1",
            fuzz_result={"hypothesis_id": "hyp-1", "angelic_values": [1]},
        )
        state.set_fuzz_result(state.fuzz_result, hypothesis_id="hyp-1")

        decision = decide_layer2_entry(state)

        self.assertEqual(decision.next_actor, "constraint")
        self.assertTrue(decision.has_angelic_values)
        self.assertFalse(decision.has_supported_constraints)

    def test_layer2_orchestrator_reuses_supported_constraints(self):
        state = BugHypothesisState(
            profile={"id": "p"},
            active_hypothesis_id="hyp-1",
            constraint_candidates=[
                ConstraintCandidate(
                    constraint="offset < len",
                    constraint_status="supported_and_executable",
                    challenge_status="supported",
                    overall_score=0.9,
                )
            ],
        )

        decision = Layer2Orchestrator().decide_entry(state)

        self.assertEqual(decision.next_actor, "patch")
        self.assertTrue(decision.has_supported_constraints)

    def test_patch_planner_builds_layer1_direct_patch_plan(self):
        state = BugHypothesisState(profile={"id": "p"})
        adapters.hydrate_debug_state(state, [_analysis_result()])

        plan = plan_patch_round(
            state=state,
            suspect=state.current_suspect(),
            pending_constraints=[],
            patch_agent_module=adapters.patch_agent,
        )

        self.assertEqual(plan.layer, "layer1")
        self.assertTrue(plan.direct_patch_mode)
        self.assertEqual(plan.pending_constraints[0].constraint_status, "layer1_direct_patch")

    def test_patch_planner_builds_operational_repair_intent_plan(self):
        state = BugHypothesisState(profile={"id": "p"})
        adapters.hydrate_debug_state(
            state,
            [
                _analysis_result(
                    debug_summary="Allocation uses sizeof(pointer) and should use sizeof(*fa).",
                    preferred_repair_stage="allocation_extent",
                    bug_type_profile={
                        "bug_type": "out_of_bounds",
                        "evidence_family": "operational",
                        "evidence_kind": "operational_allocation_size",
                        "generalization_target": "repair_intent",
                    },
                    repair_topology="cross_file_invariant",
                )
            ],
        )

        plan = plan_patch_round(
            state=state,
            suspect=state.current_suspect(),
            pending_constraints=[],
            patch_agent_module=adapters.patch_agent,
        )

        self.assertEqual(plan.layer, "layer2")
        self.assertFalse(plan.direct_patch_mode)
        self.assertEqual(plan.empty_next_actor, "fuzz")
        self.assertEqual(plan.pending_constraints[0].constraint_status, "operational_repair_intent")
        self.assertEqual(plan.pending_constraints[0].typed_angelic_evidence["evidence_family"], "operational")

    def test_counterfactual_round_builds_contract_and_patch_plan(self):
        state = BugHypothesisState(profile={"id": "p", "counterfactual_probe_budget": 0})
        adapters.hydrate_debug_state(
            state,
            [
                _analysis_result(
                    variable_names=["offset", "len"],
                    known_angelic_assignments=[{"variable": "offset", "value": "len - 1"}],
                    forbidden_fix_patterns=["crash_site_guard_only"],
                )
            ],
        )

        message, submitted_contract, trace, run_agent = self._run_counterfactual_round_with_submitted_contract(state)
        plan = plan_patch_round(
            state=state,
            suspect=state.current_suspect(),
            pending_constraints=[],
            patch_agent_module=adapters.patch_agent,
        )
        contract = state.current_counterfactual_contract()

        self.assertEqual(message.recommended_next_actor, "patch")
        self.assertIsNotNone(contract)
        self.assertEqual(plan.layer, "counterfactual")
        self.assertEqual(plan.pending_constraints[0].constraint_status, "counterfactual_contract")
        self.assertEqual(contract.intervention_site["role"], "counterfactual_probe_site")
        self.assertNotEqual(contract.enforcement_site["role"], contract.intervention_site["role"])
        self.assertEqual(contract.angelic_observations[0]["target_crash_status"], "inconclusive")
        self.assertIs(contract, submitted_contract)
        self.assertEqual(message.artifacts["counterfactual_agent_trace"], trace)
        run_agent.assert_called_once()
        abstract = plan.pending_constraints[0].abstract_constraint
        self.assertEqual(abstract["type"], "counterfactual_invariant")
        self.assertIn("len - 1", abstract["forbidden_literals"])
        self.assertEqual(abstract["forbidden_patch_patterns"], contract.forbidden_patch_patterns or contract.avoid_patch_patterns)
        self.assertEqual(abstract["repair_invariant"], contract.repair_invariant)

    def test_counterfactual_agent_registers_debug_agent_tools_and_contract_submit(self):
        registered = []

        class FakeGenericAgent:
            def __init__(self, name, system_prompt, **kwargs):
                self.name = name
                self.system_prompt = system_prompt
                self.is_termination_msg = kwargs.get("is_termination_msg")
                self.default_auto_reply = kwargs.get("default_auto_reply")

            def register_hook(self, func, description, **kwargs):
                registered.append(kwargs.get("name") or func.__name__)

        with patch.object(adapters.counterfactual_agent, "GenericAgent", FakeGenericAgent):
            agent = adapters.counterfactual_agent.get_counterfactual_contract_agent()

        self.assertEqual(agent.name, "CounterfactualContractAgent")
        self.assertTrue(callable(agent.is_termination_msg))
        self.assertIn("No CounterfactualInvariant has been accepted", agent.default_auto_reply)
        adapters.counterfactual_agent.reset_agent_state()
        self.assertFalse(agent.is_termination_msg({"content": "TERMINATE"}))
        adapters.counterfactual_agent.AGENT_STATE["contract"] = object()
        self.assertTrue(agent.is_termination_msg({"content": "TERMINATE"}))
        adapters.counterfactual_agent.reset_agent_state()
        self.assertIn("## Active Debugger Session Protocol", agent.system_prompt)
        self.assertIn("Agent role: `CounterfactualContractAgent`", agent.system_prompt)
        self.assertIn("run_to_line", registered)
        self.assertIn("print_value", registered)
        self.assertIn("debugger_assign", registered)
        self.assertIn("apply_angelic_operation", registered)
        self.assertIn("debugger_continue", registered)
        self.assertIn("search_in_repo", registered)
        self.assertIn("submit_counterfactual_invariant", registered)
        self.assertIn("submit_counterfactual_contract", registered)

    def test_counterfactual_search_rejects_test_entry_scope_drift(self):
        response = adapters.counterfactual_agent.cfc_search_in_repo(
            pattern="init_unit_tests",
            path="/src/opensips",
        )

        self.assertIn("search rejected", response)
        self.assertIn("seed/probe sites", response)
        self.assertIn("run_to_line", response)
        self.assertIn("debugger_assign", response)

    def test_debug_and_patch_agents_share_debugger_session_protocol(self):
        class FakeGenericAgent:
            def __init__(self, name, system_prompt):
                self.name = name
                self.system_prompt = system_prompt

            def register_hook(self, *args, **kwargs):
                return None

        with patch.object(adapters.debug_agent, "GenericAgent", FakeGenericAgent):
            debug = adapters.debug_agent.get_generic_agent(use_constraint=False, profile={})
            state_only_debug = adapters.debug_agent.get_generic_agent(
                use_constraint=False,
                profile={"ablation_mode": "state_only_no_angelic"},
            )
            no_cfc_debug = adapters.debug_agent.get_generic_agent(
                use_constraint=False,
                profile={"ablation_mode": "no_cfc"},
            )
        with patch.object(adapters.patch_agent, "GenericAgent", FakeGenericAgent):
            patch_agent = adapters.patch_agent.get_generic_agent(profile={})

        for agent in (debug, state_only_debug, no_cfc_debug, patch_agent):
            self.assertIn("## Active Debugger Session Protocol", agent.system_prompt)
            self.assertIn("already initialized by the pipeline", agent.system_prompt)
            self.assertIn("Do not search for a test entry point", agent.system_prompt)
        self.assertIn("Agent role: `DebugAgent`", debug.system_prompt)
        self.assertIn("Agent role: `PatchAgent`", patch_agent.system_prompt)
        self.assertIn("debugger_assign", debug.system_prompt)
        self.assertNotIn("debugger_assign", state_only_debug.system_prompt)
        self.assertIn("debugger_assign", no_cfc_debug.system_prompt)

    def test_counterfactual_submit_tool_exposes_resolved_runtime_annotations(self):
        from pydantic import TypeAdapter

        signature = inspect.signature(adapters.counterfactual_agent.submit_counterfactual_contract)

        self.assertFalse(any(isinstance(parameter.annotation, str) for parameter in signature.parameters.values()))
        for parameter in signature.parameters.values():
            TypeAdapter(parameter.annotation).json_schema()

    def test_counterfactual_agent_submit_produces_contract_and_returns_real_chat_trace(self):
        state = BugHypothesisState(profile={"id": "p"}, reproduce_result={"error": "AddressSanitizer: heap-buffer-overflow"})
        adapters.hydrate_debug_state(state, [_analysis_result(variable_names=["offset", "len"])])
        trace = {
            "system": "counterfactual system prompt",
            "history": [
                {"role": "assistant", "tool_calls": [{"function": {"name": "debugger_assign"}}]},
                {"role": "assistant", "tool_calls": [{"function": {"name": "debugger_continue"}}]},
                {"role": "assistant", "tool_calls": [{"function": {"name": "search_in_repo"}}]},
                {"role": "assistant", "tool_calls": [{"function": {"name": "submit_counterfactual_contract"}}]},
            ],
            "cost": 1,
        }

        class FakeAgent:
            def initiate(self, prompt, max_turns=None):
                self.max_turns = max_turns
                self.prompt = prompt
                adapters.counterfactual_agent.AGENT_STATE["actions"] = {
                    "intervention",
                    "post_intervention_execution",
                    "source_inspection",
                }
                response = adapters.counterfactual_agent.submit_counterfactual_contract(
                    suspect_variables=["offset", "len"],
                    angelic_observations=[
                        {
                            "intervention": "offset = len - 1",
                            "outcome": "angelic",
                            "target_crash_status": "disappeared",
                        }
                    ],
                    demonic_observations=[
                        {
                            "intervention": "offset = len",
                            "outcome": "demonic",
                            "target_crash_status": "persisted",
                        }
                    ],
                    intervention_site={"file": "/tmp/a.c", "line": 42},
                    enforcement_site={"file": "/tmp/a.c", "line": 40, "role": "producer"},
                    enforcement_priority="producer",
                    boundary_kind="strict_upper_bound",
                    boundary_predicate="offset < len",
                    boundary_summary="The crash boundary is offset == len.",
                    repair_invariant="offset < len",
                    contract_scope="offset-producing transitions in parse_header",
                    affected_operations=["parse_header offset update"],
                    repair_intent="Maintain offset within the parsed extent.",
                    rationale="Angelic and demonic observations isolate a strict upper bound.",
                )
                self.response = response
                return trace

        fake_agent = FakeAgent()
        with patch.object(adapters.counterfactual_agent, "get_counterfactual_contract_agent", return_value=fake_agent):
            contract, actual_trace = adapters.counterfactual_agent.run_counterfactual_agent(
                profile=state.profile,
                suspect=state.current_suspect(),
                root_cause_report=state.current_root_cause_report(),
                hypothesis_id=state.active_hypothesis_id,
                reproduce_result=state.reproduce_result,
                logger=self._logger(),
            )

        self.assertIsNotNone(contract)
        self.assertEqual(contract.repair_invariant, "offset < len")
        self.assertEqual(contract.intervention_site["role"], "counterfactual_probe_site")
        self.assertEqual(contract.enforcement_site["role"], "producer")
        self.assertEqual(actual_trace, trace)
        self.assertEqual(fake_agent.max_turns, 300)
        self.assertIn("# Counterfactual Invariant Task", fake_agent.prompt)
        self.assertIn("## Active Debugger Session", fake_agent.prompt)
        self.assertIn("The debugger session is already initialized", fake_agent.prompt)
        self.assertIn("active_default_frame", fake_agent.prompt)
        self.assertIn("first_debugger_action", fake_agent.prompt)
        self.assertIn("## Seed Expansion Targets", fake_agent.prompt)
        self.assertIn("submit_counterfactual_invariant", fake_agent.prompt)
        self.assertNotIn('"reproduce_result"', fake_agent.prompt)
        self.assertNotIn('"root_cause_report"', fake_agent.prompt)

    def test_counterfactual_bootstrap_sets_debug_agent_default_frame(self):
        old_state = dict(adapters.debug_agent.GLOBAL_STATE)
        try:
            adapters.debug_agent.GLOBAL_STATE["session"] = object()
            adapters.debug_agent.GLOBAL_STATE["file"] = "/tmp/old.c"
            suspect = _analysis_result(
                file="/tmp/a.c",
                line=42,
                known_angelic_values=[
                    {"site": {"file": "/tmp/producer.c", "line": 17}, "variable": "offset", "value": "63"}
                ],
            )
            task = adapters.counterfactual_agent.build_counterfactual_expansion_task(
                suspect=suspect,
                root_cause_report=None,
                hypothesis_id="hyp-test",
                reproduce_result={"error": "AddressSanitizer: heap-buffer-overflow"},
            )

            adapters.counterfactual_agent._bootstrap_debugger_context(task, suspect)

            self.assertEqual(adapters.debug_agent.GLOBAL_STATE["file"], "/tmp/producer.c")
            self.assertEqual(task["debugger_session"]["bootstrap_status"], "ready")
            self.assertEqual(task["debugger_session"]["active_default_frame"]["file"], "/tmp/producer.c")
            self.assertEqual(task["debugger_session"]["first_debugger_action"]["tool"], "run_to_line")
        finally:
            adapters.debug_agent.GLOBAL_STATE.clear()
            adapters.debug_agent.GLOBAL_STATE.update(old_state)

    def test_counterfactual_expansion_task_dynamically_loads_bug_strategy(self):
        suspect = _analysis_result(
            variable_names=["offset", "len"],
            debugger_reported_type="size_t",
            bug_type_profile={
                "bug_type": "out_of_bounds",
                "angelic_shape": "bounds_value",
                "evidence_kind": "predicate_bounds",
                "validation_obligations": ["ASan clean"],
            },
            angelic_seed_records=[
                {
                    "site": {"file": "/tmp/a.c", "line": 40, "role": "counterfactual_probe_site"},
                    "variable": "offset",
                    "value": "63",
                }
            ],
            demonic_seed_records=[
                {
                    "site": {"file": "/tmp/a.c", "line": 40, "role": "counterfactual_probe_site"},
                    "variable": "offset",
                    "value": "64",
                }
            ],
        )
        report = RootCauseReport(
            hypothesis_id="hyp-1",
            bug_type="out_of_bounds",
            repair_topology="single_site",
            preferred_edit_location={"file": "/tmp/a.c", "line": 39, "role": "loop_guard"},
        )

        task = adapters.counterfactual_agent.build_counterfactual_expansion_task(
            suspect,
            report,
            "hyp-1",
            {"error": "AddressSanitizer: heap-buffer-overflow", "file": "/tmp/a.c", "line": 42},
        )

        self.assertEqual(task["loaded_strategy"]["loaded_strategy"], "boundary")
        self.assertTrue(task["debugger_session"]["initialized"])
        self.assertTrue(task["debugger_session"]["reproducer_loaded"])
        self.assertEqual(task["debugger_session"]["recommended_start_sites"][0]["file"], "/tmp/a.c")
        self.assertEqual(task["loaded_strategy"]["counterfactual_kind"], "relation")
        self.assertEqual(task["target_crash_signature"]["bug_class"], "heap-buffer-overflow")
        self.assertEqual(task["seed_expansion_targets"][0]["seed_site"]["line"], 40)
        self.assertEqual(task["seed_expansion_targets"][0]["unsafe_state"]["expression"], "offset = 64")
        self.assertEqual(task["repair_frame"]["repair_topology"], "local_invariant")
        self.assertEqual(task["repair_frame"]["candidate_enforcement_sites"][0]["role"], "loop_guard")

    def test_counterfactual_expansion_task_loads_initialization_strategy(self):
        task = adapters.counterfactual_agent.build_counterfactual_expansion_task(
            _analysis_result(
                variable_names=["ctx"],
                bug_type_profile={"bug_type": "uninitialized_use", "angelic_shape": "initialization_state"},
            ),
            RootCauseReport(hypothesis_id="hyp-init", bug_type="uninitialized_use"),
            "hyp-init",
            {"error": "MemorySanitizer: use-of-uninitialized-value"},
        )

        self.assertEqual(task["loaded_strategy"]["loaded_strategy"], "initialization")
        self.assertEqual(task["loaded_strategy"]["counterfactual_kind"], "initialization_protocol")
        self.assertIn("init_path", task["repair_frame"]["preferred_enforcement_roles"])

    def test_counterfactual_round_does_not_fallback_when_agent_does_not_submit(self):
        state = BugHypothesisState(profile={"id": "p"})
        adapters.hydrate_debug_state(state, [_analysis_result()])
        trace = {"system": "counterfactual", "history": [], "cost": "N/A", "error": "connection failed"}

        with patch.object(
            adapters.counterfactual_agent,
            "run_counterfactual_agent",
            return_value=(None, trace),
        ):
            message = adapters.run_counterfactual_round(state, logger=self._logger())

        self.assertIsNone(state.current_counterfactual_contract())
        self.assertEqual(message.recommended_next_actor, "done")
        self.assertEqual(message.artifacts["counterfactual_agent_trace"], trace)

    def test_counterfactual_round_reports_submitted_but_rejected_contract(self):
        state = BugHypothesisState(profile={"id": "p"})
        adapters.hydrate_debug_state(state, [_analysis_result()])
        trace = {
            "system": "counterfactual",
            "history": [{"role": "assistant", "tool_calls": [{"function": {"name": "submit_counterfactual_contract"}}]}],
            "contract_rejected": {
                "reason": "missing_required_agent_actions",
                "actions": ["post-intervention execution", "enforcement-site source inspection"],
            },
        }

        with patch.object(
            adapters.counterfactual_agent,
            "run_counterfactual_agent",
            return_value=(None, trace),
        ):
            message = adapters.run_counterfactual_round(state, logger=self._logger())

        self.assertIsNone(state.current_counterfactual_contract())
        self.assertEqual(message.recommended_next_actor, "done")
        self.assertIn("submitted a contract but it was rejected", message.claims[0])
        self.assertIn("post-intervention execution", message.claims[0])

    def test_counterfactual_agent_requires_experiment_and_source_tool_trajectory(self):
        incomplete_trace = {
            "history": [
                {"role": "assistant", "tool_calls": [{"function": {"name": "submit_counterfactual_contract"}}]},
            ]
        }

        missing = adapters.counterfactual_agent._missing_required_agent_actions(incomplete_trace)

        self.assertIn("counterfactual state intervention", missing)
        self.assertIn("post-intervention execution", missing)
        self.assertIn("enforcement-site source inspection", missing)
        self.assertNotIn("contract submission", missing)

    def test_counterfactual_submit_requires_intervention_before_accepting_contract(self):
        state = BugHypothesisState(profile={"id": "p"})
        adapters.hydrate_debug_state(state, [_analysis_result(variable_names=["offset", "len"])])
        adapters.counterfactual_agent.reset_agent_state()
        adapters.counterfactual_agent.AGENT_STATE["context"] = {
            "suspect": state.current_suspect(),
            "root_cause_report": state.current_root_cause_report(),
            "hypothesis_id": state.active_hypothesis_id,
            "reproduce_result": state.reproduce_result,
        }

        submission = dict(
            bug_type="heap-buffer-overflow",
            repair_class="capacity",
            unsafe_condition="offset reaches len",
            baseline_facts=["offset == len"],
            angelic_observations=[
                {"intervention": "offset = len - 1", "classification": "angelic", "target_crash_status": "disappeared"}
            ],
            demonic_observations=[
                {"intervention": "offset = len", "classification": "demonic", "target_crash_status": "persisted"}
            ],
            boundary_summary="offset must stay below len",
            boundary_audit={
                "derived_from": "producer_side_state_transition",
                "only_sufficient_to_avoid_current_crash": False,
                "explains_invalid_state_producer": True,
                "stricter_semantic_contract": "no",
                "semantic_repair_status": "semantic_repair_candidate",
            },
            repair_invariant="offset < len",
            invariant_scope="offset-producing transitions",
            enforcement_role_preference=["producer"],
            forbidden_patch_patterns=[],
            forbidden_literals=[],
            validation_obligations=[],
            rationale="boundary isolated",
        )
        response = adapters.counterfactual_agent.submit_counterfactual_invariant(**submission)

        self.assertIn("SUBMIT_STATUS=NEEDS_MORE_EVIDENCE", response)
        self.assertIn("make 2 concrete intervention attempt", response)
        self.assertIsNone(adapters.counterfactual_agent.AGENT_STATE.get("contract"))

        adapters.counterfactual_agent.AGENT_STATE["actions"] = {
            "intervention",
            "post_intervention_execution",
            "source_inspection",
        }
        adapters.counterfactual_agent.AGENT_STATE["submit_block"] = None
        submission["angelic_observations"][0]["intervention"] = "hypothetical assignment, not applied"
        fabricated_response = adapters.counterfactual_agent.submit_counterfactual_invariant(**submission)

        self.assertIn("conceptual/hypothetical intervention", fabricated_response)
        self.assertIsNone(adapters.counterfactual_agent.AGENT_STATE.get("contract"))

    def test_counterfactual_insufficient_expansion_continues_same_report_for_intervention(self):
        state = BugHypothesisState(profile={"id": "p"})
        adapters.hydrate_debug_state(state, [_analysis_result(variable_names=["offset"])])
        adapters.counterfactual_agent.reset_agent_state()
        adapters.counterfactual_agent.AGENT_STATE["context"] = {
            "suspect": state.current_suspect(),
            "root_cause_report": state.current_root_cause_report(),
            "hypothesis_id": state.active_hypothesis_id,
            "reproduce_result": state.reproduce_result,
        }

        submission = dict(
            bug_type="assertion_failure",
            repair_class="state_machine",
            unsafe_condition="array state is invalid",
            baseline_facts=["array->start is invalid"],
            angelic_observations=[],
            demonic_observations=[],
            boundary_summary="insufficient counterfactual expansion",
            boundary_audit={
                "derived_from": "producer_side_state_transition",
                "only_sufficient_to_avoid_current_crash": False,
                "explains_invalid_state_producer": True,
                "stricter_semantic_contract": "unknown",
                "semantic_repair_status": "unknown",
            },
            repair_invariant="array state must be initialized before use",
            invariant_scope="array producer transitions",
            enforcement_role_preference=["producer_side_state_transition"],
            forbidden_patch_patterns=[],
            forbidden_literals=[],
            validation_obligations=[],
            rationale="debugger expansion was unavailable",
        )
        context = adapters.counterfactual_agent.AGENT_STATE["context"]
        response = adapters.counterfactual_agent.submit_counterfactual_invariant(**submission)

        self.assertIn("SUBMIT_STATUS=NEEDS_MORE_EVIDENCE", response)
        self.assertIn("same CounterfactualContractAgent session", response)
        self.assertNotIn("Counterfactual invariant submitted", response)
        self.assertIsNone(adapters.counterfactual_agent.AGENT_STATE.get("contract"))

        repeated_response = adapters.counterfactual_agent.submit_counterfactual_invariant(**submission)
        self.assertIn("SUBMIT_STATUS=REPEATED_SUBMIT_REJECTED", repeated_response)

        with patch.object(adapters.counterfactual_agent, "debugger_assign", return_value=(False, "not stopped")):
            adapters.counterfactual_agent.cfc_debugger_assign("offset", "offset - 1")
            adapters.counterfactual_agent.cfc_debugger_assign("offset", "offset - 1")

        duplicate_attempt_response = adapters.counterfactual_agent.submit_counterfactual_invariant(**submission)
        self.assertIn("make 1 concrete intervention attempt", duplicate_attempt_response)

        with patch.object(adapters.counterfactual_agent, "debugger_assign", return_value=(False, "not stopped")):
            adapters.counterfactual_agent.cfc_debugger_assign("offset", "offset + 1")
        with patch.object(adapters.counterfactual_agent.debug_agent, "file_content", return_value="producer source"):
            adapters.counterfactual_agent.cfc_file_content(1, 20, "/tmp/a.c")

        optimized_response = adapters.counterfactual_agent.submit_counterfactual_invariant(**submission)

        self.assertIs(adapters.counterfactual_agent.AGENT_STATE["context"], context)
        self.assertIn("Counterfactual invariant submitted", optimized_response)
        contract = adapters.counterfactual_agent.AGENT_STATE.get("contract")
        self.assertIsNotNone(contract)
        self.assertEqual(contract.semantic_repair_status, "unknown")
        self.assertEqual(len(contract.angelic_observations), 2)
        self.assertTrue(all(item["target_crash_status"] == "inconclusive" for item in contract.angelic_observations))

    def test_counterfactual_failed_intervention_is_not_recorded_as_success(self):
        adapters.counterfactual_agent.reset_agent_state()
        with patch.object(
            adapters.counterfactual_agent,
            "debugger_assign",
            return_value=(False, "assignment rejected"),
        ):
            response = adapters.counterfactual_agent.cfc_debugger_assign("offset", "len - 1")

        self.assertIn("failed", response)
        self.assertIn("intervention_attempt", adapters.counterfactual_agent.AGENT_STATE["actions"])
        self.assertNotIn("intervention", adapters.counterfactual_agent.AGENT_STATE["actions"])

    def test_counterfactual_submit_returns_actionable_error_for_string_boundary_audit(self):
        state = BugHypothesisState(profile={"id": "p"})
        adapters.hydrate_debug_state(state, [_analysis_result(variable_names=["offset", "len"])])
        adapters.counterfactual_agent.reset_agent_state()
        adapters.counterfactual_agent.AGENT_STATE["context"] = {
            "suspect": state.current_suspect(),
            "root_cause_report": state.current_root_cause_report(),
            "hypothesis_id": state.active_hypothesis_id,
            "reproduce_result": state.reproduce_result,
        }

        response = adapters.counterfactual_agent.submit_counterfactual_invariant(
            bug_type="heap-buffer-overflow",
            repair_class="capacity",
            unsafe_condition="offset reaches len",
            baseline_facts=["offset == len"],
            angelic_observations=[
                {"intervention": "offset = len - 1", "classification": "angelic", "target_crash_status": "disappeared"}
            ],
            demonic_observations=[
                {"intervention": "offset = len", "classification": "demonic", "target_crash_status": "persisted"}
            ],
            boundary_summary="offset must stay below len",
            boundary_audit="",
            repair_invariant="offset < len",
            invariant_scope="offset-producing transitions",
            enforcement_role_preference=["producer"],
            forbidden_patch_patterns=[],
            forbidden_literals=[],
            validation_obligations=[],
            rationale="boundary isolated",
        )

        self.assertIn("must be a non-empty JSON object", response)
        self.assertIn('"derived_from":"unknown"', response)
        self.assertIsNone(adapters.counterfactual_agent.AGENT_STATE.get("contract"))

    def test_counterfactual_task_demotes_estimated_safe_range_to_crash_avoidance_boundary(self):
        suspect = _analysis_result(
            variable_names=["rank"],
            estimated_safe_range="rank <= 14",
            known_angelic_values=[],
            bug_type_profile={"bug_type": "assertion_failure", "evidence_family": "state_machine"},
        )

        task = adapters.counterfactual_agent.build_counterfactual_expansion_task(
            suspect=suspect,
            root_cause_report=RootCauseReport(bug_type="assertion_failure", evidence_family="state_machine"),
            hypothesis_id="hyp-test",
            reproduce_result={"error": "AddressSanitizer: stack-buffer-overflow"},
        )

        self.assertEqual(task["loaded_strategy"]["bug_type"], "out_of_bounds")
        self.assertEqual(task["loaded_strategy"]["loaded_strategy"], "boundary")
        relation = task["suspect_runtime_scope"]["relations"][0]
        self.assertEqual(relation["role"], "crash_avoidance_boundary")
        self.assertEqual(relation["status"], "unverified_for_semantic_repair")
        seed_relation = task["seed_expansion_targets"][0]["seed_relation"]
        self.assertEqual(seed_relation["role"], "crash_avoidance_boundary")
        self.assertEqual(seed_relation["status"], "unverified_for_semantic_repair")

    def test_counterfactual_submit_marks_crash_only_audit_as_containment(self):
        state = BugHypothesisState(profile={"id": "p"})
        adapters.hydrate_debug_state(state, [_analysis_result(variable_names=["rank"])])
        adapters.counterfactual_agent.reset_agent_state()
        adapters.counterfactual_agent.AGENT_STATE["context"] = {
            "suspect": state.current_suspect(),
            "root_cause_report": state.current_root_cause_report(),
            "hypothesis_id": state.active_hypothesis_id,
            "reproduce_result": state.reproduce_result,
        }
        adapters.counterfactual_agent.AGENT_STATE["actions"] = {
            "intervention",
            "post_intervention_execution",
            "source_inspection",
        }

        response = adapters.counterfactual_agent.submit_counterfactual_invariant(
            bug_type="stack-buffer-overflow",
            repair_class="boundary",
            unsafe_condition="rank overreads local decompression buffer",
            baseline_facts=["rank == 14 avoids the local read overflow"],
            angelic_observations=[
                {"intervention": "rank = 14", "classification": "angelic", "target_crash_status": "disappeared"}
            ],
            demonic_observations=[
                {"intervention": "rank = 15", "classification": "demonic", "target_crash_status": "persisted"}
            ],
            boundary_summary="rank <= 14 only follows from crash-site buffer capacity",
            boundary_audit={
                "derived_from": "crash_site_memory_capacity",
                "only_sufficient_to_avoid_current_crash": True,
                "explains_invalid_state_producer": False,
                "stricter_semantic_contract": "unknown",
            },
            repair_invariant="rank <= 14",
            invariant_scope="MAT variable rank parsing",
            enforcement_role_preference=["fallback_consumer_guard"],
            forbidden_patch_patterns=["literalize_angelic_value"],
            forbidden_literals=["14"],
            validation_obligations=[],
            rationale="The observed boundary is memory capacity, not confirmed format validity.",
        )

        contract = adapters.counterfactual_agent.AGENT_STATE.get("contract")
        self.assertIn("Counterfactual invariant submitted", response)
        self.assertEqual(contract.semantic_repair_status, "crash_containment_only")
        self.assertEqual(contract.boundary_audit["derived_from"], "crash_site_memory_capacity")
        self.assertTrue(any("stricter" in item for item in contract.validation_obligations))
        state.set_counterfactual_contract(contract, hypothesis_id=state.active_hypothesis_id)
        plan = plan_patch_round(
            state=state,
            suspect=state.current_suspect(),
            pending_constraints=[],
            patch_agent_module=adapters.patch_agent,
        )
        candidate = plan.pending_constraints[0]
        self.assertEqual(candidate.generalization_score, 0.45)
        self.assertEqual(candidate.challenge_result["status"], "needs_source_check")
        self.assertEqual(candidate.abstract_constraint["semantic_repair_status"], "crash_containment_only")
        self.assertEqual(candidate.abstract_constraint["boundary_audit"]["derived_from"], "crash_site_memory_capacity")

    def test_counterfactual_angelic_operation_supports_logical_at_assignment(self):
        adapters.counterfactual_agent.reset_agent_state()
        with patch.object(adapters.counterfactual_agent.debug_agent, "run_to_line", return_value="stopped") as run_mock, \
             patch.object(adapters.counterfactual_agent, "debugger_assign_expression", return_value=(True, "assigned")) as assign_mock:
            response = adapters.counterfactual_agent.apply_angelic_operation("LOGIC:AT(/tmp/a.c:42) THEN offset = len - 1")

        run_mock.assert_called_once_with(line=42, file="/tmp/a.c")
        assign_mock.assert_called_once_with("offset = len - 1")
        self.assertIn("ok", response)
        self.assertIn("intervention", adapters.counterfactual_agent.AGENT_STATE["actions"])

    def test_counterfactual_angelic_operation_supports_logical_guard(self):
        adapters.counterfactual_agent.reset_agent_state()
        with patch.object(adapters.counterfactual_agent, "debugger_add_functional_guard", return_value=(True, "guard")) as guard_mock:
            response = adapters.counterfactual_agent.apply_angelic_operation(
                "LOGIC:AT(/tmp/a.c:42) THEN LOGIC:IF(offset >= len) THEN RETURN(-1)"
            )

        guard_mock.assert_called_once_with("/tmp/a.c", 42, "offset >= len", "-1")
        self.assertIn("functional guard", response)
        self.assertIn("intervention", adapters.counterfactual_agent.AGENT_STATE["actions"])

    def test_counterfactual_failed_expansion_accepts_probe_attempt_without_assignment(self):
        state = BugHypothesisState(profile={"id": "p"})
        adapters.hydrate_debug_state(state, [_analysis_result()])
        contract = self._build_counterfactual_contract(state)
        contract.boundary_summary = "insufficient counterfactual expansion"
        trace = {
            "history": [
                {"role": "assistant", "tool_calls": [{"function": {"name": "run_to_line"}}]},
                {"role": "assistant", "tool_calls": [{"function": {"name": "file_content"}}]},
                {"role": "assistant", "tool_calls": [{"function": {"name": "submit_counterfactual_contract"}}]},
            ]
        }

        missing = adapters.counterfactual_agent._missing_required_agent_actions(trace, contract)

        self.assertEqual(missing, [])

    def test_counterfactual_enforcement_site_is_ranked_before_preferred_crash_site(self):
        candidate = ConstraintCandidate(
            constraint="offset < len",
            constraint_status="counterfactual_contract",
            challenge_result={"status": "supported"},
            abstract_constraint={
                "type": "counterfactual_contract",
                "enforcement_site": {
                    "file": "/tmp/a.c",
                    "line": 12,
                    "role": "producer",
                    "patchability_score": 0.1,
                },
            },
        )
        suspect = _analysis_result(
            preferred_edit_location={
                "file": "/tmp/a.c",
                "line": 42,
                "role": "same_site_guard",
                "patchability_score": 0.99,
            },
            candidate_edit_locations=[],
        )

        locations = adapters._candidate_location_plan(candidate, suspect)

        self.assertEqual(locations[0]["source"], "counterfactual_enforcement")
        self.assertEqual(locations[0]["role"], "producer")

    def test_counterfactual_probe_marks_target_crash_disappeared_only_on_clean_exit(self):
        state = BugHypothesisState(
            profile={"id": "p", "counterfactual_probe_budget": 1},
            reproduce_result={"error": "AddressSanitizer: heap-buffer-overflow"},
        )
        adapters.hydrate_debug_state(
            state,
            [
                _analysis_result(
                    variable_names=["offset", "len"],
                    known_angelic_assignments=[{"variable": "offset", "value": "len - 1"}],
                )
            ],
        )

        with patch.object(adapters.counterfactual_agent, "debugger_run_to_line", return_value=({"reason": "breakpoint-hit"}, "")), \
             patch.object(adapters.counterfactual_agent, "debugger_assign", return_value=(True, "ok")), \
             patch.object(adapters.counterfactual_agent, "debugger_continue", return_value=({"reason": "exited-normally"}, "")):
            contract = self._build_counterfactual_contract(state, run_probes=True)

        observation = contract.angelic_observations[0]
        self.assertEqual(observation["outcome"], "angelic")
        self.assertEqual(observation["target_crash_status"], "disappeared")

    def test_counterfactual_probe_does_not_treat_breakpoint_hit_as_angelic(self):
        state = BugHypothesisState(
            profile={"id": "p", "counterfactual_probe_budget": 1},
            reproduce_result={"error": "AddressSanitizer: heap-buffer-overflow"},
        )
        adapters.hydrate_debug_state(
            state,
            [
                _analysis_result(
                    variable_names=["offset", "len"],
                    known_angelic_assignments=[{"variable": "offset", "value": "len - 1"}],
                )
            ],
        )

        with patch.object(adapters.counterfactual_agent, "debugger_run_to_line", return_value=({"reason": "breakpoint-hit"}, "")), \
             patch.object(adapters.counterfactual_agent, "debugger_assign", return_value=(True, "ok")), \
             patch.object(adapters.counterfactual_agent, "debugger_continue", return_value=({"reason": "breakpoint-hit"}, "")):
            contract = self._build_counterfactual_contract(state, run_probes=True)

        observation = contract.angelic_observations[0]
        self.assertEqual(observation["outcome"], "inconclusive")
        self.assertEqual(observation["target_crash_status"], "inconclusive")

    def test_counterfactual_probe_marks_matching_sanitizer_as_persisted(self):
        state = BugHypothesisState(
            profile={"id": "p", "counterfactual_probe_budget": 1},
            reproduce_result={"error": "AddressSanitizer: heap-buffer-overflow"},
        )
        adapters.hydrate_debug_state(
            state,
            [
                _analysis_result(
                    variable_names=["offset", "len"],
                    known_angelic_assignments=[{"variable": "offset", "value": "len - 1"}],
                )
            ],
        )
        asan_output = "==1==ERROR: AddressSanitizer: heap-buffer-overflow\nSUMMARY: AddressSanitizer\n"

        with patch.object(adapters.counterfactual_agent, "debugger_run_to_line", return_value=({"reason": "breakpoint-hit"}, "")), \
             patch.object(adapters.counterfactual_agent, "debugger_assign", return_value=(True, "ok")), \
             patch.object(adapters.counterfactual_agent, "debugger_continue", return_value=({"reason": "exited-normally"}, asan_output)):
            contract = self._build_counterfactual_contract(state, run_probes=True)

        observation = contract.angelic_observations[0]
        self.assertEqual(observation["outcome"], "demonic")
        self.assertEqual(observation["target_crash_status"], "persisted")

    def test_counterfactual_probe_marks_different_asan_error_kind_as_changed(self):
        state = BugHypothesisState(
            profile={"id": "p", "counterfactual_probe_budget": 1},
            reproduce_result={"error": "AddressSanitizer: heap-buffer-overflow"},
        )
        adapters.hydrate_debug_state(
            state,
            [
                _analysis_result(
                    variable_names=["offset", "len"],
                    known_angelic_assignments=[{"variable": "offset", "value": "len - 1"}],
                )
            ],
        )
        asan_output = "==1==ERROR: AddressSanitizer: stack-buffer-overflow\nSUMMARY: AddressSanitizer\n"

        with patch.object(adapters.counterfactual_agent, "debugger_run_to_line", return_value=({"reason": "breakpoint-hit"}, "")), \
             patch.object(adapters.counterfactual_agent, "debugger_assign", return_value=(True, "ok")), \
             patch.object(adapters.counterfactual_agent, "debugger_continue", return_value=({"reason": "exited-normally"}, asan_output)):
            contract = self._build_counterfactual_contract(state, run_probes=True)

        observation = contract.angelic_observations[0]
        self.assertEqual(observation["outcome"], "inconclusive")
        self.assertEqual(observation["target_crash_status"], "changed")

    def test_counterfactual_probe_marks_matching_signal_as_persisted(self):
        state = BugHypothesisState(
            profile={"id": "p", "counterfactual_probe_budget": 1},
            reproduce_result={"error": "AddressSanitizer: DEADLYSIGNAL\nSEGV"},
        )
        adapters.hydrate_debug_state(
            state,
            [
                _analysis_result(
                    variable_names=["offset", "len"],
                    known_angelic_assignments=[{"variable": "offset", "value": "len - 1"}],
                )
            ],
        )

        with patch.object(adapters.counterfactual_agent, "debugger_run_to_line", return_value=({"reason": "breakpoint-hit"}, "")), \
             patch.object(adapters.counterfactual_agent, "debugger_assign", return_value=(True, "ok")), \
             patch.object(adapters.counterfactual_agent, "debugger_continue", return_value=({"reason": "signal-received", "signal_name": "SIGSEGV"}, "")):
            contract = self._build_counterfactual_contract(state, run_probes=True)

        observation = contract.angelic_observations[0]
        self.assertEqual(observation["outcome"], "demonic")
        self.assertEqual(observation["target_crash_status"], "persisted")

    def test_counterfactual_probe_marks_other_sanitizer_as_changed(self):
        state = BugHypothesisState(
            profile={"id": "p", "counterfactual_probe_budget": 1},
            reproduce_result={"error": "AddressSanitizer: heap-buffer-overflow"},
        )
        adapters.hydrate_debug_state(
            state,
            [
                _analysis_result(
                    variable_names=["offset", "len"],
                    known_angelic_assignments=[{"variable": "offset", "value": "len - 1"}],
                )
            ],
        )
        lsan_output = "==1==ERROR: LeakSanitizer: detected memory leaks\nSUMMARY: LeakSanitizer\n"

        with patch.object(adapters.counterfactual_agent, "debugger_run_to_line", return_value=({"reason": "breakpoint-hit"}, "")), \
             patch.object(adapters.counterfactual_agent, "debugger_assign", return_value=(True, "ok")), \
             patch.object(adapters.counterfactual_agent, "debugger_continue", return_value=({"reason": "exited-normally"}, lsan_output)):
            contract = self._build_counterfactual_contract(state, run_probes=True)

        observation = contract.angelic_observations[0]
        self.assertEqual(observation["outcome"], "inconclusive")
        self.assertEqual(observation["target_crash_status"], "changed")

    def test_patch_round_uses_llm_operational_repair_intent(self):
        class FakeLLM:
            def __init__(self):
                self.prompts = []

            def query(self, prompt, logger=None):
                self.prompts.append(prompt)
                if "OperationalRepairIntentAnalyst" in prompt:
                    return (
                        "{"
                        "'repair_intent': 'Repair the 64-bit Mach-O fat_arch_64 allocation and read extents so each entry uses sizeof(struct fat_arch_64) or sizeof(*fa).', "
                        "'mechanism_hint': 'fat_arch_64 extent repair', "
                        "'required_edits': ['use sizeof(struct fat_arch_64) in calloc', 'use sizeof(*fa) in RRMOA length'], "
                        "'forbidden_patch_shape': ['setting duhd.au_count to zero'], "
                        "'reason': 'The debug summary identifies wrong sizeof operands in the 64-bit fat binary path.'"
                        "}"
                    )
                return "[]"

        state = BugHypothesisState(profile={"id": "p"})
        adapters.hydrate_debug_state(
            state,
            [
                _analysis_result(
                    file="/src/libdwarf/src/lib/libdwarf/dwarf_machoread.c",
                    line=1323,
                    variable_names=["fa", "duhd.au_count", "sizeof(fa)"],
                    debug_summary=(
                        "The crash is caused by two copy-paste bugs in "
                        "_dwarf_object_detector_universal_head_fd: calloc uses "
                        "sizeof(struct fat_arch) instead of sizeof(struct fat_arch_64), "
                        "and RRMOA uses duhd.au_count*sizeof(fa) instead of sizeof(*fa)."
                    ),
                    preferred_repair_stage="allocation_extent",
                    bug_type_profile={
                        "bug_type": "out_of_bounds",
                        "evidence_family": "operational",
                        "evidence_kind": "operational_allocation_size",
                        "generalization_target": "repair_intent",
                    },
                    repair_topology="local_invariant",
                )
            ],
        )

        with patch.object(
            adapters.patch_agent,
            "patch",
            return_value={
                "patches": [{"file": "/tmp/a.c", "start_line": 1, "end_line": 1, "patch": "x"}],
                "strategy": "allocation_size_fix",
                "location_type": "upstream",
                "semantic_risk": "low",
                "requires_regression_check": False,
            },
        ):
            message = adapters.run_patch_round(state, llm_agent=FakeLLM(), logger=self._logger())

        self.assertEqual(message.recommended_next_actor, "verify")
        self.assertIn("fat_arch_64 allocation and read extents", state.patch_candidates[0].constraint)
        self.assertNotIn("Repair the upstream state transition", state.patch_candidates[0].constraint)
        self.assertIn("fat_arch_64 extent repair", state.patch_candidates[0].metadata["abstract_constraint"]["llm_intent_inference"]["mechanism_hint"])

    def test_verify_policy_weak_direct_patch_routes_to_counterfactual(self):
        candidate = PatchCandidate(
            constraint="offset <= len",
            metadata={"repair_layer": "layer1"},
        )
        decision = classify_verification_outcome(
            candidate,
            {
                "status": "pass",
                "recommended_next_actor": "counterfactual",
                "layer1_verdict": "weak",
                "direct_patch_assessment": {"recommended_next_actor": "counterfactual"},
            },
        )

        self.assertEqual(decision.candidate_status, "weak_pass")
        self.assertEqual(decision.next_actor, "counterfactual")
        self.assertEqual(decision.event, "direct_patch_weak_pass")

    def test_verify_policy_rejected_patch_routes_back_to_layer2(self):
        candidate = PatchCandidate(
            constraint="offset <= len",
            metadata={"repair_layer": "layer2"},
        )
        decision = classify_verification_outcome(
            candidate,
            {
                "status": "semantic_regression",
                "recommended_next_actor": "constraint",
                "message": "Replay failed on a held-out variant.",
            },
        )

        self.assertEqual(decision.candidate_status, "rejected")
        self.assertEqual(decision.next_actor, "layer2")

    def test_verify_policy_operational_patch_failure_routes_to_fuzz_instead_of_debug(self):
        candidate = PatchCandidate(
            constraint="OPERATIONAL_REPAIR_INTENT: repair allocation extent",
            metadata={"repair_layer": "layer2", "evidence_family": "operational"},
        )
        decision = classify_verification_outcome(
            candidate,
            {
                "status": "new_site_crash",
                "recommended_next_actor": "debug",
                "message": "Crash moved after operational repair-intent patch.",
            },
        )

        self.assertEqual(decision.candidate_status, "rejected")
        self.assertEqual(decision.next_actor, "fuzz")

    def test_layer2_entry_forces_fuzz_refresh_before_constraint(self):
        state = BugHypothesisState(
            profile={"id": "p"},
            active_hypothesis_id="hyp-1",
            fuzz_result={"hypothesis_id": "hyp-1", "angelic_values": [1], "demonic_values": [2]},
            constraint_candidates=[
                ConstraintCandidate(
                    constraint="offset < len",
                    constraint_status="supported_and_executable",
                    challenge_status="supported",
                    overall_score=0.9,
                )
            ],
        )
        state.request_layer2_fuzz_refresh("verify:semantic_regression", hypothesis_id="hyp-1")

        message = adapters.run_layer2_entry_round(state)

        self.assertEqual(message.recommended_next_actor, "fuzz")
        self.assertTrue(message.artifacts["layer2_entry"]["forced_fuzz_refresh"])
        self.assertEqual(message.artifacts["layer2_entry"]["refresh_reason"], "verify:semantic_regression")

    def test_new_fuzz_result_clears_refresh_request(self):
        state = BugHypothesisState(profile={"id": "p"}, active_hypothesis_id="hyp-1")
        state.request_layer2_fuzz_refresh("verify:weak", hypothesis_id="hyp-1")

        state.set_fuzz_result({"hypothesis_id": "hyp-1", "angelic_values": [1]}, hypothesis_id="hyp-1")

        self.assertFalse(state.requires_layer2_fuzz_refresh("hyp-1"))

    def test_verify_does_not_consume_round_budget(self):
        self.assertTrue(_actor_consumes_round("debug"))
        self.assertTrue(_actor_consumes_round("patch"))
        self.assertFalse(_actor_consumes_round("verify"))

    def test_state_only_no_angelic_caps_outer_rounds_to_debug_and_patch(self):
        self.assertEqual(
            _interaction_max_rounds({"id": "p", "ablation_mode": "state_only_no_angelic"}),
            2,
        )
        self.assertEqual(
            _interaction_max_rounds({"id": "p", "ablation_mode": "state_only_no_angelic", "interaction_max_rounds": 8}),
            2,
        )
        self.assertEqual(_interaction_max_rounds({"id": "p", "interaction_max_rounds": 8}), 3)
        self.assertEqual(
            _interaction_max_rounds({"id": "p", "interaction_max_rounds": 8, "unbounded_full_pipeline": True}),
            8,
        )

    def test_no_cfc_caps_outer_rounds_to_debug_and_patch(self):
        self.assertEqual(_interaction_max_rounds({"id": "p", "ablation_mode": "no_cfc"}), 2)
        self.assertEqual(_interaction_max_rounds({"id": "p", "ablation_mode": "no_cfc", "interaction_max_rounds": 8}), 2)

    def test_legacy_layer2_actor_routes_to_counterfactual_by_default(self):
        state = BugHypothesisState(profile={"id": "p"})

        self.assertEqual(_route_legacy_layer2_actor("layer2", state, state.profile), "counterfactual")
        self.assertEqual(_route_legacy_layer2_actor("fuzz", state, state.profile), "counterfactual")
        self.assertEqual(_route_legacy_layer2_actor("constraint", state, state.profile), "counterfactual")

    def test_no_cfc_legacy_layer2_actor_routes_to_patch(self):
        state = BugHypothesisState(profile={"id": "p", "ablation_mode": "no_cfc"})

        self.assertEqual(_route_legacy_layer2_actor("layer2", state, state.profile), "patch")
        self.assertEqual(_route_legacy_layer2_actor("fuzz", state, state.profile), "patch")
        self.assertEqual(_route_legacy_layer2_actor("constraint", state, state.profile), "patch")

    def test_legacy_layer2_actor_routes_to_patch_when_contract_exists(self):
        state = BugHypothesisState(profile={"id": "p", "counterfactual_probe_budget": 0})
        adapters.hydrate_debug_state(state, [_analysis_result()])
        self._run_counterfactual_round_with_submitted_contract(state)

        self.assertEqual(_route_legacy_layer2_actor("constraint", state, state.profile), "patch")

    def test_legacy_layer2_actor_can_be_enabled_explicitly(self):
        state = BugHypothesisState(profile={"id": "p", "enable_legacy_layer2": True})

        self.assertEqual(_route_legacy_layer2_actor("layer2", state, state.profile), "layer2")

    def test_state_only_no_angelic_patch_round_caps_location_strategy_grid(self):
        state = BugHypothesisState(profile={"id": "p", "ablation_mode": "state_only_no_angelic"})
        adapters.hydrate_debug_state(
            state,
            [
                _analysis_result(
                    candidate_edit_locations=[
                        {"file": "/tmp/a.c", "line": 10, "role": "root_cause_site", "patchability_score": 0.9},
                        {"file": "/tmp/a.c", "line": 11, "role": "upstream_invariant_site", "patchability_score": 0.8},
                        {"file": "/tmp/a.c", "line": 12, "role": "upstream_invariant_site", "patchability_score": 0.7},
                        {"file": "/tmp/a.c", "line": 13, "role": "same_site_guard", "patchability_score": 0.3},
                    ],
                )
            ],
        )

        with patch.object(adapters.patch_agent, "patch", return_value=None) as mock_patch:
            message = adapters.run_patch_round(state, llm_agent=None, logger=self._logger())

        self.assertEqual(mock_patch.call_count, 6)
        self.assertEqual(message.recommended_next_actor, "done")
        self.assertEqual(state.patch_candidates, [])

    def test_state_only_no_angelic_patch_plan_strips_angelic_and_cfc_evidence(self):
        state = BugHypothesisState(profile={"id": "p", "ablation_mode": "state_only_no_angelic"})
        adapters.hydrate_debug_state(
            state,
            [
                _analysis_result(
                    typed_angelic_evidence={"evidence_family": "counterfactual", "evidence_kind": "relation"},
                    demonic_trace_summary={"delta": "from fuzz"},
                )
            ],
        )

        plan = plan_patch_round(
            state=state,
            suspect=state.current_suspect(),
            pending_constraints=[],
            patch_agent_module=adapters.patch_agent,
        )

        candidate = plan.pending_constraints[0]
        self.assertEqual(candidate.constraint_status, "operational_repair_intent")
        self.assertEqual(candidate.typed_angelic_evidence, {})
        self.assertEqual(candidate.challenge_result, {})
        self.assertEqual(candidate.abstract_constraint["type"], "observation_only_repair_intent")
        self.assertEqual(candidate.abstract_constraint["llm_intent_inference"], {})

    def test_state_only_no_angelic_skips_operational_repair_intent_llm(self):
        class FailingLLM:
            def query(self, prompt, logger=None):
                raise AssertionError("state-only no-angelic must not call operational repair-intent LLM")

        state = BugHypothesisState(profile={"id": "p", "ablation_mode": "state_only_no_angelic"})
        adapters.hydrate_debug_state(state, [_analysis_result()])

        report = adapters._refine_operational_root_cause_report(
            state,
            state.current_suspect(),
            FailingLLM(),
            logger=self._logger(),
        )

        self.assertNotIn("operational_repair_intent_inference", state.current_suspect())
        self.assertEqual(report["evidence_kind"], "observation_only_state")

    def test_state_only_no_angelic_patch_prompt_omits_angelic_and_cfc_context(self):
        suspect = _analysis_result(
            typed_angelic_evidence={"evidence_family": "counterfactual", "evidence_kind": "relation"},
            angelic_observations=[{"classification": "angelic"}],
            counterfactual_invariant={"type": "counterfactual_invariant", "repair_invariant": "offset < len"},
            challenge_result={"status": "supported"},
        )
        session = adapters.patch_agent.PatchSession(
            adapters.patch_agent.PatchInput(
                {"id": "p", "ablation_mode": "state_only_no_angelic"},
                "OPERATIONAL_REPAIR_INTENT: repair from observed crash state",
                suspect,
            )
        )

        prompt = session._get_initial_prompt()

        self.assertNotIn("## CounterfactualInvariant", prompt)
        self.assertNotIn("Concrete angelic values", prompt)
        self.assertNotIn("supporting_angelic_evidence", prompt)
        self.assertNotIn("[Typed Angelic Evidence]", prompt)
        self.assertNotIn("[Angelic Observations]", prompt)
        self.assertNotIn("[Constraint Challenger Summary]", prompt)
        self.assertNotIn("angelic_shape", prompt)

    def test_lldb_only_patch_prompt_uses_clean_runtime_boundary(self):
        suspect = _analysis_result(
            context_variables={
                "offset": "999",
                "nested_pollution": {
                    "patchability_score": 0.95,
                    "forced_patch_strategy": "fix_upstream_invariant",
                    "plain_fact": "offset is larger than len",
                },
            },
            suspect_expressions=["buf[offset]", "role: counterfactual_probe_site"],
            typed_angelic_evidence={"evidence_family": "counterfactual", "evidence_kind": "relation"},
            angelic_observations=[{"classification": "angelic"}],
            demonic_seed_records=[
                {
                    "site": {"file": "/tmp/a.c", "line": 42, "role": "counterfactual_probe_site"},
                    "variable": "offset",
                    "value": "999",
                }
            ],
            counterfactual_invariant={"type": "counterfactual_invariant", "repair_invariant": "offset < len"},
            challenge_result={
                "status": "supported",
                "counterexample_interventions": [{"value": "still crashes"}],
            },
            active_patch_location={
                "file": "/tmp/a.c",
                "line": 40,
                "role": "state_init_site",
                "patchability_score": 0.95,
            },
            forced_patch_strategy={"strategy": "fix_upstream_invariant"},
            preferred_repair_stage="state_update",
            location_groups=[{"name": "preferred"}],
        )
        session = adapters.patch_agent.PatchSession(
            adapters.patch_agent.PatchInput(
                {"id": "p", "ablation_mode": "lldb_only"},
                "OPERATIONAL_REPAIR_INTENT: repair from observed crash state",
                suspect,
            )
        )

        prompt = session._get_initial_prompt()

        self.assertIn("# Patch Task: LLDB-only Ablation", prompt)
        self.assertIn("## DebugAgent RCA Summary", prompt)
        self.assertIn("## Observed Runtime Facts", prompt)
        self.assertIn("## Source Starting Points", prompt)
        self.assertIn("Offset must be normalized before the access.", prompt)
        self.assertIn("buf[offset]", prompt)
        self.assertIn("plain_fact", prompt)
        self.assertIn("offset is larger than len", prompt)
        self.assertIn("Use source inspection to decide where the invalid state should be prevented, corrected, or validated.", prompt)
        self.assertIn("Use LLDB tools only to observe runtime state needed to validate source-level assumptions.", prompt)
        self.assertNotIn("Counterfactual Invariant Agent", prompt)
        self.assertNotIn("## CounterfactualInvariant", prompt)
        self.assertNotIn("## Counterfactual Summary", prompt)
        self.assertNotIn("constraint_role", prompt)
        self.assertNotIn("repair_intent", prompt)
        self.assertNotIn("[Demonic Seed Records]", prompt)
        self.assertNotIn("counterfactual_probe_site", prompt)
        self.assertNotIn("[Recommended Patch Strategies]", prompt)
        self.assertNotIn("[Forced Patch Strategy]", prompt)
        self.assertNotIn("patchability_score", prompt)
        self.assertNotIn("Active Patch Attempt Location", prompt)
        self.assertNotIn("Preferred Repair Stage", prompt)
        self.assertNotIn("Location Groups", prompt)
        self.assertNotIn("Constraint Challenger Summary", prompt)

    def test_lldb_only_patch_system_prompt_omits_cfc_system_framing(self):
        class FakeGenericAgent:
            def __init__(self, name, system_prompt):
                self.name = name
                self.system_prompt = system_prompt

            def register_hook(self, *args, **kwargs):
                return None

        with patch.object(adapters.patch_agent, "GenericAgent", FakeGenericAgent):
            agent = adapters.patch_agent.get_generic_agent(profile={"ablation_mode": "lldb_only"})

        self.assertIn("LLDB-only ablation branch", agent.system_prompt)
        self.assertIn("Runtime mutation and post-mutation continuation tools are intentionally unavailable", agent.system_prompt)
        self.assertNotIn("Counterfactual Invariant Agent", agent.system_prompt)
        self.assertNotIn("CFC repair invariant", agent.system_prompt)
        self.assertNotIn("debugger_assign", agent.system_prompt)

    def test_full_pipeline_budget_caps_location_strategy_grid(self):
        state = BugHypothesisState(profile={"id": "p"})
        adapters.hydrate_debug_state(
            state,
            [
                _analysis_result(
                    candidate_edit_locations=[
                        {"file": "/tmp/a.c", "line": 10, "role": "root_cause_site", "patchability_score": 0.9},
                        {"file": "/tmp/a.c", "line": 11, "role": "upstream_invariant_site", "patchability_score": 0.8},
                        {"file": "/tmp/a.c", "line": 12, "role": "upstream_invariant_site", "patchability_score": 0.7},
                        {"file": "/tmp/a.c", "line": 13, "role": "same_site_guard", "patchability_score": 0.3},
                    ],
                )
            ],
        )

        with patch.object(adapters.patch_agent, "patch", return_value=None) as mock_patch:
            message = adapters.run_patch_round(state, llm_agent=None, logger=self._logger())

        self.assertEqual(mock_patch.call_count, 6)
        self.assertEqual(message.recommended_next_actor, "layer2")
        self.assertEqual(state.patch_candidates, [])

    def test_state_tracks_root_cause_reports_per_hypothesis(self):
        state = BugHypothesisState(
            profile={"id": "p"},
        )

        adapters.hydrate_debug_state(
            state,
            [
                _analysis_result(hypothesis_id="hyp-1"),
                _analysis_result(hypothesis_id="hyp-2", file="/tmp/b.c", line=84, variable_names=["len"]),
            ],
        )
        first_report = state.current_root_cause_report()
        self.assertIsNotNone(first_report)
        self.assertEqual(first_report.hypothesis_id, "hyp-1")

        second_report = first_report.__class__(
            hypothesis_id="hyp-2",
            summary="alternate",
            bug_type="out_of_bounds",
            direct_patch_allowed=False,
        )
        state.set_root_cause_report(second_report, hypothesis_id="hyp-2")
        state.active_hypothesis_id = "hyp-2"

        self.assertIs(state.current_root_cause_report(), second_report)
        self.assertEqual(state.root_cause_reports["hyp-1"].hypothesis_id, "hyp-1")
        self.assertEqual(state.root_cause_reports["hyp-2"].hypothesis_id, "hyp-2")

    def test_state_tracks_fuzz_results_per_hypothesis(self):
        state = BugHypothesisState(profile={"id": "p"}, active_hypothesis_id="hyp-1")
        state.set_fuzz_result({"hypothesis_id": "hyp-1", "angelic_values": [1]}, hypothesis_id="hyp-1")
        state.set_fuzz_result({"hypothesis_id": "hyp-2", "angelic_values": [2]}, hypothesis_id="hyp-2")

        self.assertEqual(state.current_fuzz_result()["angelic_values"], [1])
        state.active_hypothesis_id = "hyp-2"
        self.assertEqual(state.current_fuzz_result()["angelic_values"], [2])

    def test_switching_to_hypothesis_without_artifacts_clears_compatibility_views(self):
        state = BugHypothesisState(profile={"id": "p"}, active_hypothesis_id="hyp-1")
        state.set_fuzz_result({"hypothesis_id": "hyp-1", "angelic_values": [1]}, hypothesis_id="hyp-1")
        state.replace_constraint_candidates(
            [ConstraintCandidate(constraint="x < len", constraint_status="supported_and_executable")]
        )

        state.active_hypothesis_id = "hyp-2"

        self.assertIsNone(state.current_fuzz_result())
        self.assertEqual(state.current_constraint_candidates(), [])


if __name__ == "__main__":
    unittest.main()
