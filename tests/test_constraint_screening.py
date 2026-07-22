import pathlib
import sys
import subprocess
import unittest
import tempfile
import json
from unittest.mock import patch
import types


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
fuzzer_base = types.SimpleNamespace(MutatorBase=type("MutatorBase", (), {"__init__": lambda self, logger=None: None}))
sys.modules.setdefault("fuzzer", types.SimpleNamespace())
sys.modules.setdefault("fuzzer.mutators", types.SimpleNamespace())
sys.modules.setdefault("fuzzer.mutators.base", fuzzer_base)
sys.modules.setdefault("blocks", types.SimpleNamespace(memory=types.SimpleNamespace(get_addr=lambda *a, **k: None), integer=types.SimpleNamespace()))

from agent import constraint_agent, patch_agent, adapters, debug_agent, reproduce_agent, stalk_agent  # noqa: E402
from agent.contracts import ConstraintCandidate  # noqa: E402
from agent.type_angelic import build_typed_angelic_evidence, infer_bug_type_profile  # noqa: E402
from agent.state import BugHypothesisState  # noqa: E402
from tools.fuzzer.engine import InDebuggerFuzzer  # noqa: E402
from utils.files import dump_json, make_json_safe  # noqa: E402
from utils.verification import collect_patch_evidence, verify_patch_feedback  # noqa: E402
from utils import command as command_utils  # noqa: E402


class ConstraintScreeningTests(unittest.TestCase):
    def setUp(self):
        self.suspect = {
            "file": "/tmp/f.c",
            "line": 10,
            "variable_names": ["x"],
            "llm_inferred_type": "int",
            "debug_summary": "The crash happens because memory that may be read later is not initialized.",
            "context_variables": {},
        }

    def test_all_skipped_evidence_is_not_passed(self):
        with patch.object(constraint_agent, "debugger_run_to_line", return_value=None):
            results = constraint_agent.online_verify_constraints(
                constraints=["x >= 2"],
                angelic_list=["LOGIC:AT(/tmp/f.c:10) THEN x = 4"],
                demonic_list=["Error: Timeout (LLDB eval)"],
                suspect_object=self.suspect,
                logger=type("L", (), {"info": lambda *a, **k: None, "warning": lambda *a, **k: None})(),
            )
        self.assertEqual(results["x >= 2"]["constraint_status"], "rejected")
        self.assertGreater(results["x >= 2"]["support_stats"]["positive_examples_skipped"], 0)

    def test_array_primary_var_is_not_assigned_scalar_probe(self):
        suspect = {
            "file": "/tmp/f.c",
            "line": 10,
            "variable_names": ["arr"],
            "llm_inferred_type": "mz_uint8 [32]",
            "debug_summary": "The crash happens because uninitialized array state is later read.",
            "context_variables": {},
        }
        assign_calls = []

        def _record_assign(expr):
            assign_calls.append(expr)
            return True, "ok"

        with patch.object(constraint_agent, "debugger_run_to_line", return_value=None), \
             patch.object(constraint_agent, "debugger_print", return_value="0"), \
             patch.object(constraint_agent, "debugger_assign_expression", side_effect=_record_assign), \
             patch.object(constraint_agent, "debugger_continue", return_value=({"reason": "signal-received"}, "")):
            results = constraint_agent.online_verify_constraints(
                constraints=["0"],
                angelic_list=["LOGIC:AT(/tmp/f.c:10) THEN arr[0] = 1"],
                demonic_list=[256],
                suspect_object=suspect,
                logger=type("L", (), {"info": lambda *a, **k: None, "warning": lambda *a, **k: None})(),
            )
        self.assertNotIn("arr = 256", assign_calls)
        self.assertNotIn("arr = 0x100", assign_calls)
        self.assertEqual(results["0"]["support_stats"]["negative_examples_seen"], 0)

    def test_non_scalar_evidence_is_preserved(self):
        with patch.object(constraint_agent, "debugger_run_to_line", return_value=None), \
             patch.object(constraint_agent, "debugger_print", return_value="1"), \
             patch.object(constraint_agent, "debugger_assign_expression", return_value=(True, "ok")), \
             patch.object(constraint_agent, "debugger_continue", return_value=({"reason": "exited-normally"}, "")):
            results = constraint_agent.online_verify_constraints(
                constraints=["x >= 2"],
                angelic_list=["LOGIC:AT(/tmp/f.c:10) THEN (void)memset(buf, 0, 8)", 4],
                demonic_list=[1],
                suspect_object=self.suspect,
                logger=type("L", (), {"info": lambda *a, **k: None, "warning": lambda *a, **k: None})(),
            )
        self.assertIn("LOGIC:AT(/tmp/f.c:10) THEN (void)memset(buf, 0, 8)", results["x >= 2"]["non_scalar_angelic_examples"])
        self.assertEqual(results["x >= 2"]["mechanism_hint"], "memory_init")

    def test_challenger_falsifies_constraint_on_safe_violation(self):
        with patch.object(constraint_agent, "debugger_run_to_line", return_value=None), \
             patch.object(constraint_agent, "debugger_print", side_effect=["1", "0", "0", "0"]), \
             patch.object(constraint_agent, "debugger_assign_expression", return_value=(True, "ok")), \
             patch.object(constraint_agent, "debugger_continue", return_value=({"reason": "exited-normally"}, "")):
            results = constraint_agent.online_verify_constraints(
                constraints=["x >= 2"],
                angelic_list=[4],
                demonic_list=[1],
                suspect_object={**self.suspect, "constraint_challenger_budget": 1},
                logger=type("L", (), {"info": lambda *a, **k: None, "warning": lambda *a, **k: None})(),
            )
        self.assertEqual(results["x >= 2"]["constraint_status"], "rejected")
        self.assertEqual(results["x >= 2"]["precheck_status"], "passed")
        self.assertGreater(results["x >= 2"]["precheck_score"], 0.0)
        self.assertEqual(results["x >= 2"]["challenge_result"]["status"], "falsified")
        self.assertEqual(results["x >= 2"]["challenge_status"], "falsified")
        self.assertEqual(results["x >= 2"]["challenge_score"], 0.0)
        self.assertGreater(len(results["x >= 2"]["challenge_result"]["counterexample_interventions"]), 0)

    def test_logic_intervention_can_support_constraint(self):
        with patch.object(constraint_agent, "debugger_run_to_line", return_value=None), \
             patch.object(constraint_agent, "debugger_print", side_effect=["1", "0", "1"]), \
             patch.object(constraint_agent, "debugger_assign_expression", return_value=(True, "ok")), \
             patch.object(constraint_agent, "debugger_continue", side_effect=[({"reason": "exited-normally"}, ""), ({"reason": "signal-received"}, "")]):
            results = constraint_agent.online_verify_constraints(
                constraints=["x >= 2"],
                angelic_list=["LOGIC:AT(/tmp/f.c:10) THEN x = 4", 4],
                demonic_list=[1],
                suspect_object={**self.suspect, "constraint_challenger_budget": 1},
                logger=type("L", (), {"info": lambda *a, **k: None, "warning": lambda *a, **k: None})(),
            )
        self.assertIn(results["x >= 2"]["challenge_result"]["status"], {"supported", "inconclusive", "needs_source_check", "falsified"})
        self.assertEqual(results["x >= 2"]["challenge_result"]["constraint_eval_records"][0]["intervention"]["kind"], "logic")

    def test_constraint_verifier_respects_explicit_top_k_and_budget(self):
        seen = []

        def _fake_challenger(*, constraint, intervention_budget=None, **kwargs):
            seen.append((constraint, intervention_budget))
            return {
                "status": "supported",
                "supporting_interventions": [],
                "counterexample_interventions": [],
                "constraint_eval_records": [],
                "patchability_score": 0.7,
                "overall_score": 0.7,
                "recommended_next_actor": "patch",
            }

        with patch.object(constraint_agent, "debugger_run_to_line", return_value=None), \
             patch.object(constraint_agent, "debugger_print", side_effect=["1", "0"] * 12), \
             patch.object(constraint_agent, "debugger_assign_expression", return_value=(True, "ok")), \
             patch.object(constraint_agent, "_run_constraint_challenger", side_effect=_fake_challenger):
            constraint_agent.online_verify_constraints(
                constraints=["x >= 2", "x >= 3", "x >= 4"],
                angelic_list=[4],
                demonic_list=[1],
                suspect_object={
                    **self.suspect,
                    "constraint_challenge_top_k": 1,
                    "constraint_challenger_budget": 11,
                },
                logger=type("L", (), {"info": lambda *a, **k: None, "warning": lambda *a, **k: None})(),
            )

        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0][1], 11)

    def test_operational_logic_constraint_is_verified_without_boolean_eval(self):
        with patch.object(constraint_agent, "debugger_run_to_line", return_value=None), \
             patch.object(constraint_agent, "debugger_assign_expression", return_value=(True, "ok")), \
             patch.object(constraint_agent, "debugger_continue", return_value=({"reason": "exited-normally"}, "")):
            results = constraint_agent.online_verify_constraints(
                constraints=["LOGIC:AT(/tmp/f.c:10) THEN x = 4"],
                angelic_list=["LOGIC:AT(/tmp/f.c:10) THEN x = 4"],
                demonic_list=[],
                suspect_object=self.suspect,
                logger=type("L", (), {"info": lambda *a, **k: None, "warning": lambda *a, **k: None})(),
            )
        self.assertEqual(results["LOGIC:AT(/tmp/f.c:10) THEN x = 4"]["constraint_kind"], "operational")
        self.assertEqual(results["LOGIC:AT(/tmp/f.c:10) THEN x = 4"]["constraint_status"], "supported_and_executable")
        self.assertEqual(results["LOGIC:AT(/tmp/f.c:10) THEN x = 4"]["challenge_result"]["status"], "supported")
        self.assertIn("state normalization", results["LOGIC:AT(/tmp/f.c:10) THEN x = 4"]["abstract_constraint"]["text"])

    def test_operational_logic_constraint_can_be_generalized_with_llm(self):
        class StubLLM:
            def query(self, prompt, logger=None):
                return (
                    "{'text': 'Clamp size before the copy to keep the transfer within the packet buffer.', "
                    "'normalized_variables': ['size'], "
                    "'guard_condition': 'size exceeds the packet capacity', "
                    "'effect_summary': 'The downstream memcpy stays within bounds.', "
                    "'generalized_predicate': 'size <= MAX_RPKT_LEN before memcpy', "
                    "'repair_stage': 'state_update', "
                    "'overfit_risk': 'low'}"
                )

        generalized = constraint_agent._generalize_operational_constraint_with_llm(
            llm_agent=StubLLM(),
            suspect_object={**self.suspect, "debug_summary": "Clamp size before memcpy to avoid overflowing the packet buffer."},
            fuzz_result={},
            constraint="LOGIC:AT(/tmp/f.c:10) THEN size = size > 8192 ? 8192 : size",
            angelic_values=["LOGIC:AT(/tmp/f.c:10) THEN size = size > 8192 ? 8192 : size"],
            demonic_values=["size = 8376"],
            function_body="memcpy(dst, src, size);",
            logger=type("L", (), {"warning": lambda *a, **k: None})(),
        )
        self.assertEqual(generalized["generalized_predicate"], "size <= MAX_RPKT_LEN before memcpy")
        self.assertEqual(generalized["repair_stage"], "state_update")
        self.assertEqual(generalized["overfit_risk"], "low")
        self.assertEqual(generalized["normalized_variables"], ["size"])

    def test_angelic_consumption_contract_hides_proxy_values(self):
        suspect = {
            **self.suspect,
            "debug_summary": "The crash happens because later reads observe uninitialized tree storage that should have been fully zeroed before use.",
        }
        semantics = constraint_agent._infer_constraint_semantics_with_llm(
            llm_agent=None,
            suspect_object=suspect,
            fuzz_result={},
            constraint="r->m_table_sizes[1] * 4 >= 128",
            angelic_values=["LOGIC:AT(/tmp/f.c:10) THEN (void)memset(&r->m_tree_1, 0, 128)"],
            demonic_values=[1],
            function_body="if (x) return 0;",
            logger=type("L", (), {"warning": lambda *a, **k: None})(),
        )
        contract = semantics["angelic_consumption_contract"]
        self.assertEqual(contract["raw_angelic_visibility"], "hide")
        self.assertEqual(contract["angelic_consumption_mode"], "abstract_only")
        self.assertTrue(contract["forbidden_literalizations"])

    def test_build_typed_angelic_evidence_for_uaf(self):
        profile = infer_bug_type_profile(reproduce_result={"error": "AddressSanitizer: heap-use-after-free"})
        evidence = build_typed_angelic_evidence(
            bug_type_profile=profile,
            suspect_object={"variable_names": ["obj"]},
            angelic_values=[{"obj_state": "live"}],
            demonic_values=["freed_obj_used"],
            trace_pairs=[{"outcome": {"kind": "angelic"}, "path_delta": {"change_count": 1}}],
            minimal_deltas=[{"intervention": {"kind": "assignment"}}],
        )
        self.assertEqual(evidence["bug_type"], "use_after_free")
        self.assertEqual(evidence["angelic_type"], "temporal_lifetime")
        self.assertTrue(evidence["repair_locations"])
        self.assertTrue(evidence["validation_obligations"])


class PatchRankingTests(unittest.TestCase):
    def test_memory_init_proxy_constraint_prefers_upstream_fix(self):
        suspect = {
            "debug_summary": "Only part of the tree is zeroed before later reads.",
            "repair_intent": "Ensure data that may be read on this path is initialized before use.",
            "mechanism_hint": "memory_init",
            "constraint_status": "supported_but_proxy_like",
            "top_angelic_examples": ["LOGIC:AT(...) THEN (void)memset(pTree, 0, 20 * sizeof(mz_int16))"],
        }
        ranked = patch_agent._rank_patch_strategies("r->m_table_sizes[1] >= 2", suspect)
        self.assertEqual(ranked[0]["strategy"], "fix_upstream_invariant")
        self.assertNotEqual(ranked[0]["strategy"], "bounds_check_before_access")

    def test_out_of_bounds_profile_prefers_upstream_bounds_repairs(self):
        suspect = {
            "debug_summary": "An index derived from parsed input crosses the valid buffer extent before the read.",
            "repair_intent": "Ensure the index stays within the parsed buffer boundary.",
            "mechanism_hint": "bounds_normalization",
            "constraint_status": "supported_and_executable",
            "bug_type_profile": infer_bug_type_profile(reproduce_result={"error": "AddressSanitizer: heap-buffer-overflow"}),
        }
        ranked = patch_agent._rank_patch_strategies("idx < len", suspect)
        self.assertEqual(ranked[0]["strategy"], "fix_upstream_invariant")
        self.assertEqual(ranked[0]["location_type"], "upstream")

    def test_use_after_free_profile_prefers_lifetime_or_invariant_repair(self):
        suspect = {
            "debug_summary": "The object is freed on one path and then reused later through a stale alias.",
            "repair_intent": "Ensure the object remains live until the final use or the stale path is invalidated.",
            "mechanism_hint": "ownership_reset",
            "constraint_status": "supported_and_executable",
            "bug_type_profile": infer_bug_type_profile(reproduce_result={"error": "AddressSanitizer: heap-use-after-free"}),
        }
        ranked = patch_agent._rank_patch_strategies("obj_is_live_before_use", suspect)
        self.assertEqual(ranked[0]["strategy"], "fix_upstream_invariant")
        self.assertEqual(ranked[0]["location_type"], "upstream")


class DebugRoutingTests(unittest.TestCase):
    def test_bug_type_profile_distinguishes_surface_from_root_cause(self):
        reproduce = {"error": "AddressSanitizer: DEADLYSIGNAL\nSEGV in free()"}
        summary = (
            "The root cause is a heap buffer overflow where memcpy(dst, src, size) copies more than a fixed "
            "buffer capacity and corrupts adjacent metadata before a later free() crash."
        )
        surface = infer_bug_type_profile(
            reproduce_result=reproduce,
            debug_summary=summary,
            classification_mode="surface",
        )
        root = infer_bug_type_profile(
            reproduce_result=reproduce,
            debug_summary=summary,
            classification_mode="root_cause",
        )
        self.assertEqual(surface["bug_type"], "invalid_pointer")
        self.assertEqual(root["bug_type"], "out_of_bounds")

    def test_bug_type_profile_classifies_uninitialized_report(self):
        profile = infer_bug_type_profile(
            profile={"id": "t"},
            reproduce_result={"error": "MemorySanitizer: use-of-uninitialized-value"},
        )
        self.assertEqual(profile["bug_type"], "uninitialized_use")
        self.assertEqual(profile["angelic_shape"], "initialization_state")

    def test_empty_debug_analysis_retries_instead_of_finishing(self):
        state = BugHypothesisState(profile={"id": "t"})
        message = adapters._build_debug_message(state, [])
        self.assertEqual(message.recommended_next_actor, "debug")
        self.assertEqual(message.actor, "debug")
        self.assertTrue(message.questions_for_others)
        self.assertEqual(message.questions_for_others[0].target_actor, "debug")

    def test_debug_retry_observation_is_passed_to_debug_agent(self):
        state = BugHypothesisState(
            profile={"id": "t"},
            reproduce_result={"error": "AddressSanitizer", "func": "f", "file": "/tmp/f.c", "line": 12},
            debug_retry_observation="Retry with a concrete RCA.",
        )

        with patch.object(adapters.debug_agent, "debug", return_value=[]) as debug:
            adapters.run_debug_round(state)

        info = debug.call_args.args[1]
        self.assertEqual(info["debug_retry_observation"], "Retry with a concrete RCA.")

    def test_empty_debug_retry_schedules_once_before_stopping(self):
        state = BugHypothesisState(profile={"id": "t"}, next_actor="debug", round_index=1)
        meta = {}
        logger = type("L", (), {"warning": lambda *a, **k: None})()

        scheduled = stalk_agent._schedule_empty_debug_retry(state, meta, state.profile, logger=logger)

        self.assertTrue(scheduled)
        self.assertEqual(state.next_actor, "debug")
        self.assertEqual(state.round_index, 0)
        self.assertEqual(state.debug_empty_analysis_retries, 1)
        self.assertIn("non-empty RCA", state.debug_retry_observation)
        self.assertNotIn("failure", meta)

        scheduled = stalk_agent._schedule_empty_debug_retry(state, meta, state.profile, logger=logger)

        self.assertFalse(scheduled)
        self.assertEqual(state.next_actor, "done")
        self.assertEqual(meta["failure"]["reason"], "empty_analysis")

    def test_debug_message_populates_edit_location_context(self):
        state = BugHypothesisState(
            profile={"id": "t"},
            reproduce_result={"error": "MemorySanitizer: use-of-uninitialized-value"},
        )
        analysis = [{
            "file": "/tmp/f.c",
            "line": 42,
            "variable_names": ["x"],
            "debug_summary": "The crash is caused by uninitialized state; the buffer must be fully initialized before use.",
            "function_name": "foo",
        }]
        adapters._build_debug_message(state, analysis)
        suspect = state.suspects[0]
        self.assertEqual(suspect["preferred_edit_location"]["line"], 42)
        self.assertEqual(suspect["repair_topology"], "init_then_use")
        self.assertTrue(suspect["candidate_edit_locations"])
        self.assertIn("forbidden_fix_patterns", suspect)
        self.assertIn("patch_expansion_policy", suspect)
        self.assertTrue(suspect["patch_expansion_policy"]["allow_call_chain_expansion"])
        self.assertEqual(suspect["preferred_repair_stage"], "initialization")
        self.assertIn("causal_chain_summary", suspect)
        self.assertIn("forbidden_repair_stages", suspect)
        self.assertIn("surface_bug_type_profile", suspect)
        self.assertEqual(suspect["surface_bug_type_profile"]["classification_mode"], "surface")
        self.assertEqual(suspect["bug_type_profile"]["bug_type"], "uninitialized_use")

    def test_debug_message_promotes_named_init_site_when_summary_points_to_it(self):
        state = BugHypothesisState(
            profile={"id": "t"},
            reproduce_result={"error": "MemorySanitizer: use-of-uninitialized-value"},
        )
        with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as fh:
            fh.write("#define foo_init(r) do { (r)->state = 0; } while (0)\n")
            fh.write("void use_state(struct obj *r) {\n")
            fh.write("  int x = r->state;\n")
            fh.write("}\n")
            path = fh.name
        analysis = [{
            "file": path,
            "line": 3,
            "variable_names": ["r->state"],
            "debug_summary": "The root cause is that foo_init() only initializes one field, leaving the rest uninitialized before use.",
            "function_name": "use_state",
        }]
        adapters._build_debug_message(state, analysis)
        suspect = state.suspects[0]
        self.assertEqual(suspect["preferred_edit_location"]["function"], "foo_init")
        self.assertEqual(suspect["preferred_edit_location"]["line"], 1)
        self.assertEqual(suspect["preferred_edit_location"]["role"], "constructor_init_definition")

    def test_debug_message_promotes_cross_file_init_callsite_from_summary_and_repro(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = pathlib.Path(tmpdir)
            src = repo / "src"
            build = src / "build" / "amalgamation"
            build.mkdir(parents=True)
            cfile = build / "miniz.c"
            cfile.write_text(
                "\n".join(
                    [
                        "#include \"miniz.h\"",
                        "void helper(void) {}",
                        "void use_state(void) {",
                        "  int x = 1;",
                        "}",
                        "void mz_zip_reader_extract_to_mem_no_alloc1(void) {",
                        "  int inflator = 0;",
                        "  tinfl_init(&inflator);",
                        "}",
                    ]
                )
            )
            hfile = src / "miniz.h"
            hfile.write_text("#define tinfl_init(r) do { *(r) = 0; } while (0)\n")
            state = BugHypothesisState(
                profile={"id": "t", "src": str(src)},
                reproduce_result={"error": "MemorySanitizer: use-of-uninitialized-value\n  Uninitialized value was created by an allocation of 'inflator' in the stack frame of function 'mz_zip_reader_extract_to_mem_no_alloc1'"},
            )
            analysis = [{
                "file": str(cfile),
                "line": 4,
                "variable_names": ["x"],
                "debug_summary": "The root cause may be that tinfl_init only partially initializes state before use.",
                "function_name": "use_state",
            }]
            adapters._build_debug_message(state, analysis)
            suspect = state.suspects[0]
            self.assertEqual(suspect["preferred_edit_location"]["function"], "tinfl_init")
            self.assertEqual(suspect["preferred_edit_location"]["role"], "constructor_init_callsite")
            self.assertEqual(suspect["preferred_edit_location"]["line"], 8)
            self.assertIn("inflator", suspect["preferred_edit_location"]["why_here"])

    def test_debug_session_skips_non_project_frames_when_project_frame_exists(self):
        with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as fh:
            fh.write("int opensips_entry(void) { return 0; }\n")
            path = fh.name
        session = None
        with patch.object(
            debug_agent.DebugSession,
            "_get_debug_profile",
            return_value=debug_agent.DebugProfile(path, 1, 1, is_fallback=False),
        ):
            session = debug_agent.DebugSession(
                debug_agent.DebugInput(
                    profile={"functions": ["opensips_entry"], "use_constraint": True},
                    error="",
                    func="opensips_entry",
                    file=path,
                    line=1,
                )
            )

        frames = [
            (0, "ExecuteFilesOnyByOne", "aflpp_driver.c", 234),
            (1, "opensips_entry", path, 1),
        ]
        logger = type(
            "L",
            (),
            {
                "warn": lambda *a, **k: None,
                "warning": lambda *a, **k: None,
                "debug": lambda *a, **k: None,
                "info": lambda *a, **k: None,
            },
        )()
        with patch.object(debug_agent, "debugger_backtrace", return_value=["f0", "f1"]), \
             patch.object(debug_agent, "parse_lldb_frame", side_effect=frames):
            selected = session._get_frames(logger=logger)
        self.assertEqual(selected, [frames[1]])

    def test_debug_session_skips_missing_source_frame_in_analysis(self):
        session = None
        with patch.object(
            debug_agent.DebugSession,
            "_get_debug_profile",
            return_value=debug_agent.DebugProfile("/tmp/repro.c", 1, 1, is_fallback=False),
        ):
            session = debug_agent.DebugSession(
                debug_agent.DebugInput(
                    profile={"functions": [], "use_constraint": True},
                    error="",
                    func="ExecuteFilesOnyByOne",
                    file="/tmp/repro.c",
                    line=1,
                )
            )
        logger = type(
            "L",
            (),
            {
                "warning": lambda *a, **k: None,
                "info": lambda *a, **k: None,
            },
        )()
        analysis = session._analyze_frame((0, "ExecuteFilesOnyByOne", "aflpp_driver.c", 234), logger=logger)
        self.assertIsNone(analysis)

    def test_low_patchability_constraints_prefer_low_risk_upstream_strategies(self):
        candidate = ConstraintCandidate(
            constraint="idx < len",
            constraint_status="weakly_supported",
            challenge_result={"status": "inconclusive", "patchability_score": 0.2},
        )
        ranked = adapters._candidate_strategy_plan(
            candidate,
            {
                "debug_summary": "An index derived from parsed input crosses the valid buffer extent before the read.",
                "repair_intent": "Ensure the index stays within the parsed buffer boundary.",
                "mechanism_hint": "bounds_normalization",
                "bug_type_profile": infer_bug_type_profile(reproduce_result={"error": "AddressSanitizer: heap-buffer-overflow"}),
            },
            last_feedback=None,
        )
        self.assertTrue(ranked)
        self.assertEqual(ranked[0]["location_type"], "upstream")
        self.assertEqual(ranked[0]["semantic_risk"], "low")

    def test_run_constraint_round_promotes_logic_angelic_values_to_operational_candidates(self):
        state = BugHypothesisState(
            profile={"id": "t"},
            reproduce_result={"error": "AddressSanitizer: heap-buffer-overflow"},
            suspects=[{
                "file": "/tmp/f.c",
                "line": 10,
                "function_name": "f",
                "variable_names": ["x"],
                "debug_summary": "Clamp x before the copy to preserve bounds.",
                "context_variables": {},
                "bug_type_profile": infer_bug_type_profile(reproduce_result={"error": "AddressSanitizer: heap-buffer-overflow"}),
            }],
            fuzz_result={
                "deduced_constraint": "x <= 8",
                "angelic_values": ["LOGIC:AT(/tmp/f.c:10) THEN x = 8"],
                "demonic_values": [],
            },
        )

        class StubLLM:
            def query(self, prompt, logger=None):
                return "[]"

        with patch.object(constraint_agent, "debugger_run_to_line", return_value=None), \
             patch.object(constraint_agent, "debugger_assign_expression", return_value=(True, "ok")), \
             patch.object(constraint_agent, "debugger_continue", return_value=({"reason": "exited-normally"}, "")), \
             patch.object(constraint_agent, "_generalize_operational_constraint_with_llm", return_value={
                 "text": "Clamp x before the copy to preserve bounds.",
                 "normalized_variables": ["x"],
                 "guard_condition": "x exceeds the safe copy extent",
                 "effect_summary": "The copy stays within bounds.",
                 "generalized_predicate": "x <= extent before copy",
                 "repair_stage": "state_update",
                 "overfit_risk": "low",
             }), \
             patch.object(constraint_agent, "_infer_constraint_semantics_with_llm", return_value={
                 "mechanism_hint": "bounds_normalization",
                 "repair_intent": "Clamp x before use.",
                 "demonic_summary": "Unbounded x crosses the safe extent.",
                 "proxy_like": False,
                 "strategy_hints": [],
                 "reason": "ok",
             }):
            candidates, _ = constraint_agent.run_constraint_round(
                state,
                StubLLM(),
                logger=type("L", (), {"info": lambda *a, **k: None, "warning": lambda *a, **k: None, "error": lambda *a, **k: None})(),
            )
        operational = [c for c in candidates if c.constraint_kind == "operational"]
        self.assertTrue(operational)
        self.assertEqual(operational[0].constraint, "LOGIC:AT(/tmp/f.c:10) THEN x = 8")
        self.assertEqual(operational[0].abstract_constraint["generalized_predicate"], "x <= extent before copy")
        self.assertEqual(operational[0].preferred_repair_stage, "state_update")

    def test_run_constraint_round_excludes_precheck_only_candidate_from_active_flow(self):
        state = BugHypothesisState(
            profile={"id": "t"},
            reproduce_result={"error": "AddressSanitizer: heap-buffer-overflow"},
            suspects=[{
                "file": "/tmp/f.c",
                "line": 10,
                "function_name": "f",
                "variable_names": ["x"],
                "debug_summary": "Clamp x before the copy to preserve bounds.",
                "context_variables": {},
                "bug_type_profile": infer_bug_type_profile(reproduce_result={"error": "AddressSanitizer: heap-buffer-overflow"}),
            }],
            fuzz_result={
                "deduced_constraint": "x <= 8",
                "angelic_values": [8],
                "demonic_values": [9],
            },
        )

        class StubLLM:
            def query(self, prompt, logger=None):
                return "['x <= 8']"

        with patch.object(constraint_agent, "online_verify_constraints", return_value={
            "x <= 8": {
                "constraint": "x <= 8",
                "constraint_kind": "predicate",
                "constraint_status": "weakly_supported",
                "status": "challenged_inconclusive",
                "precheck_status": "passed",
                "precheck_score": 0.75,
                "reason": "Scalar precheck passed, but challenger remained inconclusive.",
                "support_stats": {},
                "mechanism_hint": "bounds_normalization",
                "proxy_like": False,
                "execution_check": {"classification": "unclear_execution"},
                "challenge_result": {
                    "status": "inconclusive",
                    "overall_score": 0.31,
                    "recommended_next_actor": "fuzz",
                },
                "challenge_status": "inconclusive",
                "challenge_score": 0.31,
                "overall_score": 0.31,
                "top_angelic_examples": [8],
            }
        }), \
             patch.object(constraint_agent, "_infer_constraint_semantics_with_llm", return_value={
                 "mechanism_hint": "bounds_normalization",
                 "repair_intent": "Clamp x before use.",
                 "demonic_summary": "Unbounded x crosses the safe extent.",
                 "proxy_like": False,
                 "strategy_hints": [],
                 "reason": "ok",
             }):
            candidates, message = constraint_agent.run_constraint_round(
                state,
                StubLLM(),
                logger=type("L", (), {"info": lambda *a, **k: None, "warning": lambda *a, **k: None, "error": lambda *a, **k: None})(),
            )

        self.assertTrue(candidates)
        self.assertTrue(all(candidate.precheck_status == "passed" for candidate in candidates))
        self.assertTrue(all(candidate.challenge_status == "inconclusive" for candidate in candidates))
        self.assertTrue(all(candidate.status == "challenged_inconclusive" for candidate in candidates))
        self.assertEqual(message.recommended_next_actor, "fuzz")
        self.assertIn("challenger-backed validation", message.claims[0])

    def test_use_after_free_profile_changes_topology_and_stage(self):
        state = BugHypothesisState(
            profile={"id": "t"},
            reproduce_result={"error": "AddressSanitizer: heap-use-after-free"},
        )
        analysis = [{
            "file": "/tmp/f.c",
            "line": 88,
            "variable_names": ["obj"],
            "debug_summary": "The object is freed too early and then reused later through a stale alias.",
            "function_name": "free_then_use",
        }]
        adapters._build_debug_message(state, analysis)
        suspect = state.suspects[0]
        self.assertEqual(suspect["bug_type_profile"]["bug_type"], "use_after_free")
        self.assertEqual(suspect["repair_topology"], "cross_file_invariant")
        self.assertEqual(suspect["preferred_repair_stage"], "ownership_lifetime")
        self.assertIn("delete_release_without_ownership_reason", suspect["forbidden_fix_patterns"])

    def test_oob_allocation_size_summary_keeps_repair_site_distinct_from_crash_site(self):
        state = BugHypothesisState(
            profile={"id": "t"},
            reproduce_result={"error": "AddressSanitizer: heap-buffer-overflow"},
        )
        analysis = [{
            "file": "/src/libdwarf/src/lib/libdwarf/dwarf_machoread.c",
            "line": 1324,
            "variable_names": ["duhd.au_count", "fa"],
            "debug_summary": (
                "The crash is a heap-buffer-overflow in _dwarf_memcpy_noswap_bytes "
                "(dwarf_memcpy_swap.c:49) called from fill_in_uni_arch_64. "
                "fill_in_uni_arch_64 (dwarf_machoread.c:1210-1216) is called from "
                "_dwarf_object_detector_universal_head_fd (dwarf_machoread.c:1340). "
                "Root cause is the allocation/read size uses sizeof(struct fat_arch) "
                "and sizeof(fa) in dwarf_machoread.c."
            ),
            "function_name": "_dwarf_memcpy_noswap_bytes",
        }]
        adapters._build_debug_message(state, analysis)
        suspect = state.suspects[0]
        self.assertEqual(suspect["crash_site"]["file"], "dwarf_memcpy_swap.c")
        self.assertEqual(suspect["crash_site"]["line"], 49)
        self.assertEqual(suspect["crash_site"]["function"], "_dwarf_memcpy_noswap_bytes")
        self.assertEqual(suspect["root_cause_site"]["file"], "/src/libdwarf/src/lib/libdwarf/dwarf_machoread.c")
        self.assertEqual(suspect["root_cause_site"]["line"], 1324)
        self.assertEqual(suspect["root_cause_site"]["function"], "_dwarf_object_detector_universal_head_fd")
        self.assertEqual(suspect["repair_topology"], "single_site")
        self.assertFalse(suspect["patch_expansion_policy"]["allow_cross_file_expansion_if_needed"])

    def test_oob_at_style_summary_keeps_local_companion_line_in_scope(self):
        state = BugHypothesisState(
            profile={"id": "t"},
            reproduce_result={"error": "AddressSanitizer: heap-buffer-overflow"},
        )
        analysis = [{
            "file": "/src/libdwarf/src/lib/libdwarf/dwarf_machoread.c",
            "line": 1323,
            "variable_names": ["duhd.au_count", "fa", "sizeof(struct fat_arch)"],
            "debug_summary": (
                "The crash is a heap-buffer-overflow in _dwarf_memcpy_noswap_bytes "
                "at dwarf_memcpy_swap.c:49, called from fill_in_uni_arch_64 at "
                "dwarf_machoread.c:1213. The root cause is at dwarf_machoread.c "
                "lines 1323-1324 and 1332, where the 64-bit fat_arch buffer is "
                "allocated and read with wrong sizes. Bug 2 (line 1332): "
                "`duhd.au_count*sizeof(fa)` uses sizeof(fa) instead of sizeof(*fa)."
            ),
            "function_name": "_dwarf_memcpy_noswap_bytes",
        }]
        adapters._build_debug_message(state, analysis)
        suspect = state.suspects[0]
        self.assertEqual(suspect["crash_site"]["file"], "dwarf_memcpy_swap.c")
        self.assertEqual(suspect["crash_site"]["line"], 49)
        self.assertEqual(suspect["crash_site"]["function"], "_dwarf_memcpy_noswap_bytes")
        self.assertNotEqual(suspect["root_cause_site"]["function"], "_dwarf_memcpy_noswap_bytes")
        self.assertEqual(suspect["repair_topology"], "local_invariant")
        self.assertIn("sizeof(fa)", suspect["variable_names"])
        self.assertLessEqual(suspect["allowed_edit_scope"]["line_window"][0], 1323)
        self.assertGreaterEqual(suspect["allowed_edit_scope"]["line_window"][1], 1332)
        group = suspect["location_groups"][0]
        self.assertTrue(group["must_modify_together"])
        self.assertIn(1332, [item["line"] for item in group["locations"]])

    def test_oob_root_cause_function_without_line_is_used_for_edit_locations(self):
        state = BugHypothesisState(
            profile={"id": "t"},
            reproduce_result={"error": "AddressSanitizer: heap-buffer-overflow"},
        )
        analysis = [{
            "file": "/src/libdwarf/src/lib/libdwarf/dwarf_machoread.c",
            "line": 1325,
            "variable_names": ["duhd.au_count", "fa", "sizeof(struct fat_arch)"],
            "debug_summary": (
                "Heap-buffer-overflow in _dwarf_memcpy_noswap_bytes "
                "(dwarf_memcpy_swap.c:49) during memcpy called from fill_in_uni_arch_64 "
                "(dwarf_machoread.c:1211-1213). ROOT CAUSE: Two related bugs in "
                "_dwarf_object_detector_universal_head_fd (dwarf_machoread.c): "
                "Line 1323-1324 uses sizeof(struct fat_arch). Line 1332 uses sizeof(fa)."
            ),
            "function_name": "_dwarf_memcpy_noswap_bytes",
        }]
        adapters._build_debug_message(state, analysis)
        suspect = state.suspects[0]
        self.assertEqual(suspect["root_cause_site"]["function"], "_dwarf_object_detector_universal_head_fd")
        group = suspect["location_groups"][0]
        self.assertTrue(all(item["function"] == "_dwarf_object_detector_universal_head_fd" for item in group["locations"]))
        self.assertIn(1332, [item["line"] for item in group["locations"]])

    def test_oob_copy_paste_summary_ignores_correct_comparison_path_lines(self):
        state = BugHypothesisState(
            profile={"id": "t"},
            reproduce_result={"error": "AddressSanitizer: heap-buffer-overflow"},
        )
        analysis = [{
            "file": "/src/libdwarf/src/lib/libdwarf/dwarf_machoread.c",
            "line": 1323,
            "variable_names": ["fa", "duhd.au_count", "sizeof(struct fat_arch)"],
            "debug_summary": (
                "The crash is a heap-buffer-overflow caused by two copy-paste bugs in "
                "the 64-bit fat binary handling path in `_dwarf_object_detector_universal_head_fd` "
                "(dwarf_machoread.c). Bug 1 (line 1324): calloc uses sizeof(struct fat_arch). "
                "Bug 2 (line 1332): duhd.au_count*sizeof(fa) uses sizeof(fa). "
                "The 32-bit path (lines 1293-1305) correctly uses sizeof(struct fat_arch) "
                "and sizeof(*fa), proving these are copy-paste errors. "
                "Fix: Line 1324 change sizeof(struct fat_arch). Line 1332 change sizeof(fa)."
            ),
            "function_name": "_dwarf_memcpy_noswap_bytes",
        }]
        adapters._build_debug_message(state, analysis)
        suspect = state.suspects[0]
        self.assertEqual(suspect["root_cause_site"]["function"], "_dwarf_object_detector_universal_head_fd")
        self.assertEqual(suspect["crash_site"], {})
        lines = [item["line"] for item in suspect["location_groups"][0]["locations"]]
        self.assertIn(1323, lines)
        self.assertIn(1324, lines)
        self.assertIn(1332, lines)
        self.assertNotIn(1293, lines)
        self.assertNotIn(1305, lines)

    def test_null_deref_profile_prefers_non_guard_stage(self):
        state = BugHypothesisState(
            profile={"id": "t"},
            reproduce_result={"error": "SIGSEGV at address 0x0"},
        )
        analysis = [{
            "file": "/tmp/f.c",
            "line": 21,
            "variable_names": ["p"],
            "debug_summary": "The callee receives a NULL pointer on an invalid path and dereferences it.",
            "function_name": "consume_ptr",
        }]
        adapters._build_debug_message(state, analysis)
        suspect = state.suspects[0]
        self.assertEqual(suspect["bug_type_profile"]["bug_type"], "null_dereference")
        self.assertEqual(suspect["repair_topology"], "caller_to_callee")
        self.assertEqual(suspect["preferred_repair_stage"], "input_validation")
        self.assertIn("dummy_pointer_fabrication", suspect["forbidden_fix_patterns"])

    def test_patch_prompt_contains_type_overlay(self):
        suspect = {
            "file": "/tmp/f.c",
            "line": 10,
            "variable_names": ["buf", "len"],
            "repair_intent": "Ensure accesses remain within the valid buffer extent.",
            "top_angelic_examples": ["idx = len - 1"],
            "demonic_summary": "The access crosses the heap buffer bound.",
            "constraint_role": "generalized_hypothesis",
            "bug_type_profile": infer_bug_type_profile(
                reproduce_result={"error": "AddressSanitizer: heap-buffer-overflow"}
            ),
        }
        session = patch_agent.PatchSession(
            patch_agent.PatchInput(
                profile={"chat_dir": "/tmp", "patch_output": "/tmp/p.json"},
                constraint="idx < len",
                suspect_object=suspect,
            )
        )
        prompt = session._get_initial_prompt()
        self.assertIn("Typed Angelic Evidence Profile", prompt)
        self.assertIn("out_of_bounds", prompt)

    def test_patch_prompt_contains_typed_angelic_evidence_summary(self):
        suspect = {
            "file": "/tmp/f.c",
            "line": 10,
            "variable_names": ["obj"],
            "repair_intent": "Ensure the object remains live until use completes.",
            "top_angelic_examples": ["obj_state = live"],
            "demonic_summary": "A freed object is reused on a later path.",
            "constraint_role": "generalized_hypothesis",
            "bug_type_profile": infer_bug_type_profile(reproduce_result={"error": "AddressSanitizer: heap-use-after-free"}),
            "typed_angelic_evidence": {
                "bug_type": "use_after_free",
                "angelic_type": "temporal_lifetime",
                "generalized_spec": {"text": "use(o) must happen before free(o)"},
            },
            "demonic_trace_summary": {"unsafe_examples": ["free(o) -> use(o)"]},
        }
        session = patch_agent.PatchSession(
            patch_agent.PatchInput(
                profile={"chat_dir": "/tmp", "patch_output": "/tmp/p.json"},
                constraint="obj_is_live_before_use",
                suspect_object=suspect,
            )
        )
        prompt = session._get_initial_prompt()
        self.assertIn("Typed Angelic Evidence", prompt)
        self.assertIn("temporal_lifetime", prompt)

    def test_counterfactual_patch_prompt_uses_summary_without_raw_observations(self):
        suspect = {
            "file": "/tmp/f.c",
            "line": 10,
            "variable_names": ["destlen"],
            "debug_summary": "Allocation must reserve space for the terminator.",
            "counterfactual_invariant": {
                "type": "counterfactual_invariant",
                "unsafe_condition": "remaining capacity can reach zero before terminator write",
                "repair_invariant": "output allocation must reserve one extra byte for the terminator",
                "invariant_scope": "iconv output buffer allocation",
                "counterfactual_summary": {
                    "demonic": "allocation exactly equals converted output bytes, leaving no room for terminator",
                    "angelic": "allocation has at least one extra byte, terminator write stays in bounds",
                    "boundary": "capacity >= converted_output_bytes + 1",
                },
                "validation_obligations": ["ASan clean"],
            },
            "angelic_observations": [
                {
                    "intervention": "destlen=9 malloc(9)",
                    "after_state": "iconv writes 6 bytes ('LAYOUT'), dest=0x6020000008d6",
                }
            ],
            "demonic_trace_summary": {
                "observations": [
                    {
                        "intervention": "destlen=6 malloc(6)",
                        "after_state": "dest=0x6020000008d6",
                    }
                ]
            },
            "typed_angelic_evidence": {"classification_basis": "0x6020000008d6 LAYOUT malloc(6)"},
        }
        session = patch_agent.PatchSession(
            patch_agent.PatchInput(
                profile={"chat_dir": "/tmp", "patch_output": "/tmp/p.json"},
                constraint="reserve terminator capacity",
                suspect_object=suspect,
            )
        )

        prompt = session._get_initial_prompt()

        self.assertIn("Counterfactual Summary", prompt)
        self.assertIn("allocation exactly equals converted output bytes", prompt)
        self.assertNotIn("Angelic Observations", prompt)
        self.assertNotIn("Demonic Trace Summary", prompt)
        self.assertNotIn("destlen=6", prompt)
        self.assertNotIn("malloc(6)", prompt)
        self.assertNotIn("0x6020000008d6", prompt)
        self.assertNotIn("LAYOUT", prompt)

    def test_patch_prompt_contains_challenger_summary(self):
        suspect = {
            "file": "/tmp/f.c",
            "line": 10,
            "variable_names": ["idx", "len"],
            "repair_intent": "Restore the upstream bound invariant before the access.",
            "top_angelic_examples": ["idx = len - 1"],
            "demonic_summary": "The access crosses the valid extent.",
            "constraint_role": "generalized_hypothesis",
            "challenge_result": {
                "status": "supported",
                "patchability_score": 0.3,
                "notes": ["Constraint is supported, but patchability remains low."],
                "counterexample_interventions": [{"intervention": {"kind": "assignment", "source": "bounds_family"}}],
            },
        }
        session = patch_agent.PatchSession(
            patch_agent.PatchInput(
                profile={"chat_dir": "/tmp", "patch_output": "/tmp/p.json"},
                constraint="idx < len",
                suspect_object=suspect,
            )
        )
        prompt = session._get_initial_prompt()
        self.assertIn("Constraint Challenger Summary", prompt)
        self.assertIn("Known Challenger Counterexamples", prompt)
        self.assertIn("Low Patchability Notice", prompt)

    def test_patch_prompt_uses_active_patch_attempt_location(self):
        suspect = {
            "file": "/tmp/f.c",
            "line": 10,
            "variable_names": ["idx"],
            "repair_intent": "Repair the upstream state before use.",
            "top_angelic_examples": ["idx = 1"],
            "demonic_summary": "Unsafe execution reaches the current crash state.",
            "constraint_role": "generalized_hypothesis",
            "active_patch_location": {"file": "/tmp/f.c", "line": 42, "role": "upstream_invariant_site"},
        }
        session = patch_agent.PatchSession(
            patch_agent.PatchInput(
                profile={"chat_dir": "/tmp", "patch_output": "/tmp/p.json"},
                constraint="idx < len",
                suspect_object=suspect,
            )
        )
        prompt = session._get_initial_prompt()
        self.assertIn('"line": 42', prompt)
        self.assertIn("companion edit along the call chain", prompt)
        self.assertIn("Active Patch Attempt Location", prompt)


class FuzzTypedEvidenceTests(unittest.TestCase):
    def test_candidate_location_plan_prioritizes_upstream_when_patchability_is_low(self):
        candidate = ConstraintCandidate(
            constraint="idx < len",
            challenge_result={"status": "inconclusive", "patchability_score": 0.2},
        )
        locations = adapters._candidate_location_plan(
            candidate,
            {
                "preferred_edit_location": {"file": "/tmp/f.c", "line": 50, "role": "same_site_guard", "patchability_score": 0.35},
                "candidate_edit_locations": [
                    {"file": "/tmp/f.c", "line": 45, "role": "upstream_invariant_site", "patchability_score": 0.72},
                    {"file": "/tmp/f.c", "line": 50, "role": "same_site_guard", "patchability_score": 0.35},
                ],
            },
        )
        self.assertTrue(locations)
        self.assertEqual(locations[0]["line"], 45)

    def test_make_json_safe_handles_custom_candidate_objects(self):
        class Candidate:
            def __init__(self):
                self.expr = "r->m_tree_1"
                self.score = 3

        safe = make_json_safe({"candidate": Candidate()})
        self.assertEqual(safe["candidate"]["__class__"], "Candidate")
        self.assertEqual(safe["candidate"]["expr"], "r->m_tree_1")

    def test_build_fuzz_message_propagates_typed_evidence(self):
        state = BugHypothesisState(profile={"id": "t"})
        fuzz_result = {
            "hypothesis_id": "hyp-1",
            "angelic_values": [1],
            "demonic_values": [2],
            "deduced_constraint": "x < len",
            "trace_pairs": [],
            "typed_angelic_evidence": {
                "bug_type": "out_of_bounds",
                "angelic_type": "bounds_value",
                "repair_locations": ["index/offset computation"],
            },
            "bug_type_profile": infer_bug_type_profile(reproduce_result={"error": "AddressSanitizer: heap-buffer-overflow"}),
        }
        message = adapters._build_fuzz_message(state, fuzz_result)
        self.assertEqual(state.bug_type_profile["bug_type"], "out_of_bounds")
        self.assertEqual(message.recommended_next_actor, "constraint")
        self.assertEqual(message.evidence[0].payload["typed_angelic_evidence"]["angelic_type"], "bounds_value")

    def test_bug_type_aware_known_assignment_expansion(self):
        engine = InDebuggerFuzzer(debugger=None, llm_agent=None)
        suspect = {
            "variable_names": ["idx", "len"],
            "context_variables": {},
            "demonic_seed_values": {"len": "7"},
            "bug_type_profile": infer_bug_type_profile(reproduce_result={"error": "AddressSanitizer: heap-buffer-overflow"}),
        }
        expanded = engine._expand_known_assignment_candidates(suspect)
        self.assertIn({"len": "0"}, expanded)
        self.assertIn({"len": "1"}, expanded)
        self.assertIn({"len": "2"}, expanded)

    def test_group_target_candidates_does_not_use_mutating_index_lookup(self):
        engine = InDebuggerFuzzer(debugger=None, llm_agent=None)
        suspect = {
            "variable_names": ["r->m_tree_1", "r->m_type"],
            "context_variables": {"r->m_table_sizes": "1"},
            "suspect_expressions": ["r->m_tree_1", "r->m_table_sizes", "r->m_type"],
            "bug_type_profile": infer_bug_type_profile(reproduce_result={"error": "MemorySanitizer: use-of-uninitialized-value"}),
        }
        groups = engine._group_target_candidates(suspect)
        self.assertTrue(groups)
        flat = [target for group in groups for target in group]
        self.assertIn("r->m_tree_1", flat)

    def test_build_intervention_serializes_custom_candidate_value(self):
        class Candidate:
            def __init__(self):
                self.expr = "LOGIC:AT(/tmp/f.c:10) THEN x=1"

        engine = InDebuggerFuzzer(debugger=None, llm_agent=None)
        intervention = engine._build_intervention(
            Candidate(),
            {"file": "/tmp/f.c", "line": 10, "variable_names": ["x"]},
            applied=True,
        )
        self.assertEqual(intervention["actions"][0]["value"]["__class__"], "Candidate")

    def test_planner_initial_prompt_contains_typed_profile(self):
        engine = InDebuggerFuzzer(debugger=None, llm_agent=None)
        suspect = {
            "variable_names": ["obj"],
            "bug_type_profile": infer_bug_type_profile(reproduce_result={"error": "AddressSanitizer: heap-use-after-free"}),
            "typed_angelic_evidence": {
                "bug_type": "use_after_free",
                "angelic_type": "temporal_lifetime",
                "generalized_spec": {"text": "use(o) must happen before free(o)"},
            },
        }
        prompt = engine._build_planner_initial_prompt(suspect, {"obj": "0x1234"})
        self.assertIn("Typed Bug Profile", prompt)
        self.assertIn("use_after_free", prompt)
        self.assertIn("temporal_lifetime", prompt)
        self.assertIn("Typed Intervention Playbook", prompt)
        self.assertIn("delay or skip a free", prompt)

    def test_planner_initial_prompt_compacts_large_runtime_artifacts(self):
        engine = InDebuggerFuzzer(debugger=None, llm_agent=None)
        huge_asan = "AddressSanitizer: heap-buffer-overflow\n" + ("frame detail " * 2000)
        suspect = {
            "variable_names": ["cur_aug_p", "end_aug_p"],
            "focus_targets": ["cur_aug_p", "end_aug_p"],
            "debug_summary": "Change > to >= at the bounds check.",
            "file": "/src/libdwarf/src/lib/libdwarf/dwarf_frame2.c",
            "line": 1541,
            "function_name": "_dwarf_create_cie_from_after_start",
            "profile": {"id": "42525052", "llm_config": {"model": "deepseek-chat"}},
            "reproduce_result": {"error": huge_asan},
            "bug_type_profile": {
                **infer_bug_type_profile(reproduce_result={"error": huge_asan}),
                "classification_basis": huge_asan,
            },
        }

        prompt = engine._build_planner_initial_prompt(suspect, {"cur_aug_p": "0x1", "end_aug_p": "0x2"})

        self.assertIn("cur_aug_p", prompt)
        self.assertIn("Change > to >=", prompt)
        self.assertNotIn("reproduce_result", prompt)
        self.assertNotIn("llm_config", prompt)
        self.assertNotIn("classification_basis", prompt)
        self.assertLess(len(prompt), 12000)


class VerificationTypedEvidenceTests(unittest.TestCase):
    def test_compile_failure_summary_prefers_failure_lines_over_ok_tail(self):
        noisy_stdout = "\n".join(
            [
                "testAlpha (Suite.Tests) ... ok",
                "error: patch failed: parser/msg_parser.c:271",
                "error: parser/msg_parser.c: patch does not apply",
            ]
            + [f"testUnicode{i} (CheckUnicodeSourceFiles.Tests) ... ok" for i in range(30)]
            + ["----------------------------------------------------------------------"]
        )
        with patch("utils.verification.file_apply_patches", return_value=True), \
             patch("utils.verification.file_undo_patches", return_value=True), \
             patch("utils.verification.run_compile", return_value=(1, noisy_stdout, "")):
            evidence = collect_patch_evidence(
                {
                    "patches": [{"file": "/tmp/f.c", "start_line": 1, "end_line": 1, "patch": "noop"}],
                },
                logger=type("L", (), {"error": lambda *a, **k: None, "debug": lambda *a, **k: None})(),
            )

        self.assertEqual(evidence["stage"], "compile_error")
        message = evidence["failure"]["message"]
        self.assertIn("return code 1", message)
        self.assertIn("patch failed: parser/msg_parser.c:271", message)
        self.assertIn("patch does not apply", message)
        self.assertNotIn("testUnicode29", message)

    def test_verify_feedback_carries_validation_obligations(self):
        feedback = verify_patch_feedback(
            {
                "patches": [],
                "bug_type_profile": infer_bug_type_profile(reproduce_result={"error": "AddressSanitizer: heap-use-after-free"}),
                "typed_angelic_evidence": {
                    "validation_obligations": ["ASan clean", "LSan clean"],
                },
            },
            logger=type("L", (), {"error": lambda *a, **k: None, "debug": lambda *a, **k: None})(),
        )
        self.assertEqual(feedback["status"], "apply_error")
        self.assertEqual(feedback["details"]["validation_obligations"], ["ASan clean", "LSan clean"])

    def test_verify_feedback_reports_validation_obligations_without_affecting_decision(self):
        with patch("utils.verification.file_apply_patches", return_value=True), \
             patch("utils.verification.file_undo_patches", return_value=True), \
             patch("utils.verification.run_compile", return_value=(0, "", "")), \
             patch("utils.verification._run_primary_replay", return_value={"return_code": 0, "error": "", "command": "poc"}), \
             patch("utils.verification._run_variant_replay", return_value={"status": "pass", "input_count": 2, "items": []}), \
             patch("utils.verification._run_regression_replay", return_value={"status": "regression_unavailable", "input_count": 0, "items": []}):
            feedback = verify_patch_feedback(
                {
                    "patches": [{"file": "/tmp/f.c", "line": 1, "patch": "noop"}],
                    "bug_type_profile": infer_bug_type_profile(reproduce_result={"error": "AddressSanitizer: heap-use-after-free"}),
                    "typed_angelic_evidence": {
                        "validation_obligations": ["ASan clean", "LSan clean"],
                    },
                    "semantic_risk": "medium",
                },
                logger=type("L", (), {"error": lambda *a, **k: None, "debug": lambda *a, **k: None})(),
            )
        self.assertEqual(feedback["status"], "pass")
        self.assertEqual(feedback["details"]["residual_risk"], "regression_unavailable")
        self.assertEqual(
            feedback["details"]["validation_obligation_status"]["coverage"][1]["status"],
            "needs_targeted_followup",
        )
        self.assertEqual(feedback["details"]["verification_confidence"], 0.8)

    def test_nonzero_primary_replay_without_sanitizer_is_not_reported_as_crash_persistence(self):
        with patch("utils.verification.file_apply_patches", return_value=True), \
             patch("utils.verification.file_undo_patches", return_value=True), \
             patch("utils.verification.run_compile", return_value=(0, "", "")), \
             patch(
                 "utils.verification._run_primary_replay",
                 return_value={
                     "return_code": 1,
                     "error": "invalid input: rejected malformed augmentation",
                     "command": "poc",
                 },
             ):
            feedback = verify_patch_feedback(
                {
                    "patches": [{"file": "/tmp/f.c", "line": 1, "patch": "noop"}],
                    "bug_type_profile": infer_bug_type_profile(reproduce_result={"error": "AddressSanitizer: heap-buffer-overflow"}),
                    "typed_angelic_evidence": {
                        "validation_obligations": ["ASan clean"],
                    },
                    "llm_verifier_enabled": False,
                },
                logger=type("L", (), {"error": lambda *a, **k: None, "debug": lambda *a, **k: None})(),
            )

        self.assertEqual(feedback["status"], "runtime_failure")
        self.assertNotIn("Patch does not fix the crash", feedback["message"])
        self.assertIn("without reproducing a sanitizer crash", feedback["message"])
        self.assertIn("not proof that the original crash remains", feedback["message"])

    def test_llm_verifier_can_accept_nonzero_primary_replay_without_sanitizer(self):
        with patch("utils.verification.file_apply_patches", return_value=True), \
             patch("utils.verification.file_undo_patches", return_value=True), \
             patch("utils.verification.run_compile", return_value=(0, "", "")), \
             patch(
                 "utils.verification._run_primary_replay",
                 return_value={
                     "return_code": 1,
                     "error": "invalid input: rejected malformed augmentation",
                     "command": "poc",
                 },
             ), \
             patch(
                 "utils.verification._judge_runtime_failure_with_llm",
                 return_value={
                     "status": "pass",
                     "recommended_next_actor": "done",
                     "blame_hint": "Original ASan crash disappeared; non-zero exit is an expected malformed-input rejection.",
                     "message": "Original crash fixed; program now rejects the malformed input.",
                     "decision_source": "llm",
                 },
             ) as judge, \
             patch("utils.verification._run_variant_replay", return_value={"status": "pass", "input_count": 1, "items": []}) as variants, \
             patch("utils.verification._run_regression_replay", return_value={"status": "pass", "input_count": 1, "items": []}) as regressions:
            feedback = verify_patch_feedback(
                {
                    "patches": [{"file": "/tmp/f.c", "line": 1, "patch": "noop"}],
                    "bug_type_profile": infer_bug_type_profile(reproduce_result={"error": "AddressSanitizer: heap-buffer-overflow"}),
                    "typed_angelic_evidence": {
                        "validation_obligations": ["original POC passes", "ASan clean"],
                    },
                },
                logger=type("L", (), {"error": lambda *a, **k: None, "debug": lambda *a, **k: None, "info": lambda *a, **k: None})(),
            )

        judge.assert_called_once()
        variants.assert_called_once()
        regressions.assert_called_once()
        self.assertEqual(feedback["status"], "pass")
        self.assertEqual(feedback["details"]["tiers"]["tier1_original_poc"]["status"], "pass_llm_nonzero")
        self.assertEqual(
            feedback["details"]["validation_obligation_status"]["coverage"][0]["status"],
            "satisfied",
        )

    def test_sanitizer_output_fails_even_when_return_code_is_zero(self):
        sanitizer_output = (
            "==1==ERROR: AddressSanitizer: heap-buffer-overflow\n"
            "    #0 0x1 in memcpy /src/llvm-project/compiler-rt/lib/asan/asan_interceptors_memintrinsics.cpp:22:3\n"
            "    #1 0x2 in product /src/project/file.c:10:2\n"
        )
        with patch("utils.verification.file_apply_patches", return_value=True), \
             patch("utils.verification.file_undo_patches", return_value=True), \
             patch("utils.verification.run_compile", return_value=(0, "", "")), \
             patch("utils.verification._run_primary_replay", return_value={"return_code": 0, "error": sanitizer_output, "command": "poc"}), \
             patch("utils.verification._run_variant_replay", return_value={"status": "disabled", "input_count": 0, "items": []}), \
             patch("utils.verification._run_regression_replay", return_value={"status": "regression_unavailable", "input_count": 0, "items": []}), \
             patch("utils.verification._judge_runtime_failure_with_llm", return_value={"status": "pass"}) as judge:
            feedback = verify_patch_feedback(
                {
                    "patches": [{"file": "/tmp/f.c", "line": 1, "patch": "noop"}],
                    "bug_type_profile": infer_bug_type_profile(reproduce_result={"error": sanitizer_output}),
                    "typed_angelic_evidence": {"validation_obligations": ["ASan clean"]},
                },
                expected_file="/src/project/file.c",
                expected_line=10,
                logger=type("L", (), {"error": lambda *a, **k: None, "debug": lambda *a, **k: None, "info": lambda *a, **k: None})(),
            )

        judge.assert_not_called()
        self.assertNotEqual(feedback["status"], "pass")
        self.assertIn(feedback["status"], {"same_site_crash", "weak_constraint", "new_site_crash"})
        self.assertEqual(feedback["details"]["tiers"]["tier1_original_poc"]["status"], "fail")

    def test_lsan_stdout_fails_even_when_return_code_is_zero(self):
        leak_output = (
            "==123==ERROR: LeakSanitizer: detected memory leaks\n"
            "Direct leak of 64 byte(s) in 1 object(s) allocated from:\n"
            "SUMMARY: LeakSanitizer: 64 byte(s) leaked in 1 allocation(s)\n"
        )
        with patch("utils.verification.file_apply_patches", return_value=True), \
             patch("utils.verification.file_undo_patches", return_value=True), \
             patch("utils.verification.run_compile", return_value=(0, "", "")), \
             patch(
                 "utils.verification._run_primary_replay",
                 return_value={"return_code": 0, "stdout": leak_output, "stderr": "", "error": "", "command": "poc"},
             ), \
             patch("utils.verification._judge_runtime_failure_with_llm", return_value={"status": "pass"}) as judge:
            feedback = verify_patch_feedback(
                {
                    "patches": [{"file": "/tmp/f.c", "line": 1, "patch": "noop"}],
                    "bug_type_profile": infer_bug_type_profile(reproduce_result={"error": "AddressSanitizer: heap-buffer-overflow"}),
                },
                logger=type("L", (), {"error": lambda *a, **k: None, "debug": lambda *a, **k: None, "info": lambda *a, **k: None})(),
            )

        judge.assert_not_called()
        self.assertNotEqual(feedback["status"], "pass")
        self.assertEqual(feedback["details"]["tiers"]["tier1_original_poc"]["status"], "fail")
        self.assertIn("LeakSanitizer: detected memory leaks", feedback["message"])

    def test_lsan_failure_cannot_be_overridden_by_runtime_llm(self):
        leak_output = (
            "REPRODUCING THE ISSUE FOR gpac.cve-2023-4681...\n"
            "Error DASHing file: BitStream Not Compliant\n"
            "==44291==ERROR: LeakSanitizer: detected memory leaks\n"
            "Direct leak of 188 byte(s) in 1 object(s) allocated from:\n"
            "    #0 0x555555e0be9f in malloc /src/llvm-project/compiler-rt/lib/asan/asan_malloc_linux.cpp:68:3\n"
            "    #1 0x555557a3bcb2 in avi_parse_input_file /src/gpac/src/media_tools/avilib.c:1944:35\n"
            "SUMMARY: AddressSanitizer: 188 byte(s) leaked in 1 allocation(s).\n"
        )
        with patch("utils.verification.file_apply_patches", return_value=True), \
             patch("utils.verification.file_undo_patches", return_value=True), \
             patch("utils.verification.run_compile", return_value=(0, "", "")), \
             patch(
                 "utils.verification._run_primary_replay",
                 return_value={"return_code": 1, "error": leak_output, "command": "secb repro"},
             ), \
             patch(
                 "utils.verification._judge_runtime_failure_with_llm",
                 return_value={
                     "status": "pass",
                     "recommended_next_actor": "done",
                     "blame_hint": "No crash; memory leak is not a runtime failure.",
                     "message": "The crash is fixed.",
                 },
             ) as judge:
            feedback = verify_patch_feedback(
                {
                    "patches": [{"file": "/tmp/f.c", "line": 1, "patch": "noop"}],
                    "bug_type_profile": infer_bug_type_profile(reproduce_result={"error": "AddressSanitizer: SEGV"}),
                },
                logger=type("L", (), {"error": lambda *a, **k: None, "debug": lambda *a, **k: None, "info": lambda *a, **k: None})(),
            )

        judge.assert_not_called()
        self.assertNotEqual(feedback["status"], "pass")
        self.assertEqual(feedback["details"]["tiers"]["tier1_original_poc"]["status"], "fail")
        self.assertIn("LeakSanitizer: detected memory leaks", feedback["message"])

    def test_variant_lsan_output_fails_even_when_return_code_is_zero(self):
        from utils import verification

        leak_output = (
            "==123==ERROR: LeakSanitizer: detected memory leaks\n"
            "SUMMARY: LeakSanitizer: 64 byte(s) leaked in 1 allocation(s)\n"
        )
        profile = {"args": ["/tmp/poc"], "file": "/out/fuzz", "enable_variant_replay": True}

        with patch("utils.verification.derive_input_variants", return_value=[["/tmp/poc.mut"]]), \
             patch(
                 "utils.verification.run_profile_once",
                 return_value={"return_code": 0, "stdout": leak_output, "stderr": "", "error": "", "command": "/out/fuzz /tmp/poc.mut"},
             ):
            report = verification._run_variant_replay(profile)

        self.assertEqual(report["status"], "fail")
        self.assertEqual(report["items"][0]["status"], "fail")
        self.assertIn("LeakSanitizer: detected memory leaks", report["items"][0]["runtime_output"])

    def test_llm_runtime_failure_feedback_includes_raw_output_excerpt(self):
        leak_output = (
            "==123==ERROR: LeakSanitizer: detected memory leaks\n"
            "Direct leak of 64 byte(s) in 1 object(s) allocated from:\n"
            "    #0 0x49e8c6 in malloc\n"
            "    #1 0x512345 in make_object /src/project/core.c:42:10\n"
            "SUMMARY: LeakSanitizer: 64 byte(s) leaked in 1 allocation(s)\n"
        )
        with patch("utils.verification.file_apply_patches", return_value=True), \
             patch("utils.verification.file_undo_patches", return_value=True), \
             patch("utils.verification.run_compile", return_value=(0, "", "")), \
             patch(
                 "utils.verification._run_primary_replay",
                 return_value={"return_code": 1, "error": leak_output, "command": "poc"},
             ), \
             patch(
                 "utils.verification._judge_runtime_failure_with_llm",
                 return_value={
                     "status": "runtime_failure",
                     "recommended_next_actor": "patch",
                     "blame_hint": "Patch fixed the original crash but introduced a leak.",
                     "message": "Original crash resolved, but a new memory leak is detected. The patch may need to address the leak as well.",
                     "decision_source": "llm",
                 },
             ) as judge:
            feedback = verify_patch_feedback(
                {
                    "patches": [{"file": "/tmp/f.c", "line": 1, "patch": "noop"}],
                    "bug_type_profile": infer_bug_type_profile(reproduce_result={"error": "AddressSanitizer: heap-buffer-overflow"}),
                },
                logger=type("L", (), {"error": lambda *a, **k: None, "debug": lambda *a, **k: None, "info": lambda *a, **k: None})(),
            )

        judge.assert_not_called()
        self.assertNotEqual(feedback["status"], "pass")
        self.assertIn("Runtime output excerpt", feedback["message"])
        self.assertIn("LeakSanitizer: detected memory leaks", feedback["message"])
        self.assertIn("/src/project/core.c:42:10", feedback["message"])

    def test_variant_replay_disabled_by_default(self):
        from utils import verification

        with patch("utils.verification.derive_input_variants") as derive:
            report = verification._run_variant_replay({"args": ["/tmp/poc"], "file": "/out/fuzz"})

        derive.assert_not_called()
        self.assertEqual(report["status"], "disabled")
        self.assertEqual(report["input_count"], 0)

    def test_verify_feedback_rejects_harness_only_patch_for_product_bug(self):
        with patch("utils.verification.file_apply_patches", return_value=True), \
             patch("utils.verification.file_undo_patches", return_value=True), \
             patch("utils.verification.run_compile", return_value=(0, "", "")), \
             patch("utils.verification._run_primary_replay", return_value={"return_code": 0, "error": "", "command": "poc"}), \
             patch("utils.verification._run_variant_replay", return_value={"status": "pass", "input_count": 2, "items": []}), \
             patch("utils.verification._run_regression_replay", return_value={"status": "pass", "input_count": 2, "items": []}):
            feedback = verify_patch_feedback(
                {
                    "patches": [{"file": "/src/project/scripts/fuzz/driver.c", "line": 1, "patch": "noop"}],
                    "suspect_file": "/src/project/src/core.c",
                    "bug_type_profile": infer_bug_type_profile(
                        reproduce_result={"error": "AddressSanitizer: heap-buffer-overflow"},
                        debug_summary="The root cause is a memcpy buffer overflow in product code before a later crash.",
                        classification_mode="root_cause",
                    ),
                    "typed_angelic_evidence": {
                        "validation_obligations": ["ASan clean"],
                    },
                    "semantic_risk": "medium",
                },
                logger=type("L", (), {"error": lambda *a, **k: None, "debug": lambda *a, **k: None})(),
            )
        self.assertEqual(feedback["status"], "contract_mismatch")
        self.assertEqual(feedback["error_signature"], "contract_mismatch")
        self.assertIn("product-code contract repair", feedback["blame_hint"])


class SnapshotRobustnessTests(unittest.TestCase):
    def test_dump_json_writes_valid_json_atomically(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = pathlib.Path(tmpdir) / "x.json"
            dump_json({"a": 1, "b": [2, 3]}, str(path))
            self.assertEqual(path.read_text().strip()[0], "{")
            self.assertIn('"a": 1', path.read_text())


class ReproduceFrameParsingTests(unittest.TestCase):
    def test_asan_binary_offset_frame_is_symbolized_to_project_source(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            executable = root / "build" / "bin" / "exiv2"
            executable.parent.mkdir(parents=True)
            executable.write_text("binary placeholder\n")
            source = root / "src" / "easyaccess.cpp"
            source.parent.mkdir(parents=True)
            source.write_text("int isoSpeed() { return 0; }\n")

            output = f"""
==1903==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000
    #0 0x555555796890 in strcmp /src/llvm-project/compiler-rt/lib/asan/../sanitizer_common/sanitizer_common_interceptors.inc:465:25
    #1 0x5555558fe35d in Exiv2::isoSpeed(Exiv2::ExifData const&) ({executable}+0x3aa35d)
SUMMARY: AddressSanitizer: SEGV ({executable}+0x3aa35d) in Exiv2::isoSpeed(Exiv2::ExifData const&)
"""
            completed = types.SimpleNamespace(
                returncode=0,
                stdout=f"Exiv2::isoSpeed(Exiv2::ExifData const&)\n{source}:42\n",
                stderr="",
            )
            with patch.object(reproduce_agent.subprocess, "run", return_value=completed):
                result = reproduce_agent._parse_run_output(
                    {"src": str(root), "file": str(executable), "args": []},
                    1,
                    "",
                    output,
                    "secb repro",
                    [],
                    logger=type("L", (), {"info": lambda *a, **k: None})(),
                )

        self.assertEqual(result["func"], "Exiv2::isoSpeed(Exiv2::ExifData const&)")
        self.assertEqual(result["file"], str(source))
        self.assertEqual(result["line"], 42)

    def test_asan_binary_offset_frame_falls_back_to_function_search(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            executable = root / "build" / "bin" / "exiv2"
            executable.parent.mkdir(parents=True)
            executable.write_text("not a real binary\n")
            source = root / "src" / "easyaccess.cpp"
            source.parent.mkdir(parents=True)
            source.write_text("\nconst char* isoSpeed() { return nullptr; }\n")

            output = f"""
==1935==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000
    #0 0x555555796890 in strcmp /src/llvm-project/compiler-rt/lib/asan/../sanitizer_common/sanitizer_common_interceptors.inc:465:25
    #1 0x5555558fe35d in Exiv2::isoSpeed(Exiv2::ExifData const&) ({executable}+0x3aa35d)
SUMMARY: AddressSanitizer: SEGV ({executable}+0x3aa35d) in Exiv2::isoSpeed(Exiv2::ExifData const&)
"""
            result = reproduce_agent._parse_run_output(
                {"src": str(root), "file": str(executable), "args": []},
                1,
                "",
                output,
                "secb repro",
                [],
                logger=type("L", (), {"info": lambda *a, **k: None})(),
            )

        self.assertEqual(result["func"], "Exiv2::isoSpeed(Exiv2::ExifData const&)")
        self.assertEqual(result["file"], str(source))
        self.assertEqual(result["line"], 2)

    def test_project_executable_is_inferred_from_binary_frame(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            executable = root / "tests" / "unit-test-server"
            executable.parent.mkdir(parents=True)
            executable.write_text("binary placeholder\n")
            source = root / "src" / "modbus.c"
            source.parent.mkdir(parents=True)
            source.write_text("int modbus_reply(void) { return 0; }\n")

            output = f"""
==4788==ERROR: AddressSanitizer: SEGV
    #0 0x555555666ce4 in modbus_reply {source}:980:46
    #3 0x5555555874cd in _start ({executable}+0x334cd)
SUMMARY: AddressSanitizer: SEGV {source}:980:46 in modbus_reply
"""
            result = reproduce_agent._parse_run_output(
                {"src": str(root), "file": "", "args": []},
                1,
                "",
                output,
                "secb repro",
                [],
                logger=type("L", (), {"info": lambda *a, **k: None})(),
            )

        self.assertEqual(result["executable"], str(executable))

    def test_asan_shared_library_offset_frame_is_symbolized_to_project_source(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            executable = root / "build" / "bin" / "exiv2"
            executable.parent.mkdir(parents=True)
            executable.write_text("binary placeholder\n")
            shared = root / "build" / "src" / "libexiv2.so.26"
            shared.parent.mkdir(parents=True)
            shared.write_text("shared placeholder\n")
            source = root / "src" / "pngchunk_int.cpp"
            source.parent.mkdir(parents=True)
            source.write_text("int keyTXTChunk() { return 0; }\n")

            output = f"""
==1995==ERROR: AddressSanitizer: heap-buffer-overflow
    #0 0x7ffff7a13e45 in Exiv2::Internal::PngChunk::keyTXTChunk(Exiv2::DataBuf const&, bool) ({shared}+0x7f0e45)
SUMMARY: AddressSanitizer: heap-buffer-overflow ({shared}+0x7f0e45) in Exiv2::Internal::PngChunk::keyTXTChunk(Exiv2::DataBuf const&, bool)
"""
            completed = types.SimpleNamespace(
                returncode=0,
                stdout=f"Exiv2::Internal::PngChunk::keyTXTChunk(Exiv2::DataBuf const&, bool)\n{source}:77\n",
                stderr="",
            )
            with patch.object(reproduce_agent.subprocess, "run", return_value=completed):
                result = reproduce_agent._parse_run_output(
                    {"src": str(root), "file": str(executable), "args": []},
                    1,
                    "",
                    output,
                    "secb repro",
                    [],
                    logger=type("L", (), {"info": lambda *a, **k: None})(),
                )

        self.assertEqual(result["file"], str(source))
        self.assertEqual(result["line"], 77)

    def test_bare_sanitizer_source_frame_resolves_by_function_name(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            source = root / "MagickCore" / "enhance.c"
            source.parent.mkdir(parents=True)
            source.write_text("\n\nstatic void SetPixelViaPixelInfo(void) {}\n")
            result = reproduce_agent._parse_run_output(
                {"src": str(root), "file": "", "args": []},
                1,
                "",
                "    #0 0x555555c1120c in SetPixelViaPixelInfo enhance.c\n",
                "secb repro",
                [],
                logger=type("L", (), {"info": lambda *a, **k: None})(),
            )
        self.assertEqual(result["file"], str(source))
        self.assertEqual(result["line"], 3)

    def test_bug_description_fallback_resolves_function_location(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            source = root / "client" / "client_control.c"
            source.parent.mkdir(parents=True)
            source.write_text("\nint ControlObjectClient_setOrigin(void) { return 0; }\n")
            result = reproduce_agent._parse_run_output(
                {
                    "src": str(root),
                    "file": "",
                    "args": [],
                    "bug_description": (
                        "segmentation violation via the function "
                        "ControlObjectClient_setOrigin() at /client/client_control.c"
                    ),
                },
                -66,
                "",
                "Timed out",
                "secb repro",
                [],
                logger=type("L", (), {"info": lambda *a, **k: None})(),
            )
        self.assertEqual(result["file"], str(source))
        self.assertEqual(result["line"], 2)

    def test_bug_description_fallback_resolves_qualified_function_in_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            source = root / "src" / "easyaccess.cpp"
            source.parent.mkdir(parents=True)
            source.write_text("\nint isoSpeed() { return 0; }\n")
            result = reproduce_agent._parse_run_output(
                {
                    "src": str(root),
                    "file": "",
                    "args": [],
                    "bug_description": (
                        "Exiv2::isoSpeed in easyaccess.cpp allows remote attackers "
                        "to cause a denial of service."
                    ),
                },
                1,
                "",
                "AddressSanitizer:DEADLYSIGNAL\n",
                "secb repro",
                [],
                logger=type("L", (), {"info": lambda *a, **k: None})(),
            )
        self.assertEqual(result["func"], "Exiv2::isoSpeed")
        self.assertEqual(result["file"], str(source))
        self.assertEqual(result["line"], 2)

    def test_bug_description_fallback_resolves_plain_function_in_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            source = root / "libarchive" / "archive_read_support_format_zip.c"
            source.parent.mkdir(parents=True)
            source.write_text("\nstatic int archive_read_format_zip_cleanup(void) { return 0; }\n")
            result = reproduce_agent._parse_run_output(
                {
                    "src": str(root),
                    "file": "",
                    "args": [],
                    "bug_description": (
                        "A memory leak in archive_read_format_zip_cleanup in "
                        "archive_read_support_format_zip.c allows remote attackers "
                        "to cause a denial of service."
                    ),
                },
                1,
                "",
                "SUMMARY: AddressSanitizer: 320 byte(s) leaked in 2 allocation(s).\n",
                "secb repro",
                [],
                logger=type("L", (), {"info": lambda *a, **k: None})(),
            )
        self.assertEqual(result["func"], "archive_read_format_zip_cleanup")
        self.assertEqual(result["file"], str(source))
        self.assertEqual(result["line"], 2)

    def test_ubsan_relative_path_resolves_under_project_tree(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            source = root / "src" / "laser" / "lsr_dec.c"
            source.parent.mkdir(parents=True)
            source.write_text("static int lsr_translate_coords(void) { return 0; }\n")
            result = reproduce_agent._parse_run_output(
                {"src": str(root), "args": []},
                1,
                "",
                "laser/lsr_dec.c:853:10: runtime error: shift exponent 4294967295 is too large\n",
                "secb repro",
                [],
                logger=type("L", (), {"info": lambda *a, **k: None})(),
            )
        self.assertEqual(result["file"], str(source))
        self.assertEqual(result["line"], 853)


class DebugInputValidationTests(unittest.TestCase):
    def test_state_only_debug_agent_uses_no_angelic_system_prompt(self):
        captured = {}

        class FakeAgent:
            def __init__(self, name, system_prompt):
                captured["system_prompt"] = system_prompt
                captured["hooks"] = []

            def register_hook(self, func, description, **kwargs):
                captured["hooks"].append(kwargs.get("name") or func.__name__)

        with patch.object(debug_agent, "GenericAgent", FakeAgent):
            debug_agent.get_generic_agent(
                True,
                use_crash_line_mode=False,
                bug_type_profile={"bug_type": "out_of_bounds"},
                profile={"ablation_mode": "state_only_no_angelic"},
            )

        self.assertIn("state-only debugging task", captured["system_prompt"])
        self.assertIn("Do not assign new values", captured["system_prompt"])
        self.assertNotIn("Intercept, Don't just Observe", captured["system_prompt"])
        self.assertNotIn("Typed Bug Profile", captured["system_prompt"])
        self.assertNotIn("debugger_assign", captured["hooks"])
        self.assertNotIn("debugger_assign_expression", captured["hooks"])
        self.assertNotIn("debugger_continue", captured["hooks"])

    def test_state_only_crash_variable_list_extracts_crash_line_tokens(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            source = pathlib.Path(tmpdir) / "x.c"
            source.write_text("int f(void) {\n  return obj->field + len;\n}\n")
            variables = debug_agent._extract_crash_variable_list(str(source), 2)

        self.assertIn("obj->field", variables)
        self.assertIn("len", variables)

    def test_secbench_legacy_constraint_is_formatted_as_bug_description(self):
        rendered = debug_agent._format_bug_description(
            {
                "runner": "secbench",
                "secbench": {"instance_id": "x.cve"},
                "constraint": "CVE natural language description",
            }
        )

        self.assertIn("## Bug Description", rendered)
        self.assertIn("CVE natural language description", rendered)
        self.assertNotIn("Primary Generalized Constraint", rendered)

    def test_debug_initial_prompt_includes_bug_description_separately(self):
        prompt = debug_agent.INITIAL_PROMPT.format(
            file="/src/x.c",
            line=10,
            start_line=1,
            error="asan",
            body="int f(void) { return 0; }",
            bug_description=debug_agent._format_bug_description({"bug_description": "public CVE summary"}),
            accumulated="",
        )

        self.assertIn("## Bug Description", prompt)
        self.assertIn("public CVE summary", prompt)
        self.assertNotIn("Primary Generalized Constraint", prompt)

    def test_secbench_bug_report_is_included_in_debug_context(self):
        rendered = debug_agent._format_bug_description(
            {
                "bug_description": "public CVE summary",
                "bug_report": "Maintainer: fix ownership before releasing the object.",
            }
        )

        self.assertIn("## Bug Description", rendered)
        self.assertIn("## Original Bug Report", rendered)
        self.assertIn("fix ownership before releasing", rendered)

    def test_secbench_bug_report_is_included_in_patch_context(self):
        session = patch_agent.PatchSession(
            patch_agent.PatchInput(
                profile={"bug_report": "Maintainer recommends validating the object lifetime."},
                constraint="object remains live",
                suspect_object={
                    "file": "/tmp/f.c",
                    "line": 10,
                    "variable_names": ["obj"],
                    "debug_summary": "obj is stale",
                },
            )
        )

        prompt = session._get_initial_prompt()

        self.assertIn("## Original Bug Report", prompt)
        self.assertIn("validating the object lifetime", prompt)

    def test_debug_session_rejects_missing_reproduce_frame(self):
        profile = {"use_constraint": True}
        debug_input = debug_agent.DebugInput(profile, "runtime error", "N/A", "N/A", -1)
        with self.assertRaisesRegex(RuntimeError, "valid reproduce frame"):
            debug_agent.DebugSession(debug_input)

    def test_debug_returns_empty_analysis_for_missing_reproduce_frame(self):
        profile = {"file": "/tmp/project", "use_constraint": True}
        info = {"error": "runtime error", "func": "N/A", "file": "N/A", "line": -1}
        logger = type(
            "L",
            (),
            {
                "warning": lambda *a, **k: None,
                "info": lambda *a, **k: None,
                "error": lambda *a, **k: None,
            },
        )()
        self.assertEqual(debug_agent.debug(profile, info, logger=logger), [])


class StalkReproduceDecisionTests(unittest.TestCase):
    def test_return_code_zero_with_sanitizer_output_is_still_a_crash(self):
        result = {
            "return_code": 0,
            "error": "==1==ERROR: AddressSanitizer: heap-buffer-overflow\n",
        }
        self.assertTrue(stalk_agent._has_runtime_crash_signature(result))

    def test_sync_profile_executable_from_reproduce(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            executable = pathlib.Path(tmpdir) / "target"
            executable.write_text("binary placeholder\n")
            profile = {"file": ""}
            changed = stalk_agent._sync_profile_executable_from_reproduce(
                profile,
                {"executable": str(executable)},
                logger=type("L", (), {"info": lambda *a, **k: None, "warning": lambda *a, **k: None})(),
            )
        self.assertTrue(changed)
        self.assertEqual(profile["file"], str(executable))

    def test_sync_profile_executable_replaces_invalid_profile_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            executable = pathlib.Path(tmpdir) / "target"
            executable.write_text("binary placeholder\n")
            profile = {"file": str(pathlib.Path(tmpdir) / "missing"), "args": ["old"]}
            changed = stalk_agent._sync_profile_executable_from_reproduce(
                profile,
                {"executable": str(executable), "args": ["new"]},
                logger=type("L", (), {"info": lambda *a, **k: None, "warning": lambda *a, **k: None})(),
            )
        self.assertTrue(changed)
        self.assertEqual(profile["file"], str(executable))
        self.assertEqual(profile["args"], ["new"])

    def test_secbench_command_is_filled_from_repro_without_testcase_arg(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            case_dir = pathlib.Path(tmpdir) / "case"
            case_dir.mkdir()
            row = {
                "work_dir": "/src/imagemagick",
                "secb_sh": """
repro() {
    /src/imagemagick/utilities/magick -seed 0 magick:logo tmp || true
}

patch() {
}
""",
            }
            (case_dir / "row.json").write_text(json.dumps(row))
            profile = {"file": "", "args": [], "secbench": {"case_dir": str(case_dir)}}
            changed = stalk_agent._maybe_fill_secbench_command_from_case(
                profile,
                logger=type("L", (), {"info": lambda *a, **k: None})(),
            )
        self.assertTrue(changed)
        self.assertEqual(profile["file"], "/src/imagemagick/utilities/magick")
        self.assertEqual(profile["args"][:2], ["-seed", "0"])

    def test_secbench_command_skips_touch_and_replaces_invalid_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            case_dir = pathlib.Path(tmpdir) / "case"
            case_dir.mkdir()
            row = {
                "work_dir": "/src/imagemagick",
                "secb_sh": """
repro() {
    touch /testcase/poc.sixel
    /src/imagemagick/utilities/magick montage /testcase/poc.sixel /dev/null
}

patch() {
}
""",
            }
            (case_dir / "row.json").write_text(json.dumps(row))
            profile = {
                "file": "/src/imagemagick/touch",
                "args": ["/testcase/poc.sixel"],
                "secbench": {"case_dir": str(case_dir)},
            }
            changed = stalk_agent._maybe_fill_secbench_command_from_case(
                profile,
                logger=type("L", (), {"info": lambda *a, **k: None})(),
            )
        self.assertTrue(changed)
        self.assertEqual(profile["file"], "/src/imagemagick/utilities/magick")
        self.assertEqual(profile["args"][:2], ["montage", "/testcase/poc.sixel"])

    def test_secbench_lsan_reproduce_infers_command_from_secb_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            executable = root / "utilities" / "magick"
            executable.parent.mkdir()
            executable.write_text("binary placeholder\n")
            (root / "secb").write_text(
                """
repro() {
    /tmp/src/utilities/magick -seed 0 magick:logo tmp
}

patch() {
}
""".replace("/tmp/src", str(root))
            )
            result = reproduce_agent._parse_run_output(
                {"runner": "secbench", "src": str(root), "file": "", "args": []},
                0,
                "==1==ERROR: LeakSanitizer: detected memory leaks\n",
                "",
                "secb repro",
                [],
                logger=type("L", (), {"info": lambda *a, **k: None})(),
            )
        self.assertEqual(result["executable"], str(executable))
        self.assertEqual(result["args"][:2], ["-seed", "0"])

    def test_secbench_command_is_filled_from_source_secb_when_case_dir_missing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            executable = root / "utilities" / "magick"
            executable.parent.mkdir()
            executable.write_text("binary placeholder\n")
            (root / "secb").write_text(
                f"""
repro() {{
    {executable} -seed 0 magick:logo tmp
}}

patch() {{
}}
"""
            )
            profile = {
                "runner": "secbench",
                "src": str(root),
                "file": "",
                "args": [],
                "secbench": {"case_dir": str(root / "missing_case")},
            }
            changed = stalk_agent._maybe_fill_secbench_command_from_case(
                profile,
                logger=type("L", (), {"info": lambda *a, **k: None})(),
            )
        self.assertTrue(changed)
        self.assertEqual(profile["file"], str(executable))
        self.assertEqual(profile["args"][:2], ["-seed", "0"])

    def test_secbench_command_is_filled_from_global_secb(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir) / "src"
            root.mkdir()
            executable = root / "utilities" / "magick"
            executable.parent.mkdir()
            executable.write_text("binary placeholder\n")
            secb = pathlib.Path(tmpdir) / "usr" / "local" / "bin" / "secb"
            secb.parent.mkdir(parents=True)
            secb.write_text(
                f"""
repro() {{
    {executable} -seed 0 -quality 3 "(" magick:logo +repage ")" tmp
}}

patch() {{
}}
"""
            )
            profile = {
                "runner": "secbench",
                "src": str(root),
                "file": "",
                "args": [],
                "secbench": {"case_dir": str(root / "missing_case")},
            }
            with patch.object(reproduce_agent.shutil, "which", return_value=str(secb)):
                changed = stalk_agent._maybe_fill_secbench_command_from_case(
                    profile,
                    logger=type("L", (), {"info": lambda *a, **k: None})(),
                )
        self.assertTrue(changed)
        self.assertEqual(profile["file"], str(executable))
        self.assertEqual(profile["args"][:4], ["-seed", "0", "-quality", "3"])

    def test_secbench_command_skips_bare_shell_helpers(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            executable = root / "build" / "examples" / "server_example_basic_io" / "server_example_basic_io"
            executable.parent.mkdir(parents=True)
            executable.write_text("binary placeholder\n")
            secb = root / "secb"
            secb.write_text(
                f"""
repro() {{
    base64 -d /testcase/poc > /testcase/poc_decoded
    {executable} &
    SERVER_PID=$!
    sleep 2
    python3 -c "print('send poc')"
    kill $SERVER_PID
}}

patch() {{
}}
"""
            )
            profile = {
                "runner": "secbench",
                "src": str(root),
                "file": "",
                "args": [],
                "secbench": {"case_dir": str(root / "missing_case")},
            }
            changed = stalk_agent._maybe_fill_secbench_command_from_case(
                profile,
                logger=type("L", (), {"info": lambda *a, **k: None})(),
            )
        self.assertTrue(changed)
        self.assertEqual(profile["file"], str(executable))
        self.assertEqual(profile["args"], [])

    def test_secbench_command_parses_pipeline_rhs_executable(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir)
            executable = root / "build" / "host" / "bin" / "mruby"
            executable.parent.mkdir(parents=True)
            executable.write_text("binary placeholder\n")
            secb = root / "secb"
            secb.write_text(
                f"""
repro() {{
    echo "' %8646911284551352320d'%1" | {executable}
}}

patch() {{
}}
"""
            )
            profile = {
                "runner": "secbench",
                "src": str(root),
                "file": "",
                "args": [],
                "secbench": {"case_dir": str(root / "missing_case")},
            }
            changed = stalk_agent._maybe_fill_secbench_command_from_case(
                profile,
                logger=type("L", (), {"info": lambda *a, **k: None})(),
            )
        self.assertTrue(changed)
        self.assertEqual(profile["file"], str(executable))
        self.assertEqual(profile["args"], [])

    def test_php_readdir_patch_uses_plain_block_not_do_without_while(self):
        command = command_utils._normalize_secbench_debug_build("bear /usr/local/bin/compile")
        self.assertIn("{ struct dirent *result = NULL;", command)
        self.assertNotIn("do { struct dirent *result = NULL;", command)

    def test_secbench_debug_build_sets_autoconf_malloc_cache(self):
        command = command_utils._normalize_secbench_debug_build("bear /usr/local/bin/compile")
        self.assertIn("ac_cv_func_malloc_0_nonnull=yes", command)
        self.assertIn("ac_cv_func_realloc_0_nonnull=yes", command)

    def test_secbench_debug_build_downgrades_upx_makefile_werror(self):
        command = command_utils._normalize_secbench_debug_build("bear /usr/local/bin/compile")
        self.assertIn("grep -Rqs -- '-Werror' src", command)
        self.assertIn("s/[[:space:]]-Werror/ -Wno-error/g", command)

    def test_secbench_debug_build_forces_cmake_cxx14(self):
        command = command_utils._normalize_secbench_debug_build("bear /usr/local/bin/compile")
        self.assertIn("-DCMAKE_CXX_STANDARD=14", command)
        self.assertIn("-DCMAKE_CXX_STANDARD_REQUIRED=ON", command)
        self.assertIn("for _secb_build_sh in build.sh /src/build.sh", command)
        self.assertIn("perl -0pi -e 's/(^|[;&|]\\s*)(cmake)(\\s+)", command)

    def test_secbench_debug_build_adds_cmake_cxx14_to_old_profiles(self):
        old_command = (
            "if [ -f build.sh ] && ! grep -q CMAKE_COMPILE_WARNING_AS_ERROR build.sh; then "
            "sed -i 's/cmake /cmake -DCMAKE_COMPILE_WARNING_AS_ERROR=OFF "
            "-DENABLE_WERROR=OFF -DWERROR=OFF -DWARNINGS_AS_ERRORS=OFF /' build.sh; fi; "
            "bear /usr/local/bin/compile"
        )
        command = command_utils._normalize_secbench_debug_build(old_command)
        self.assertIn("-DCMAKE_CXX_STANDARD=14", command)
        self.assertIn("-DCMAKE_CXX_STANDARD_REQUIRED=ON", command)
        self.assertIn("for _secb_build_sh in build.sh /src/build.sh", command)

    def test_secbench_debug_build_keeps_independent_cmake_cxx14_patch(self):
        command = (
            "if [ -f build.sh ] && ! grep -q CMAKE_COMPILE_WARNING_AS_ERROR build.sh; then "
            "sed -i 's/cmake /cmake -DCMAKE_COMPILE_WARNING_AS_ERROR=OFF "
            "-DENABLE_WERROR=OFF -DWERROR=OFF -DWARNINGS_AS_ERRORS=OFF "
            "-DCMAKE_CXX_STANDARD=14 -DCMAKE_CXX_STANDARD_REQUIRED=ON /' build.sh; fi; "
            "bear /usr/local/bin/compile"
        )
        normalized = command_utils._normalize_secbench_debug_build(command)
        self.assertIn("for _secb_build_sh in build.sh /src/build.sh", normalized)
        self.assertIn("/src/build.sh", normalized)

    def test_secbench_debug_build_cmake_patch_matches_multiline_build_script(self):
        command = command_utils._normalize_secbench_debug_build("bear /usr/local/bin/compile")
        self.assertIn("/gm' \"$_secb_build_sh\"", command)

        with tempfile.TemporaryDirectory() as tmp:
            build_sh = pathlib.Path(tmp) / "build.sh"
            build_sh.write_text("#!/bin/bash -eu\nset -eu\ncmake /src/openexr\nmake -j$(nproc)", encoding="utf-8")
            patch_command = command.split("; git submodule update", 1)[0]
            subprocess.run(["bash", "-c", patch_command], cwd=tmp, check=True)
            patched = build_sh.read_text(encoding="utf-8")

        self.assertIn("cmake -DCMAKE_COMPILE_WARNING_AS_ERROR=OFF", patched)
        self.assertIn("-DCMAKE_CXX_STANDARD=14", patched)
        self.assertIn("-DCMAKE_CXX_STANDARD_REQUIRED=ON", patched)


if __name__ == "__main__":
    unittest.main()
