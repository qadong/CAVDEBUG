import pathlib
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

from tools.fuzzer.engine import InDebuggerFuzzer  # noqa: E402
from tools.fuzzer.handles import infer_intervention_handles, should_skip_debugger_type_probe  # noqa: E402
from tools.fuzzer.synthesized_mutator import MutationOrchestrator  # noqa: E402


class FuzzHandleTests(unittest.TestCase):
    def test_infers_pointer_and_boundary_handles(self):
        suspect = {
            "variable_names": ["cur_aug_p", "end_aug_p"],
            "context_variables": {"aug_data_len": "16"},
            "llm_inferred_type": "unsigned char *",
        }

        handles = infer_intervention_handles(suspect)
        by_name = {handle.name: handle for handle in handles}

        self.assertEqual(by_name["cur_aug_p"].kind, "pointer_slot")
        self.assertEqual(by_name["end_aug_p"].kind, "pointer_boundary")
        self.assertEqual(by_name["aug_data_len"].kind, "size_slot")

    def test_pointer_like_suspect_skips_debugger_type_probe_when_inferred_type_exists(self):
        suspect = {
            "variable_names": ["cur_aug_p", "end_aug_p"],
            "context_variables": {"aug_data_len": "16"},
            "llm_inferred_type": "unsigned char *",
        }

        self.assertTrue(should_skip_debugger_type_probe(suspect))

    def test_apply_mutation_uses_slot_assignment_for_primary_handle(self):
        suspect = {
            "variable_names": ["cur_aug_p"],
            "llm_inferred_type": "unsigned char *",
        }
        fuzzer = InDebuggerFuzzer(debugger=None, llm_agent=None)
        fuzzer._intervention_handles = infer_intervention_handles(suspect)

        with patch("tools.fuzzer.engine.debugger_assign", return_value=(True, "")) as assign_mock, \
             patch("tools.fuzzer.engine.debugger_assign_expression", return_value=(False, "should_not_run")) as expr_mock:
            ok = fuzzer._apply_mutation("NULL", suspect)

        self.assertTrue(ok)
        assign_mock.assert_called_once()
        expr_mock.assert_not_called()

    def test_apply_mutation_uses_slot_assignment_for_simple_dict_targets(self):
        suspect = {
            "variable_names": ["aug_data_len"],
            "context_variables": {"aug_data_len": "16"},
            "llm_inferred_type": "size_t",
        }
        fuzzer = InDebuggerFuzzer(debugger=None, llm_agent=None)
        fuzzer._intervention_handles = infer_intervention_handles(suspect)

        with patch("tools.fuzzer.engine.debugger_assign", return_value=(True, "")) as assign_mock, \
             patch("tools.fuzzer.engine.debugger_assign_expression", return_value=(False, "should_not_run")) as expr_mock:
            ok = fuzzer._apply_mutation({"aug_data_len": "8"}, suspect)

        self.assertTrue(ok)
        assign_mock.assert_called_once_with("aug_data_len", "(size_t)(8)")
        expr_mock.assert_not_called()

    def test_synthesized_mutator_installs_at_helper_without_custom_init(self):
        script = """
class AgentMutator(SynthesizedMutator):
    def compose(self):
        return [
            self.at("/tmp/a.c", 42, "len=8"),
            at("/tmp/a.c", 43, logic_assign("len > 8", "len", "8")),
        ]
"""
        logger = type("L", (), {"info": lambda *a, **k: None, "debug": lambda *a, **k: None, "error": lambda *a, **k: None})()
        orchestrator = MutationOrchestrator(debugger=None, logger=logger)

        candidates, error = orchestrator.run_agent_script(
            {"file": "/tmp/a.c", "line": 40, "variable_names": ["len"]},
            script,
        )

        self.assertIsNone(error)
        self.assertIn('LOGIC:AT(/tmp/a.c:42) THEN len=8', candidates)
        self.assertIn('LOGIC:AT(/tmp/a.c:43) THEN LOGIC:IF(len > 8) THEN ASSIGN(len=8)', candidates)

    def test_synthesized_mutator_repairs_missing_parent_init_helpers(self):
        script = """
class AgentMutator(SynthesizedMutator):
    def __init__(self):
        pass

    def compose(self):
        return [self.at("/tmp/a.c", 42, "len=8")]
"""
        logger = type("L", (), {"info": lambda *a, **k: None, "debug": lambda *a, **k: None, "error": lambda *a, **k: None})()
        orchestrator = MutationOrchestrator(debugger=None, logger=logger)

        candidates, error = orchestrator.run_agent_script(
            {"file": "/tmp/a.c", "line": 40, "variable_names": ["len"]},
            script,
        )

        self.assertIsNone(error)
        self.assertEqual(candidates, {'LOGIC:AT(/tmp/a.c:42) THEN len=8'})


if __name__ == "__main__":
    unittest.main()
