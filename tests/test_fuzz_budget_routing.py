import pathlib
import sys
import types
import unittest


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
from agent.contracts import HypothesisRecord  # noqa: E402
from agent.state import BugHypothesisState  # noqa: E402


class FuzzBudgetRoutingTests(unittest.TestCase):
    def test_budget_exhaustion_routes_back_to_debug_and_exhausts_hypothesis(self):
        state = BugHypothesisState(
            profile={"id": "p"},
            suspects=[{"hypothesis_id": "hyp-1", "file": "a.c", "line": 10}],
            hypothesis_pool=[
                HypothesisRecord(id="hyp-1", summary="candidate", score=0.9, status="active"),
                HypothesisRecord(id="hyp-2", summary="backup", score=0.5, status="active"),
            ],
            active_hypothesis_id="hyp-1",
        )

        message = adapters.hydrate_fuzz_state(
            state,
            {
                "hypothesis_id": "hyp-1",
                "angelic_values": [],
                "demonic_values": [1],
                "cost_stats": {
                    "budget_exhausted": True,
                    "exhausted_budget": "candidate_budget",
                },
            },
        )

        self.assertEqual(message.recommended_next_actor, "debug")
        self.assertIn("runtime budget", message.claims[0])
        self.assertEqual(message.artifacts["round_metrics"]["costs"]["exhausted_budget"], "candidate_budget")
        self.assertEqual(state.hypothesis_pool[0].status, "exhausted")
        self.assertEqual(state.hypothesis_pool[0].failures[-1]["type"], "fuzz_budget_exhausted")

    def test_non_budget_failure_does_not_exhaust_hypothesis(self):
        state = BugHypothesisState(
            profile={"id": "p"},
            suspects=[
                {"hypothesis_id": "hyp-1", "file": "a.c", "line": 10},
                {"hypothesis_id": "hyp-2", "file": "b.c", "line": 20},
            ],
            hypothesis_pool=[
                HypothesisRecord(id="hyp-1", summary="candidate", score=0.9, status="active"),
                HypothesisRecord(id="hyp-2", summary="backup", score=0.5, status="active"),
            ],
            active_hypothesis_id="hyp-1",
        )

        message = adapters.hydrate_fuzz_state(
            state,
            {
                "hypothesis_id": "hyp-1",
                "angelic_values": [],
                "demonic_values": [1],
                "cost_stats": {
                    "budget_exhausted": False,
                },
            },
        )

        self.assertEqual(message.recommended_next_actor, "fuzz")
        self.assertEqual(state.hypothesis_pool[0].status, "active")
        self.assertEqual(state.hypothesis_pool[0].failures[-1]["type"], "no_angelic_values")


if __name__ == "__main__":
    unittest.main()
