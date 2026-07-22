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
fuzzer_base = types.SimpleNamespace(MutatorBase=type("MutatorBase", (), {"__init__": lambda self, logger=None: None}))
sys.modules.setdefault("fuzzer", types.SimpleNamespace())
sys.modules.setdefault("fuzzer.mutators", types.SimpleNamespace())
sys.modules.setdefault("fuzzer.mutators.base", fuzzer_base)
sys.modules.setdefault("blocks", types.SimpleNamespace(memory=types.SimpleNamespace(get_addr=lambda *a, **k: None), integer=types.SimpleNamespace()))

from tools.debugger import functions as debugger_functions  # noqa: E402
from tools.debugger import server as debugger_server  # noqa: E402
from tools.debugger import controller as debugger_controller  # noqa: E402
from tools.fuzzer.engine import InDebuggerFuzzer  # noqa: E402


class _FakeDebugger:
    def __init__(self):
        self.print_calls = []
        self.assign_expression_calls = []
        self._cost_stats = {"eval_requests": 0}

    def print(self, expression):
        self.print_calls.append(expression)
        self._cost_stats["eval_requests"] += 1
        return f"value:{expression}"

    def assign_expression(self, expression):
        self.assign_expression_calls.append(expression)
        return True, "ok"

    def get_cost_stats(self):
        return dict(self._cost_stats)

    def reset_cost_stats(self):
        self._cost_stats = {"eval_requests": 0}


class DebuggerCostControlTests(unittest.TestCase):
    def test_debugger_print_uses_epoch_cache_until_state_changes(self):
        fake = _FakeDebugger()
        with patch.object(debugger_functions, "debugger_instance", return_value=fake):
            debugger_functions.debugger_reset_cost_stats()
            first = debugger_functions.debugger_print("x")
            second = debugger_functions.debugger_print("x")
            debugger_functions.debugger_assign_expression("x = 1")
            third = debugger_functions.debugger_print("x")
            stats = debugger_functions.debugger_get_cost_stats()

        self.assertEqual(first, "value:x")
        self.assertEqual(second, "value:x")
        self.assertEqual(third, "value:x")
        self.assertEqual(fake.print_calls, ["x", "x"])
        self.assertEqual(stats["print_cache_hits"], 1)
        self.assertEqual(stats["print_cache_misses"], 2)
        self.assertGreaterEqual(stats["cache_invalidations"], 1)

    def test_debugger_print_respawns_immediately_after_timeout(self):
        fake = _FakeDebugger()
        fake.print = lambda expression: "Error: Timeout (LLDB eval)"
        with patch.object(debugger_functions, "debugger_instance", return_value=fake), \
             patch.object(debugger_functions, "debugger_respawn_if_unhealthy") as respawn, \
             patch.object(debugger_functions, "debugger_restore_last_position", return_value=False):
            debugger_functions.debugger_reset_cost_stats()
            result = debugger_functions.debugger_print("x")

        self.assertIn("Debugger was reset immediately after the timeout", result)
        respawn.assert_called_once()

    def test_kill_waits_for_its_housekeeping_response(self):
        class _FakeController:
            def __init__(self):
                self.calls = []
                self._process = SimpleNamespace(stdout=object())

            def execute(self, command):
                self.calls.append(command)

        fake = debugger_server.LldbServer.__new__(debugger_server.LldbServer)
        fake._controller = _FakeController()
        fake._stream_desynced = False
        fake.logger = SimpleNamespace(debug=lambda *a, **k: None, warning=lambda *a, **k: None)
        fake._get_output_best_effort = lambda timeout=0.0: ("^", "done", "")

        with patch.object(debugger_server, "sleep", return_value=None), \
             patch.object(fake, "_stdout_has_pending_output", return_value=False):
            fake.kill()

        self.assertFalse(fake._stream_desynced)
        self.assertEqual(fake._controller.calls, ["process kill"])

    def test_kill_uses_ignore_to_drain_process_not_launched_noise(self):
        fake = debugger_server.LldbServer.__new__(debugger_server.LldbServer)
        fake._stream_desynced = False
        fake.logger = SimpleNamespace(debug=lambda *a, **k: None, warning=lambda *a, **k: None)

        execute_calls = []
        fake._execute = lambda command, ignore=False: execute_calls.append((command, ignore))
        fake._stdout_has_pending_output = lambda timeout=0.0: False

        with patch.object(debugger_server, "sleep", return_value=None):
            fake.kill()

        self.assertEqual(execute_calls[0], ("process kill", True))

    def test_execute_ignore_waits_for_delayed_result_record(self):
        class _FakeController:
            def __init__(self):
                self.calls = []
                self._process = SimpleNamespace(stdout=object())

            def execute(self, command):
                self.calls.append(command)

        fake = debugger_server.LldbServer.__new__(debugger_server.LldbServer)
        fake._controller = _FakeController()
        fake._stream_desynced = False
        fake.logger = SimpleNamespace(debug=lambda *a, **k: None, warning=lambda *a, **k: None)
        reads = []

        def _delayed_result(timeout=0.0):
            reads.append(timeout)
            return ("^", "done", "")

        fake._get_output_best_effort = _delayed_result

        with patch.object(fake, "_stdout_has_pending_output", return_value=False):
            fake._execute("target create /tmp/bin", ignore=True)

        self.assertEqual(fake._controller.calls, ["target create /tmp/bin"])
        self.assertEqual(len(reads), 1)
        self.assertGreater(reads[0], 0)
        self.assertFalse(fake._stream_desynced)

    def test_execute_ignore_does_not_fail_after_many_async_records(self):
        class _FakeController:
            def __init__(self):
                self.calls = []

            def execute(self, command):
                self.calls.append(command)

        fake = debugger_server.LldbServer.__new__(debugger_server.LldbServer)
        fake._controller = _FakeController()
        fake._stream_desynced = False
        fake.logger = SimpleNamespace(debug=lambda *a, **k: None, warning=lambda *a, **k: None)
        responses = iter([("=", "library-unloaded", "")] * 300 + [("^", "done", "")])
        fake._get_output_best_effort = lambda timeout=0.0: next(responses)

        fake._execute("process kill", ignore=True)

        self.assertEqual(fake._controller.calls, ["process kill"])
        self.assertFalse(fake._stream_desynced)

    def test_execute_ignore_marks_stream_desynced_when_result_never_arrives(self):
        class _FakeController:
            def __init__(self):
                self.calls = []

            def execute(self, command):
                self.calls.append(command)

        fake = debugger_server.LldbServer.__new__(debugger_server.LldbServer)
        fake._controller = _FakeController()
        fake._stream_desynced = False
        fake.logger = SimpleNamespace(debug=lambda *a, **k: None, warning=lambda *a, **k: None)
        fake._get_output_best_effort = lambda timeout=0.0: (_ for _ in ()).throw(TimeoutError())

        with self.assertRaisesRegex(TimeoutError, "housekeeping command response"):
            fake._execute("breakpoint delete -f", ignore=True)

        self.assertTrue(fake._stream_desynced)

    def test_self_healing_retries_once_after_housekeeping_desync(self):
        calls = []

        @debugger_functions.self_healing
        def operation():
            calls.append("call")
            if len(calls) == 1:
                raise debugger_controller.DebuggerStreamDesyncedError("housekeeping command response")
            return "recovered"

        with patch.object(debugger_functions, "debugger_respawn_if_unhealthy") as respawn:
            result = operation()

        self.assertEqual(result, "recovered")
        self.assertEqual(calls, ["call", "call"])
        respawn.assert_called_once()


class DebuggerControllerStreamTests(unittest.TestCase):
    def test_lldb_stdout_is_unbuffered_for_select_based_reads(self):
        process = SimpleNamespace(poll=lambda: None)

        with patch.object(debugger_controller.subprocess, "Popen", return_value=process) as popen:
            debugger_controller.LldbController("lldb-mi", "/tmp", {})

        self.assertEqual(popen.call_args.kwargs["bufsize"], 0)


class FuzzerCostControlTests(unittest.TestCase):
    def setUp(self):
        self.engine = InDebuggerFuzzer(debugger=None, llm_agent=None)
        self.suspect = {
            "file": "/tmp/f.c",
            "line": 10,
            "variable_names": ["len"],
            "focus_targets": ["len"],
            "suspect_expressions": ["len", "other"],
            "demonic_seed_values": {"len": 9},
            "bug_type_profile": {"bug_type": "out_of_bounds"},
            "llm_inferred_type": "int",
        }
        self.engine._init_cost_stats(self.suspect)
        self.engine._init_harness_policy(self.suspect)

    def test_candidate_budget_exhaustion_is_reported(self):
        tuned = {**self.suspect, "fuzz_candidate_budget": 1}
        self.engine._init_cost_stats(tuned)
        self.engine._init_harness_policy(tuned)
        def _record_angelic(value, angelic_values, demonic_values):
            angelic_values.append(value)
            return "angelic", "stop: exited-normally"

        with patch.object(self.engine, "_determine_ignore_count", return_value=0), \
             patch("tools.fuzzer.engine.debugger_clear_breakpoints"), \
             patch("tools.fuzzer.engine.debugger_run_to_line", return_value=({"reason": "breakpoint-hit"}, "")), \
             patch("tools.fuzzer.engine.debugger_print", return_value="7"), \
             patch("tools.fuzzer.engine.debugger_backtrace", return_value=["f0"]), \
             patch("tools.fuzzer.engine.debugger_get_cost_stats", return_value={}), \
             patch.object(self.engine, "_apply_mutation", return_value=True), \
             patch.object(self.engine, "_analyze_mutation_result", side_effect=_record_angelic):
            angelic, demonic = self.engine._run_mutation_loop(
                [1, 2, 3],
                tuned,
                profile={},
            )

        self.assertEqual(angelic, [1])
        self.assertEqual(demonic, [9])
        self.assertTrue(self.engine._cost_stats["budget_exhausted"])
        self.assertEqual(self.engine._cost_stats["exhausted_budget"], "candidate_budget")
        self.assertEqual(self.engine._cost_stats["candidate_stats"]["tested"], 1)

    def test_snapshot_expression_budget_marks_remaining_values_unavailable(self):
        tuned = {**self.suspect, "fuzz_snapshot_expression_budget": 1}
        self.engine._init_cost_stats(tuned)
        self.engine._init_harness_policy(tuned)
        with patch("tools.fuzzer.engine.debugger_print", return_value="7"), \
             patch("tools.fuzzer.engine.debugger_backtrace", return_value=["f0"]), \
             patch("tools.fuzzer.engine.debugger_get_cost_stats", return_value={}):
            snapshot = self.engine._capture_state_snapshot(tuned)

        self.assertEqual(snapshot["variables"]["len"], "7")
        self.assertIn("budget exhausted", snapshot["expressions"]["other"])
        self.assertTrue(self.engine._cost_stats["budget_exhausted"])
        self.assertEqual(self.engine._cost_stats["exhausted_budget"], "snapshot_expression_budget")

    def test_bug_type_pruning_skips_target_mismatches(self):
        candidates = [{"ptr": "NULL"}, {"len": "1"}, "other = 0", "offset = 0"]
        pruned = self.engine._prune_candidates_for_bug_type(candidates, self.suspect)

        self.assertEqual(pruned, [{"len": "1"}, "offset = 0"])
        self.assertEqual(self.engine._cost_stats["candidate_stats"]["pruned_skips"], 2)
        self.assertEqual(self.engine._cost_stats["pruning_reasons"]["target_mismatch"], 2)

    def test_harness_retries_prepare_after_respawn(self):
        def _record_angelic(value, angelic_values, demonic_values):
            angelic_values.append(value)
            return "angelic", "stop: exited-normally"

        with patch.object(self.engine, "_determine_ignore_count", return_value=0), \
             patch("tools.fuzzer.engine.debugger_clear_breakpoints"), \
             patch("tools.fuzzer.engine.debugger_run_to_line", side_effect=[
                 ({"reason": "signal-received"}, ""),
                 ({"reason": "breakpoint-hit"}, ""),
             ]), \
             patch("tools.fuzzer.engine.debugger_print", return_value="7"), \
             patch("tools.fuzzer.engine.debugger_backtrace", return_value=["f0"]), \
             patch("tools.fuzzer.engine.debugger_get_cost_stats", return_value={}), \
             patch("tools.debugger.driver.debugger_respawn") as respawn, \
             patch.object(self.engine, "_apply_mutation", return_value=True), \
             patch.object(self.engine, "_analyze_mutation_result", side_effect=_record_angelic):
            angelic, _ = self.engine._run_mutation_loop([1], self.suspect, profile={})

        self.assertEqual(angelic, [1])
        self.assertEqual(respawn.call_count, 1)
        self.assertEqual(self.engine._cost_stats["debugger_stats"]["prepare_failures"], 1)
        self.assertEqual(self.engine._cost_stats["debugger_stats"]["respawns"], 1)

    def test_harness_reduced_mode_stretches_respawn_interval(self):
        tuned = {
            **self.suspect,
            "fuzz_force_respawn_every_n_candidates": 1,
            "fuzz_harness_cache_miss_soft_limit": 1,
        }
        self.engine._init_cost_stats(tuned)
        self.engine._init_harness_policy(tuned)

        def _record_angelic(value, angelic_values, demonic_values):
            angelic_values.append(value)
            return "angelic", "stop: exited-normally"

        with patch.object(self.engine, "_determine_ignore_count", return_value=0), \
             patch("tools.fuzzer.engine.debugger_clear_breakpoints"), \
             patch("tools.fuzzer.engine.debugger_run_to_line", return_value=({"reason": "breakpoint-hit"}, "")), \
             patch("tools.fuzzer.engine.debugger_print", return_value="7"), \
             patch("tools.fuzzer.engine.debugger_backtrace", return_value=["f0"]), \
             patch("tools.fuzzer.engine.debugger_get_cost_stats", return_value={"print_cache_misses": 1}), \
             patch("tools.debugger.driver.debugger_respawn") as respawn, \
             patch.object(self.engine, "_apply_mutation", return_value=True), \
             patch.object(self.engine, "_analyze_mutation_result", side_effect=_record_angelic):
            angelic, _ = self.engine._run_mutation_loop([1, 2, 3], tuned, profile={})

        self.assertEqual(angelic, [1, 2, 3])
        self.assertEqual(respawn.call_count, 1)
        self.assertEqual(self.engine._cost_stats["harness_policy"]["mode"], "reduced")

    def test_synthesized_planner_stops_immediately_on_connection_error(self):
        fake_planner = SimpleNamespace(
            initiate=lambda *a, **k: {
                "history": [],
                "cost": "N/A",
                "error": "Connection error.",
            },
            step=lambda *a, **k: {
                "history": [],
                "cost": "N/A",
                "error": "Connection error.",
            },
        )

        with patch("tools.fuzzer.engine.GenericAgent", return_value=fake_planner):
            angelic, demonic = self.engine._run_synthesized_fuzzing(self.suspect, profile={})

        self.assertEqual(angelic, [])
        self.assertEqual(demonic, [])

    def test_harness_minimal_mode_skips_backtrace(self):
        tuned = {
            **self.suspect,
            "fuzz_harness_eval_timeout_soft_limit": 1,
        }
        self.engine._init_cost_stats(tuned)
        self.engine._init_harness_policy(tuned)
        with patch("tools.fuzzer.engine.debugger_print", return_value="7"), \
             patch("tools.fuzzer.engine.debugger_backtrace") as backtrace, \
             patch("tools.fuzzer.engine.debugger_get_cost_stats", return_value={"lldb": {"eval_timeouts": 1}}):
            snapshot = self.engine._capture_state_snapshot(tuned)

        self.assertEqual(snapshot["backtrace"], [])
        self.assertEqual(self.engine._cost_stats["harness_policy"]["mode"], "minimal")
        backtrace.assert_not_called()

    def test_harness_reduced_snapshot_window_limits_expression_evals(self):
        tuned = {
            **self.suspect,
            "fuzz_snapshot_expression_budget": 8,
            "fuzz_harness_cache_miss_soft_limit": 1,
            "fuzz_harness_reduced_snapshot_eval_window": 1,
        }
        self.engine._init_cost_stats(tuned)
        self.engine._init_harness_policy(tuned)
        with patch("tools.fuzzer.engine.debugger_print", return_value="7"), \
             patch("tools.fuzzer.engine.debugger_backtrace", return_value=["f0"]), \
             patch("tools.fuzzer.engine.debugger_get_cost_stats", return_value={"print_cache_misses": 1}):
            snapshot = self.engine._capture_state_snapshot(tuned)

        self.assertEqual(snapshot["variables"]["len"], "7")
        self.assertIn("budget exhausted", snapshot["expressions"]["other"])
        self.assertEqual(self.engine._cost_stats["harness_policy"]["mode"], "reduced")


if __name__ == "__main__":
    unittest.main()
