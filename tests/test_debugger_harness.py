import pathlib
import sys
import types
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "stalker"))
sys.modules.setdefault("coloredlogs", types.SimpleNamespace(install=lambda *a, **k: None))

from tools.debugger.experiment_runner import DebuggerIntervention, ExperimentPlan  # noqa: E402
from tools.debugger.harness import DebuggerHarness  # noqa: E402
from tools.debugger.runtime_policy import DebuggerRuntimePolicy  # noqa: E402
from tools.debugger.session import BreakpointTarget, DebuggerSession  # noqa: E402
from tools.debugger.snapshotter import DebuggerSnapshotter, SnapshotRequest  # noqa: E402


class _FakeBackend:
    def __init__(self):
        self.print_calls = []
        self.assign_calls = []
        self.executed = []
        self.runtime = {
            "print_cache_misses": 0,
            "lldb": {"eval_timeouts": 0, "total_eval_seconds": 0.0, "slow_evals": 0},
        }

    def run(self):
        return {"reason": "done"}, ""

    def continue_run(self):
        return {"reason": "exited-normally"}, "ok"

    def run_to_line(self, file, start_line, end_line=None, ignore_count=None, condition=None):
        self.executed.append(("run_to_line", file, start_line, end_line, ignore_count, condition))
        return {"reason": "breakpoint-hit", "frame": {"file": file, "line": str(start_line)}}, ""

    def run_to_last_hit(self, file, line):
        self.executed.append(("run_to_last_hit", file, line))
        return {"reason": "breakpoint-hit", "frame": {"file": file, "line": str(line)}}, ""

    def clear_breakpoints(self):
        self.executed.append(("clear_breakpoints",))

    def set_breakpoint(self, file, start_line, end_line=None, ignore_count=None, condition=None):
        self.executed.append(("set_breakpoint", file, start_line, end_line, ignore_count, condition))
        return ["ok"]

    def get_breakpoint_hit_count(self, breakpoint_id):
        return 0

    def print_value(self, expression):
        self.print_calls.append(expression)
        if expression == "slow_expr":
            self.runtime["lldb"]["slow_evals"] = 1
        return f"value:{expression}"

    def get_type(self, expression):
        return "int"

    def assign(self, variable, value):
        self.assign_calls.append(("assign", variable, value))
        return True, f"{variable}={value}"

    def assign_expression(self, expression):
        self.assign_calls.append(("assign_expression", expression))
        return True, expression

    def add_functional_guard(self, file, line, condition, return_value):
        self.assign_calls.append(("functional_guard", file, line, condition, return_value))
        return True, "guard"

    def execute(self, command):
        self.executed.append(("execute", command))
        return "done"

    def backtrace(self):
        return ["frame0", "frame1", "frame2"]

    def reset_cost_stats(self):
        self.runtime = {
            "print_cache_misses": 0,
            "lldb": {"eval_timeouts": 0, "total_eval_seconds": 0.0, "slow_evals": 0},
        }

    def get_cost_stats(self):
        return dict(self.runtime)


class RuntimePolicyTests(unittest.TestCase):
    def test_policy_downgrades_on_timeouts(self):
        policy = DebuggerRuntimePolicy({})
        state = policy.observe_runtime({"lldb": {"eval_timeouts": 3, "total_eval_seconds": 0.0, "slow_evals": 0}})

        self.assertEqual(state.mode, "minimal")
        self.assertTrue(state.actions["disable_preemptive_respawn"])
        self.assertFalse(policy.should_capture_backtrace())


class SessionAndSnapshotterTests(unittest.TestCase):
    def test_snapshotter_applies_budget_and_backtrace_limit(self):
        backend = _FakeBackend()
        session = DebuggerSession(backend=backend)
        snapshotter = DebuggerSnapshotter(session)
        policy = DebuggerRuntimePolicy({})
        policy.observe_runtime({"print_cache_misses": 0, "lldb": {"eval_timeouts": 3, "total_eval_seconds": 0.0, "slow_evals": 0}})

        snapshot = snapshotter.capture(
            SnapshotRequest(
                variables=["x"],
                expressions=["e1", "e2", "e3"],
                expression_budget=10,
                include_backtrace=True,
                backtrace_limit=1,
            ),
            policy=policy,
        )

        self.assertEqual(snapshot.variables["x"], "value:x")
        self.assertEqual(snapshot.expressions["e1"], "value:e1")
        self.assertIn("budget exhausted", snapshot.expressions["e3"])
        self.assertEqual(snapshot.backtrace, [])
        self.assertEqual(snapshot.metrics["expression_budget"], 2)

    def test_session_tracks_last_target(self):
        backend = _FakeBackend()
        session = DebuggerSession(backend=backend)
        result = session.prepare(BreakpointTarget(file="a.c", line=12))

        self.assertTrue(result.reached)
        self.assertEqual(session.last_target.file, "a.c")
        self.assertEqual(session.export_metrics()["prepare_calls"], 1)


class HarnessFacadeTests(unittest.TestCase):
    def test_harness_runs_experiment_and_exports_metrics(self):
        backend = _FakeBackend()
        harness = DebuggerHarness(backend=backend)
        plan = ExperimentPlan(
            target=BreakpointTarget(file="main.c", line=9),
            before_snapshot=SnapshotRequest(variables=["x"], expressions=["slow_expr"], include_backtrace=True, backtrace_limit=2),
            interventions=[DebuggerIntervention(kind="assign_expression", payload={"expression": "x = 1"})],
            after_snapshot=SnapshotRequest(variables=["x"]),
            continue_after=True,
        )

        result = harness.run_experiment(plan)
        state = harness.export_state()

        self.assertTrue(result.preparation.reached)
        self.assertEqual(result.interventions[0].kind, "assign_expression")
        self.assertEqual(result.before_snapshot.backtrace[:2], ["frame0", "frame1"])
        self.assertEqual(result.metrics["harness"]["interventions"], 1)
        self.assertEqual(result.metrics["session"]["continue_calls"], 1)
        self.assertIn(state["health"]["status"], {"healthy", "warning"})


if __name__ == "__main__":
    unittest.main()
