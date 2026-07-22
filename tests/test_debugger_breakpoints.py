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

from agent import debug_agent  # noqa: E402
from tools.debugger import functions as debugger_functions  # noqa: E402


class DebuggerBreakpointLifecycleTests(unittest.TestCase):
    def test_debugger_run_to_line_clears_stale_breakpoints_before_setting_new_one(self):
        call_order = []

        def _record(name):
            def inner(*args, **kwargs):
                call_order.append(name)
                if name == "run":
                    return {"reason": "breakpoint-hit"}, ""
                if name == "set":
                    return ["Breakpoint set"]
                return None
            return inner

        with patch.object(debugger_functions, "debugger_clear_breakpoints", side_effect=_record("clear")), \
             patch.object(debugger_functions, "debugger_set_breakpoint", side_effect=_record("set")), \
             patch.object(debugger_functions, "debugger_run", side_effect=_record("run")), \
             patch.object(debugger_functions, "debugger_record_last_position", side_effect=_record("record")):
            out, target = debugger_functions.debugger_run_to_line("/tmp/demo.c", 42)

        self.assertEqual(out["reason"], "breakpoint-hit")
        self.assertEqual(target, "")
        self.assertEqual(call_order, ["clear", "set", "run", "record"])

    def test_reproduce_resets_breakpoints_before_rearming_profile(self):
        session = debug_agent.DebugSession.__new__(debug_agent.DebugSession)
        session.logger = None
        profile = debug_agent.DebugProfile("/tmp/demo.c", 42, 2)
        call_order = []

        def _record(name):
            def inner(*args, **kwargs):
                call_order.append(name)
                if name in {"run", "continue"}:
                    return {"reason": "breakpoint-hit"}, ""
                if name == "set":
                    return ["Breakpoint set"]
                return None
            return inner

        with patch.object(debug_agent, "debugger_clear_breakpoints", side_effect=_record("clear")), \
             patch.object(debug_agent, "debugger_set_breakpoint", side_effect=_record("set")), \
             patch.object(debug_agent, "debugger_run", side_effect=_record("run")), \
             patch.object(debug_agent, "debugger_continue", side_effect=_record("continue")), \
             patch.object(debug_agent, "debugger_record_last_position", side_effect=_record("record")):
            session._reproduce(profile)

        self.assertEqual(call_order, ["clear", "set", "run", "continue", "record"])

    def test_run_falls_back_to_reproduce_crash_frame_when_profile_replay_misses_breakpoint(self):
        session = debug_agent.DebugSession.__new__(debug_agent.DebugSession)
        session.logger = None
        session._input = debug_agent.DebugInput(
            profile={"root_cause_output": "/tmp/root-cause.json", "use_constraint": True},
            error="AddressSanitizer: heap-buffer-overflow",
            func="crash_func",
            file="/tmp/crash.c",
            line=134,
        )
        session._profile = debug_agent.DebugProfile("/tmp/selected.c", 20, 1, is_fallback=False)
        session._use_constraint = True
        session._use_crash_line_mode = False
        analyzed_frames = []

        def _analyze(frame):
            analyzed_frames.append(frame)
            return {"file": frame[2], "line": frame[3], "function_name": frame[1]}

        with patch.object(session, "_reproduce", side_effect=RuntimeError("exited-normally")), \
             patch.object(session, "_analyze_frame", side_effect=_analyze), \
             patch.object(debug_agent, "dump_json"):
            output = session.run()

        self.assertTrue(session._profile.is_fallback)
        self.assertTrue(session._use_crash_line_mode)
        self.assertEqual(analyzed_frames, [(0, "crash_func", "/tmp/crash.c", 134)])
        self.assertEqual(output.analysis[0]["function_name"], "crash_func")


if __name__ == "__main__":
    unittest.main()
