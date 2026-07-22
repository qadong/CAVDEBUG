from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from tools.debugger import functions as debugger_functions


class DebuggerBackend(Protocol):
    def run(self) -> tuple[dict, str]: ...
    def continue_run(self) -> tuple[dict, str]: ...
    def run_to_line(
        self,
        file: str,
        start_line: int,
        end_line: int | None = None,
        ignore_count: int | None = None,
        condition: str | None = None,
    ) -> tuple[dict, str]: ...
    def run_to_last_hit(self, file: str, line: int) -> tuple[dict, str]: ...
    def clear_breakpoints(self) -> Any: ...
    def set_breakpoint(
        self,
        file: str,
        start_line: int,
        end_line: int | None = None,
        ignore_count: int | None = None,
        condition: str | None = None,
    ) -> list[str]: ...
    def get_breakpoint_hit_count(self, breakpoint_id: int) -> int: ...
    def print_value(self, expression: str) -> str: ...
    def get_type(self, expression: str) -> str: ...
    def assign(self, variable: str, value: str) -> tuple[bool, str]: ...
    def assign_expression(self, expression: str) -> tuple[bool, str]: ...
    def add_functional_guard(self, file: str, line: int, condition: str, return_value: str) -> tuple[bool, str]: ...
    def execute(self, command: str) -> str: ...
    def backtrace(self) -> list[str]: ...
    def reset_cost_stats(self) -> None: ...
    def get_cost_stats(self) -> dict[str, Any]: ...


class _FunctionsDebuggerBackend:
    def run(self) -> tuple[dict, str]:
        return debugger_functions.debugger_run()

    def continue_run(self) -> tuple[dict, str]:
        return debugger_functions.debugger_continue()

    def run_to_line(
        self,
        file: str,
        start_line: int,
        end_line: int | None = None,
        ignore_count: int | None = None,
        condition: str | None = None,
    ) -> tuple[dict, str]:
        return debugger_functions.debugger_run_to_line(
            file, start_line, end_line=end_line, ignore_count=ignore_count, condition=condition
        )

    def run_to_last_hit(self, file: str, line: int) -> tuple[dict, str]:
        return debugger_functions.debugger_run_to_last_hit(file, line)

    def clear_breakpoints(self) -> Any:
        return debugger_functions.debugger_clear_breakpoints()

    def set_breakpoint(
        self,
        file: str,
        start_line: int,
        end_line: int | None = None,
        ignore_count: int | None = None,
        condition: str | None = None,
    ) -> list[str]:
        return debugger_functions.debugger_set_breakpoint(
            file, start_line, end_line=end_line, ignore_count=ignore_count, condition=condition
        )

    def get_breakpoint_hit_count(self, breakpoint_id: int) -> int:
        return debugger_functions.debugger_get_breakpoint_hit_count(breakpoint_id)

    def print_value(self, expression: str) -> str:
        return debugger_functions.debugger_print(expression)

    def get_type(self, expression: str) -> str:
        return debugger_functions.debugger_get_type(expression)

    def assign(self, variable: str, value: str) -> tuple[bool, str]:
        return debugger_functions.debugger_assign(variable, value)

    def assign_expression(self, expression: str) -> tuple[bool, str]:
        return debugger_functions.debugger_assign_expression(expression)

    def add_functional_guard(self, file: str, line: int, condition: str, return_value: str) -> tuple[bool, str]:
        return debugger_functions.debugger_add_functional_guard(file, line, condition, return_value)

    def execute(self, command: str) -> str:
        return debugger_functions.debugger_execute(command)

    def backtrace(self) -> list[str]:
        return debugger_functions.debugger_backtrace()

    def reset_cost_stats(self) -> None:
        debugger_functions.debugger_reset_cost_stats()

    def get_cost_stats(self) -> dict[str, Any]:
        return debugger_functions.debugger_get_cost_stats()


@dataclass(frozen=True)
class BreakpointTarget:
    file: str
    line: int
    end_line: int | None = None
    ignore_count: int | None = None
    condition: str | None = None
    last_hit: bool = False


@dataclass(frozen=True)
class NavigationResult:
    target: BreakpointTarget
    lldb_output: dict[str, Any]
    target_output: str

    @property
    def reached(self) -> bool:
        return self.lldb_output.get("reason") == "breakpoint-hit"


@dataclass(frozen=True)
class AssignmentResult:
    success: bool
    message: str
    kind: str


class DebuggerSession:
    """Shared debugger session facade over the existing debugger primitives."""

    def __init__(self, backend: DebuggerBackend | None = None) -> None:
        self._backend = backend or _FunctionsDebuggerBackend()
        self._last_target: BreakpointTarget | None = None
        self._metrics: dict[str, int] = {
            "prepare_calls": 0,
            "prepare_failures": 0,
            "continue_calls": 0,
            "run_calls": 0,
            "snapshot_calls": 0,
            "assignment_calls": 0,
            "assignment_failures": 0,
            "guard_calls": 0,
            "execute_calls": 0,
            "backtrace_calls": 0,
            "breakpoint_clears": 0,
        }

    @property
    def last_target(self) -> BreakpointTarget | None:
        return self._last_target

    def reset_metrics(self) -> None:
        for key in list(self._metrics.keys()):
            self._metrics[key] = 0

    def export_metrics(self) -> dict[str, int]:
        return dict(self._metrics)

    def record_snapshot(self) -> None:
        self._metrics["snapshot_calls"] += 1

    def reset_runtime_metrics(self) -> None:
        self._backend.reset_cost_stats()

    def get_runtime_metrics(self) -> dict[str, Any]:
        return self._backend.get_cost_stats()

    def run(self) -> tuple[dict, str]:
        self._metrics["run_calls"] += 1
        return self._backend.run()

    def continue_run(self) -> tuple[dict, str]:
        self._metrics["continue_calls"] += 1
        return self._backend.continue_run()

    def clear_breakpoints(self) -> Any:
        self._metrics["breakpoint_clears"] += 1
        return self._backend.clear_breakpoints()

    def set_breakpoint(
        self,
        file: str,
        line: int,
        end_line: int | None = None,
        ignore_count: int | None = None,
        condition: str | None = None,
    ) -> list[str]:
        return self._backend.set_breakpoint(file, line, end_line=end_line, ignore_count=ignore_count, condition=condition)

    def get_breakpoint_hit_count(self, breakpoint_id: int) -> int:
        return self._backend.get_breakpoint_hit_count(breakpoint_id)

    def prepare(self, target: BreakpointTarget) -> NavigationResult:
        self._metrics["prepare_calls"] += 1
        try:
            if target.last_hit:
                lldb_output, target_output = self._backend.run_to_last_hit(target.file, target.line)
            else:
                lldb_output, target_output = self._backend.run_to_line(
                    target.file,
                    target.line,
                    end_line=target.end_line,
                    ignore_count=target.ignore_count,
                    condition=target.condition,
                )
        except Exception:
            self._metrics["prepare_failures"] += 1
            raise
        result = NavigationResult(target=target, lldb_output=lldb_output, target_output=target_output)
        if result.reached:
            self._last_target = target
        else:
            self._metrics["prepare_failures"] += 1
        return result

    def print_value(self, expression: str) -> str:
        return self._backend.print_value(expression)

    def get_type(self, expression: str) -> str:
        return self._backend.get_type(expression)

    def backtrace(self) -> list[str]:
        self._metrics["backtrace_calls"] += 1
        return self._backend.backtrace()

    def assign(self, variable: str, value: str) -> AssignmentResult:
        self._metrics["assignment_calls"] += 1
        success, message = self._backend.assign(variable, value)
        if not success:
            self._metrics["assignment_failures"] += 1
        return AssignmentResult(success=success, message=message, kind="assign")

    def assign_expression(self, expression: str) -> AssignmentResult:
        self._metrics["assignment_calls"] += 1
        success, message = self._backend.assign_expression(expression)
        if not success:
            self._metrics["assignment_failures"] += 1
        return AssignmentResult(success=success, message=message, kind="assign_expression")

    def add_functional_guard(self, file: str, line: int, condition: str, return_value: str) -> AssignmentResult:
        self._metrics["guard_calls"] += 1
        success, message = self._backend.add_functional_guard(file, line, condition, return_value)
        if not success:
            self._metrics["assignment_failures"] += 1
        return AssignmentResult(success=success, message=message, kind="functional_guard")

    def execute(self, command: str) -> str:
        self._metrics["execute_calls"] += 1
        return self._backend.execute(command)
