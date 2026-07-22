from typing import List, Tuple, Callable, Any
import functools
from tools.debugger.driver import debugger_backend_generation, debugger_instance, debugger_respawn, debugger_respawn_if_unhealthy
from tools.debugger.controller import DebuggerProcessExitedError, DebuggerStreamDesyncedError
from utils.logger import get_logger

# Consecutive print timeouts before auto-respawn (debugger likely stuck or target dead)
_PRINT_TIMEOUT_RESPAWN_THRESHOLD = 2
_consecutive_print_timeouts = 0

# Last successful run_to_line position for auto-restore after respawn
_last_run_to_line_file: str | None = None
_last_run_to_line_line: int | None = None
_breakpoint_registry: list[dict] = []
_debugger_replay_context: dict = {}
_debugger_state_epoch = 0
_print_cache: dict[tuple[int, str], str] = {}
_debugger_cost_stats = {
    "print_requests": 0,
    "print_cache_hits": 0,
    "print_cache_misses": 0,
    "cache_invalidations": 0,
    "state_epoch": 0,
}


def _bump_debugger_cost_stat(key: str, amount=1) -> None:
    _debugger_cost_stats[key] = _debugger_cost_stats.get(key, 0) + amount


def _invalidate_print_cache(reason: str = "") -> None:
    global _debugger_state_epoch
    if _print_cache:
        _print_cache.clear()
    _debugger_state_epoch += 1
    _debugger_cost_stats["state_epoch"] = _debugger_state_epoch
    _bump_debugger_cost_stat("cache_invalidations")
    if reason:
        get_logger("debugger").debug("Invalidated debugger print cache: %s", reason)


def _is_debugger_timeout_message(message: str) -> bool:
    text = str(message or "").lower()
    return "timeout" in text or "lldb_eval_timeout" in text


def debugger_reset_cost_stats() -> None:
    global _consecutive_print_timeouts
    _consecutive_print_timeouts = 0
    _print_cache.clear()
    for key in list(_debugger_cost_stats.keys()):
        _debugger_cost_stats[key] = 0
    _debugger_cost_stats["state_epoch"] = _debugger_state_epoch
    dbg = debugger_instance()
    if hasattr(dbg, "reset_cost_stats"):
        dbg.reset_cost_stats()


def debugger_get_cost_stats() -> dict:
    combined = dict(_debugger_cost_stats)
    combined["state_epoch"] = _debugger_state_epoch
    dbg = debugger_instance()
    if hasattr(dbg, "get_cost_stats"):
        combined["lldb"] = dbg.get_cost_stats()
    return combined


def debugger_record_last_position(file: str, line: int) -> None:
    """Record the last run_to_line position for auto-restore after respawn."""
    global _last_run_to_line_file, _last_run_to_line_line
    _last_run_to_line_file = file
    _last_run_to_line_line = line
    _debugger_replay_context["last_position"] = {"file": file, "line": line}


def _breakpoint_key(bp: dict) -> tuple:
    return (
        bp.get("file"),
        bp.get("line"),
        bp.get("ignore_count"),
        bp.get("condition"),
        bp.get("source"),
    )


def _register_breakpoint(
    file: str,
    line: int,
    breakpoint_id: int | None,
    message: str,
    ignore_count: int | None = None,
    condition: str | None = None,
    source: str = "breakpoint",
) -> None:
    if "Invalid breakpoint" in str(message) or "Error" in str(message):
        return

    bp = {
        "id": breakpoint_id,
        "file": file,
        "line": int(line),
        "ignore_count": ignore_count,
        "condition": condition,
        "source": source,
        "message": message,
        "verified": True,
    }
    key = _breakpoint_key(bp)
    for i, existing in enumerate(_breakpoint_registry):
        if _breakpoint_key(existing) == key:
            _breakpoint_registry[i] = bp
            return
    _breakpoint_registry.append(bp)


def debugger_list_breakpoints() -> dict:
    """
    Return debugger breakpoints tracked by the Python wrapper.
    This registry reflects breakpoints set through debugger functions, not
    arbitrary manual LLDB console breakpoints.
    """
    return {"breakpoints": [dict(bp) for bp in _breakpoint_registry]}


def debugger_restore_breakpoints(breakpoints: list[dict] | None = None) -> list[str]:
    """
    Best-effort restore of registered breakpoints into the current LLDB backend.
    Does not clear existing LLDB breakpoints.
    """
    snapshot = [dict(bp) for bp in (breakpoints if breakpoints is not None else _breakpoint_registry)]
    restored = []
    for bp in snapshot:
        result = debugger_set_breakpoint(
            bp["file"],
            int(bp["line"]),
            ignore_count=bp.get("ignore_count"),
            condition=bp.get("condition"),
        )
        restored.extend(result)
    return restored


def debugger_restore_last_position() -> bool:
    """
    After respawn, restore to the last run_to_line position.
    Returns True if restore was attempted and succeeded, False otherwise.
    """
    global _last_run_to_line_file, _last_run_to_line_line
    if _last_run_to_line_file is None or _last_run_to_line_line is None:
        return False
    breakpoint_snapshot = [dict(bp) for bp in _breakpoint_registry]
    try:
        dbg_output, _ = debugger_run_to_line(_last_run_to_line_file, _last_run_to_line_line)
        if dbg_output.get("reason") == "breakpoint-hit":
            debugger_restore_breakpoints(breakpoint_snapshot)
            get_logger("debugger").info(
                "Restored to last position %s:%s", _last_run_to_line_file, _last_run_to_line_line
            )
            return True
    except Exception as e:
        get_logger("debugger").warning("Failed to restore last position: %s", e)
    return False

def self_healing(func: Callable[..., Any]) -> Callable[..., Any]:
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except DebuggerStreamDesyncedError as e:
            logger = get_logger("debugger")
            logger.warning(f"检测到调试器 MI 输出流失步 ({e})，正在触发自愈重试...")
            debugger_respawn_if_unhealthy(str(e))
            try:
                return func(*args, **kwargs)
            except Exception as retry_e:
                logger.error(f"MI 输出流自愈重试失败: {retry_e}")
                raise retry_e
        except DebuggerProcessExitedError as e:
            logger = get_logger("debugger")
            logger.warning(f"检测到调试器异常退出 ({e})，正在触发自愈重试...")
            # debugger_instance() 在下次调用时会自动重启（因为 poll() 不为 None）
            # 我们只需要再次尝试执行即可
            try:
                # 第二次调用 debugger_instance() 会触发 driver.py 中的 get() 重启逻辑
                return func(*args, **kwargs)
            except Exception as retry_e:
                logger.error(f"自愈重试失败: {retry_e}")
                raise retry_e
    return wrapper

@self_healing
def debugger_run() -> Tuple[dict, str]:
    """
    [lldb output, target output]
    """
    _invalidate_print_cache("run")
    gdb = debugger_instance()
    gdb.kill()  # just kill the current process even if it is not running
    return gdb.run()


@self_healing
def debugger_continue() -> Tuple[dict, str]:
    """
    [lldb output, target output]
    """
    _invalidate_print_cache("continue")
    return debugger_instance().continue_run()


@self_healing
def debugger_backtrace() -> List[str]:
    backtrace_output = debugger_instance().backtrace()
    
    # Check if backtrace returned an error message
    if backtrace_output.startswith("Error:"):
        # Auto-recover: respawn and restore to last run_to_line position
        debugger_respawn_if_unhealthy(f"backtrace failed: {backtrace_output[:80]}")
        if debugger_restore_last_position():
            # Retry backtrace after restore
            backtrace_output = debugger_instance().backtrace()
            if not backtrace_output.startswith("Error:"):
                frames = []
                for line in backtrace_output.split("\n")[1:]:
                    frame = line.strip()
                    if frame == "":
                        continue
                    frames.append(frame[2:] if frame.startswith("* ") else frame)
                return frames
        return []
    
    frames = []
    for line in backtrace_output.split("\n")[1:]:
        frame = line.strip()
        if frame == "":
            continue
        if frame.startswith("* "):
            frames.append(frame[2:])
        else:
            frames.append(frame)
    return frames


@self_healing
def debugger_frame(frame: int) -> str:
    return debugger_instance().frame(frame)


@self_healing
def debugger_read_memory(address: str, size: int = 1, count: int = 16, fmt: str = "x") -> str:
    """
    Read target memory at a concrete address.
    """
    return debugger_instance().read_memory(address, size=size, count=count, fmt=fmt)


@self_healing
def debugger_set_breakpoint_with_ids(file, start_line, end_line=None, ignore_count=None, condition=None) -> list[tuple[str, int]]:
    """
    Set breakpoint from start_line to end_line and return (message, id) pairs.
    """
    response = []

    gdb = debugger_instance()
    result_msg, bkpt_id = gdb.set_breakpoint(file, start_line, ignore_count=ignore_count, condition=condition)
    _register_breakpoint(file, start_line, bkpt_id, result_msg, ignore_count=ignore_count, condition=condition)
    response.append((result_msg, bkpt_id))

    if end_line is not None:
        for i in range(start_line + 1, end_line + 1):
            result_msg, bkpt_id = gdb.set_breakpoint(file, i, ignore_count=ignore_count, condition=condition)
            _register_breakpoint(file, i, bkpt_id, result_msg, ignore_count=ignore_count, condition=condition)
            response.append((result_msg, bkpt_id))

    return response


@self_healing
def debugger_set_breakpoint(file, start_line, end_line=None, ignore_count=None, condition=None) -> List[str]:
    """
    Set breakpoint from start_line to end_line.
    
    Args:
        file: File path
        start_line: Starting line number
        end_line: Ending line number (optional)
        ignore_count: Number of times to ignore before stopping (optional)
        condition: C expression condition for the breakpoint (optional)
    
    Returns:
        List of result messages (for backward compatibility)
    """
    return [
        message
        for message, _ in debugger_set_breakpoint_with_ids(
            file,
            start_line,
            end_line=end_line,
            ignore_count=ignore_count,
            condition=condition,
        )
    ]


@self_healing
def debugger_get_breakpoint_hit_count(breakpoint_id: int) -> int:
    """
    Get the hit count (times) for a specific breakpoint.
    
    Args:
        breakpoint_id: The breakpoint ID (number)
    
    Returns:
        Hit count (times) of the breakpoint, or 0 if not found or never hit
    """
    return debugger_instance().get_breakpoint_hit_count(breakpoint_id)


def debugger_get_tracked_breakpoint_hit_count(breakpoint_id) -> int | None:
    try:
        breakpoint_id = int(breakpoint_id)
    except (TypeError, ValueError):
        return None
    if breakpoint_id < 0:
        return None
    return debugger_get_breakpoint_hit_count(breakpoint_id)


@self_healing
def debugger_run_to_last_hit(file: str, line: int) -> Tuple[dict, str]:
    """
    Phase 1: Count breakpoint hits by running until crash.
    Phase 2: Set breakpoint with ignore count to stop at the last hit.
    
    This implements the "统计次数 -> 定位最后一次" logic using pure MI commands.
    
    Args:
        file: File path
        line: Line number
    
    Returns:
        (lldb_output, target_output) tuple when stopped at the last hit
    """
    return debugger_instance().run_to_last_hit(file, line)


@self_healing
def debugger_clear_breakpoints():
    """
    Clear all breakpoints.
    """
    result = debugger_instance().clear_breakpoints()
    _breakpoint_registry.clear()
    return result


@self_healing
def debugger_run_to_line(
    file: str, start_line: int, end_line: int = None, ignore_count: int = None, condition: str = None
) -> Tuple[dict, str]:
    """
    In case the line is not reachable, specify to_line to add breakpoints
    to every line from line to to_line.
    
    Args:
        file: File path
        start_line: Starting line number
        end_line: Ending line number (optional)
        ignore_count: Number of times to ignore before stopping (optional)
        condition: C expression condition for the breakpoint (optional)

    Returns:
        [lldb output, target output] tuple
    """
    # Treat run_to_line as a fresh navigation request. Reusing stale breakpoints
    # causes duplicate stops and inflated hit counts across repeated experiments.
    _invalidate_print_cache("run_to_line")
    debugger_clear_breakpoints()
    debugger_set_breakpoint(file, start_line, end_line, ignore_count=ignore_count, condition=condition)
    dbg_output, target_output = debugger_run()
    if dbg_output.get("reason") == "breakpoint-hit":
        debugger_record_last_position(file, start_line)
    return dbg_output, target_output


@self_healing
def debugger_continue_execution():
    return debugger_instance().continue_execution()


@self_healing
def debugger_step_over():
    return debugger_instance().step_over()


@self_healing
def debugger_step_into():
    return debugger_instance().step_into()


@self_healing
def debugger_print(expression):
    """
    Print the value of the expression.
    """
    global _consecutive_print_timeouts
    expression_s = str(expression)
    _bump_debugger_cost_stat("print_requests")
    cache_key = (_debugger_state_epoch, expression_s)
    if cache_key in _print_cache:
        _bump_debugger_cost_stat("print_cache_hits")
        return _print_cache[cache_key]
    _bump_debugger_cost_stat("print_cache_misses")
    generation_before = debugger_backend_generation()
    dbg = debugger_instance()
    generation_after = debugger_backend_generation()
    if generation_after != generation_before:
        restored = debugger_restore_last_position()
        if restored:
            dbg = debugger_instance()
        elif _last_run_to_line_file is not None and _last_run_to_line_line is not None:
            return (
                "Error: Debugger backend was reset before evaluating this expression, but the last "
                "analysis point could not be restored. Use run_to_line to restore state before printing."
            )

    res = dbg.print(expression_s)
    if "Error: Timeout" in res or "LLDB_EVAL_TIMEOUT" in res:
        _consecutive_print_timeouts += 1
        logger = get_logger("debugger")
        logger.warning(
            f"print({expression}) timed out ({_consecutive_print_timeouts}/{_PRINT_TIMEOUT_RESPAWN_THRESHOLD})."
        )
        debugger_respawn_if_unhealthy("lldb mi eval timeout desynced the output stream")
        _consecutive_print_timeouts = 0
        restored = debugger_restore_last_position()
        if restored:
            return (
                "Error: Timeout (LLDB eval). Debugger was reset immediately after the timeout and restored "
                "to the last analysis point. Retry print_value only if the value is still necessary."
            )
        return (
            "Error: Timeout (LLDB eval). Debugger was reset immediately after the timeout because the MI "
            "output stream may be desynchronized. Use run_to_line to restore state before continuing."
        )
        if _consecutive_print_timeouts >= _PRINT_TIMEOUT_RESPAWN_THRESHOLD:
            debugger_respawn_if_unhealthy(
                f"consecutive print timeouts ({_consecutive_print_timeouts})"
            )
            _consecutive_print_timeouts = 0
            restored = debugger_restore_last_position()
            if restored:
                return (
                    "Error: Timeout (LLDB eval). Debugger was reset and restored to last position. "
                    "You can retry print_value or continue analysis."
                )
            return (
                "Error: Timeout (LLDB eval). Debugger was reset due to consecutive timeouts. "
                "Use run_to_line to restore state before continuing."
            )
    else:
        _consecutive_print_timeouts = 0
        if not any(marker in res.lower() for marker in ("error:", "timeout", "not available", "unavailable", "lldb_eval")):
            _print_cache[cache_key] = res
    return res


@self_healing
def debugger_get_type(expression):
    """
    Get the type of the expression.
    """
    return debugger_instance().get_variable_type(expression)


@self_healing
def debugger_assign(variable: str, value: str) -> Tuple[bool, str]:
    """
    Assign a value to a variable in the debugger.
    Returns (success: bool, message: str).
    """
    _invalidate_print_cache("assign")
    success, message = debugger_instance().assign(variable, value)
    if (not success) and _is_debugger_timeout_message(message):
        debugger_respawn_if_unhealthy(f"assignment timed out: {variable}")
        debugger_restore_last_position()
        return False, f"{message}. Debugger was reset because the MI output stream may be desynchronized."
    if success:
        # Auto-verify: Get the actual value after assignment
        current_val = debugger_print(variable)
        # Check if verification output contains error messages
        # This catches cases where assignment appeared to succeed but actually failed
        if current_val and ("error:" in current_val.lower() or "cannot assign" in current_val.lower() or "const-qualified" in current_val.lower()):
            # The verification revealed an error - assignment actually failed
            # Return only the error message, not the original "success" message
            return False, f"Assignment failed. Verified value: {current_val}"
        message = f"{message} Verified value: {current_val}"
    return success, message


@self_healing
def debugger_assign_expression(expression: str) -> Tuple[bool, str]:
    """
    Execute a complete assignment expression in the debugger.
    """
    _invalidate_print_cache("assign_expression")
    success, message = debugger_instance().assign_expression(expression)
    if (not success) and _is_debugger_timeout_message(message):
        debugger_respawn_if_unhealthy("assignment expression timed out")
        debugger_restore_last_position()
        return False, f"{message}. Debugger was reset because the MI output stream may be desynchronized."
    return success, message


@self_healing
def debugger_add_functional_guard(file: str, line: int, condition: str, return_value: str) -> Tuple[bool, str]:
    """
    Adds a 'functional guard' that forces a return if a condition is met.
    This effectively injects an 'if (condition) return return_value;' patch at runtime.
    """
    _invalidate_print_cache("functional_guard")
    success, message = debugger_instance().add_functional_guard(file, line, condition, return_value)
    if success:
        _register_breakpoint(
            file,
            line,
            None,
            message,
            condition=condition,
            source=f"functional_guard:return {return_value}",
        )
    if (not success) and _is_debugger_timeout_message(message):
        debugger_respawn_if_unhealthy("functional guard setup timed out")
        debugger_restore_last_position()
        return False, f"{message}. Debugger was reset because the MI output stream may be desynchronized."
    return success, message


@self_healing
def debugger_execute(command):
    _invalidate_print_cache("execute")
    message = debugger_instance().execute(command)
    if _is_debugger_timeout_message(message):
        debugger_respawn_if_unhealthy("debugger execute timed out")
        debugger_restore_last_position()
        return f"{message}. Debugger was reset because the MI output stream may be desynchronized."
    return message
