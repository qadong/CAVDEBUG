import os
import re
import select
import time
from time import sleep
from typing import Dict, List, Tuple, Optional
from fix import apply_valid_pointer_check_fix, apply_valid_pointer_check_post_fix
from tools.debugger.integration import parse_lldb_info
from tools.debugger.controller import LldbController, DebuggerProcessExitedError, DebuggerStreamDesyncedError
from utils.parsers import check_sanitizer_error
from utils.logger import logm, get_logger

NAME = "debugger"

# Timeout for expression evaluation (print, expr). 600s was causing 10min hangs.
# Default 18s: large ASan/fuzzer binaries and nested member expressions often need
# more than 12s even at O0. Keep retry bounded to avoid wedging the session.
LLDB_PRINT_TIMEOUT = int(os.environ.get("LLDB_PRINT_TIMEOUT", "18"))
LLDB_PRINT_TIMEOUT_RETRY_MULT = float(os.environ.get("LLDB_PRINT_TIMEOUT_RETRY_MULT", "2.0"))
LLDB_PRINT_TIMEOUT_MAX = int(os.environ.get("LLDB_PRINT_TIMEOUT_MAX", "60"))
LLDB_FRAME_TIMEOUT = int(os.environ.get("LLDB_FRAME_TIMEOUT", "30"))
LLDB_HOUSEKEEPING_TIMEOUT = float(os.environ.get("LLDB_HOUSEKEEPING_TIMEOUT", "15"))


class LldbServer:
    def __init__(
        self,
        executable,
        args: List[str],
        env: Dict[str, str],
        cwd=os.getcwd(),
    ) -> None:
        self._executable = executable
        self._args = args
        self._env = env
        self._controller = LldbController("lldb-mi", cwd, env)
        self.logger = get_logger(NAME)
        self._stream_desynced = False
        self._cost_stats = {
            "eval_requests": 0,
            "eval_timeouts": 0,
            "eval_retries": 0,
            "eval_errors": 0,
            "assign_requests": 0,
            "assign_expression_requests": 0,
            "total_eval_seconds": 0.0,
            "slow_evals": 0,
        }

        if not os.path.exists(self._executable):
            raise Exception(f"Executable {self._executable} does not exist")

    def reset_cost_stats(self) -> None:
        for key in list(self._cost_stats.keys()):
            self._cost_stats[key] = 0.0 if key == "total_eval_seconds" else 0

    def get_cost_stats(self) -> dict:
        return dict(self._cost_stats)

    def _bump_cost_stat(self, key: str, amount=1) -> None:
        self._cost_stats[key] = self._cost_stats.get(key, 0) + amount

    def _execute(self, cmd, ignore=False):
        self._controller.execute(cmd)
        if ignore:
            self._drain_ignored_response()

    @logm(NAME, True)
    def execute(self, cmd, ignore=False):
        """Public version of _execute for external use (e.g. fuzzer blocks)."""
        self._execute(cmd, ignore)
        if ignore:
            return "Command executed"
        output, final_line = self._collect_mi_output(["~", "&", "^"], timeout=5)
        output_str = "\n".join(output).strip()
        if not final_line:
            return "Error: Timeout waiting for command response"
        if final_line[1] == "error":
            return f"Error: Command failed - {final_line[2]}"
        return output_str or "Command executed"

    def _get_output(self, until=None, timeout=None):
        """Get output with optional timeout."""
        if timeout is None:
            return self._controller.get_output(until)

        deadline = time.monotonic() + max(0.0, float(timeout))
        stdout = getattr(self._controller, "_process", None).stdout
        if stdout is None:
            raise DebuggerProcessExitedError("LLDB process stdout is unavailable")

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not self._stdout_has_pending_output(timeout=remaining):
                self._stream_desynced = True
                self.logger.warning(
                    "[DEBUG] MI output stream marked desynced after timeout waiting %.1fs for token %s",
                    timeout,
                    until,
                )
                raise TimeoutError(f"get_output timed out after {timeout} seconds")

            try:
                raw_line = stdout.readline().decode("utf-8")
            except (BrokenPipeError, OSError) as e:
                raise DebuggerProcessExitedError(f"LLDB process has exited: {e}") from e

            if not raw_line:
                exit_code = self._controller._process.poll()
                raise DebuggerProcessExitedError(f"LLDB process has exited with code {exit_code}")

            line = raw_line.strip()
            if line == "" or line == "(gdb)":
                continue
            if not self._controller._match_until(until, line[0]):
                self.logger.debug(line)
                continue
            return self._controller._parse_line(line)

    def _get_output_best_effort(self, until=None, timeout=0.2):
        """Read one MI line without marking the stream desynced on timeout."""
        deadline = time.monotonic() + max(0.0, float(timeout))
        stdout = getattr(self._controller, "_process", None).stdout
        if stdout is None:
            raise DebuggerProcessExitedError("LLDB process stdout is unavailable")

        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not self._stdout_has_pending_output(timeout=remaining):
                raise TimeoutError(f"best-effort get_output timed out after {timeout} seconds")

            raw_line = stdout.readline().decode("utf-8")
            if not raw_line:
                exit_code = self._controller._process.poll()
                raise DebuggerProcessExitedError(f"LLDB process has exited with code {exit_code}")

            line = raw_line.strip()
            if line == "" or line == "(gdb)":
                continue
            if not self._controller._match_until(until, line[0]):
                self.logger.debug(line)
                continue
            return self._controller._parse_line(line)

    def _stdout_has_pending_output(self, timeout: float = 0.0) -> bool:
        """
        Cheap readiness probe for LLDB stdout.
        This avoids spawning a timed reader thread for housekeeping paths like
        `kill()`, where "no output available" is not a stream-desync condition.
        """
        try:
            stdout = getattr(self._controller, "_process", None).stdout
            if stdout is None:
                return False
            readable, _, _ = select.select([stdout], [], [], max(0.0, timeout))
            return bool(readable)
        except Exception:
            return False

    def _drain_ignored_response(self, timeout: float | None = None) -> None:
        """
        Consume the result record for a housekeeping command issued with
        `ignore=True`.

        MI commands are ordered, so returning before their ``^done``/``^error``
        record arrives lets the next command consume the stale result as its
        own. That can make a breakpoint insertion look successful even though
        its response has not been read yet. Ignore the command's status, but
        always synchronize the stream before returning.
        """
        if timeout is None:
            timeout = LLDB_HOUSEKEEPING_TIMEOUT
        try:
            deadline = time.monotonic() + timeout
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                line = self._get_output_best_effort(timeout=remaining)
                if line[0] == "^":
                    return
        except (DebuggerProcessExitedError, TimeoutError):
            pass

        self._stream_desynced = True
        raise DebuggerStreamDesyncedError("Timed out waiting for LLDB MI housekeeping command response")

    @logm(NAME, True)
    def start(self):
        for key, value in self._env.items():
            self._execute(f"settings set target.env-vars {key}={value}", True)
        self._execute(f"target create {self._executable}", True)

    def _parse_stopped_reason(self, line_data: str) -> dict:
        info = parse_lldb_info(line_data)
        reason = info["reason"]
        
        res = {"reason": reason}
        if "bkptno" in info:
            try:
                res["breakpoint_id"] = int(info["bkptno"])
            except (TypeError, ValueError):
                res["breakpoint_id"] = info["bkptno"]
        if "frame" in info:
            res.update({
                "file": info["frame"].get("file"),
                "line": info["frame"].get("line"),
                "func": info["frame"].get("func"),
                "args": info["frame"].get("args"),
            })
        
        if reason == "signal-received":
            res.update({
                "signal_name": info.get("signal-name") or info.get("signal", "unknown"),
                "signal_meaning": info.get("signal-meaning", ""),
            })
        
        # Check for UBSan-related stop
        if reason and ("nullptr" in reason.lower() or "ubsan" in reason.lower()):
            res["ubsan_stop"] = True
            res["note"] = f"UBSan stop detected (reason: {reason})"
        elif "frame" in info and "__ubsan_" in info["frame"].get("func", ""):
            res["ubsan_stop"] = True
            res["note"] = f"UBSan stop detected (reason: {reason})"
            
        return res

    @logm(NAME)
    def _parse_run_output(self, is_run, logger=None) -> Tuple[dict, str]:
        target_output = ""
        
        logger.debug(f"_parse_run_output: read output (is_run={is_run})")
        try:
            # Waiting for a running target to emit MI output is not the same as
            # expression-eval desync. A quiet process can legitimately produce
            # no MI line for several seconds; do not poison the MI stream here.
            line = self._get_output_best_effort(timeout=10)
        except TimeoutError:
            return self._handle_timeout_error(logger), target_output

        # State tracking
        state = {
            "saw_thread_exited": False,
            "saw_done": False,
            "saw_running": False,
            "saw_ubsan_error": False,
            "iteration_count": 0,
            "iterations_since_thread_exited": 0,
            "iterations_since_running": 0,
            "iterations_since_ubsan": 0,
        }

        while (line[0], line[1]) != ("*", "stopped"):
            state["iteration_count"] += 1
            
            # Handle special lines
            if line[0] == "@":
                target_output += line[2] + "\n"
                if "runtime error:" in line[2] or "undefined-behavior" in line[2]:
                    state["saw_ubsan_error"] = True
                    state["iterations_since_ubsan"] = 0
                if "AddressSanitizer report breakpoint hit" in line[2]:
                    self._execute("process continue")
            
            elif (line[0], line[1]) == ("*", "running"):
                state["saw_running"] = True
                state["iterations_since_running"] = 0
            
            elif line[0] == "^" and line[1] == "done":
                state["saw_done"] = True
            
            elif (line[0], line[1]) == ("=", "library-loaded"):
                self._handle_library_loaded(line, is_run, logger)
            
            elif (line[0], line[1]) == ("=", "thread-exited"):
                state["saw_thread_exited"] = True
                state["iterations_since_thread_exited"] = 0
            
            elif line[0] == "&":
                if "Process must be launched" in line[2]:
                    return self._process_not_launched_error(), target_output

            # Update counters and check for exit conditions
            if state["saw_running"]: state["iterations_since_running"] += 1
            if state["saw_ubsan_error"]: state["iterations_since_ubsan"] += 1
            if state["saw_thread_exited"]: state["iterations_since_thread_exited"] += 1

            exit_reason = self._check_exit_conditions(state, is_run, logger)
            if exit_reason:
                return exit_reason, target_output

            try:
                line = self._get_output_best_effort(timeout=10)
            except TimeoutError:
                return self._handle_loop_timeout(state, logger), target_output

        return self._parse_stopped_reason(line[2]), target_output

    def _handle_timeout_error(self, logger) -> dict:
        status = self._controller._process.poll()
        if status is not None:
            return {
                "reason": "error",
                "error": "lldb_crashed",
                "note": f"LLDB process has exited (return code: {status})"
            }
        return {
            "reason": "error",
            "error": "timeout",
            "note": "Program may not have started properly"
        }

    def _handle_library_loaded(self, line, is_run, logger):
        if apply_valid_pointer_check_fix():
            info = parse_lldb_info(line[2])
            if info["id"] == "_$__lldb_valid_pointer_check":
                if (not is_run) and apply_valid_pointer_check_post_fix():
                    temp_line = self._get_output()
                    while (temp_line[0], temp_line[1]) != ("=", "thread-created"):
                        temp_line = self._get_output()
                    sleep(1)
                    self._execute("process continue")

    def _check_exit_conditions(self, state, is_run, logger) -> Optional[dict]:
        if state["saw_ubsan_error"] and state["iterations_since_ubsan"] > 30:
            return {"reason": "exited-normally", "note": "Likely aborted due to UBSan error"}
        
        if not is_run and state["saw_thread_exited"] and state["iterations_since_thread_exited"] > 20:
            return {"reason": "exited-normally", "note": "Program exited normally (thread-exited)"}
        
        if state["saw_running"]:
            max_iters = 200 if is_run else 50
            if state["iterations_since_running"] > max_iters:
                if not is_run and state["saw_thread_exited"]:
                    return {"reason": "exited-normally", "note": "Program exited normally"}
                if is_run or (state["saw_done"] and state["iterations_since_running"] > max_iters * 2):
                    return {"reason": "exited-normally", "note": "Program likely exited"}
        return None

    def _handle_loop_timeout(self, state, logger) -> dict:
        if state["saw_running"] or state["saw_thread_exited"] or state["saw_done"]:
            return {"reason": "exited-normally", "note": "Program may have exited"}
        return {"reason": "error", "error": "timeout", "note": "Timeout waiting for LLDB output"}

    def _process_not_launched_error(self) -> dict:
        return {
            "reason": "error",
            "error": "process_not_launched",
            "note": "Process must be launched"
        }

    @logm(NAME, True)
    def run(self) -> Tuple[dict, str]:
        cmd = "run"
        for arg in self._args:
            cmd += f' "{arg}"'
        self._execute(cmd)
        return self._parse_run_output(True)

    def continue_run(self) -> Tuple[dict, str]:
        self._execute("process continue")
        return self._parse_run_output(False)

    def _collect_mi_output(self, until_tokens: List[str], timeout=5) -> Tuple[List[str], Optional[Tuple[str, str, str]]]:
        output_lines = []
        try:
            line = self._get_output(until_tokens, timeout=timeout)
            while line[0] in ["~", "&"]:
                output_lines.append(line[2])
                try:
                    line = self._get_output(timeout=1)
                except TimeoutError:
                    return output_lines, None
            return output_lines, line
        except TimeoutError:
            return output_lines, None

    def _collect_mi_output_best_effort(self, until_tokens: List[str], timeout=1) -> Tuple[List[str], Optional[Tuple[str, str, str]]]:
        output_lines = []
        try:
            line = self._get_output_best_effort(until_tokens, timeout=timeout)
            while line[0] in ["~", "&"]:
                output_lines.append(line[2])
                try:
                    line = self._get_output_best_effort(timeout=0.2)
                except TimeoutError:
                    return output_lines, None
            return output_lines, line
        except TimeoutError:
            return output_lines, None

    @logm(NAME, True)
    def backtrace(self) -> str:
        self._execute("thread backtrace")
        output, final_line = self._collect_mi_output(["~", "&", "^"])
        if not final_line:
            if output:
                return "\n".join(output)
            return "Error: Timeout waiting for backtrace"
        if final_line[1] == "error":
            return f"Error: Backtrace failed - {final_line[2]}"
        return "\n".join(output) if output else "Error: No output"

    @logm(NAME, True)
    def frame(self, frame) -> str:
        self._execute(f"frame select {frame}")
        output, final_line = self._collect_mi_output(["~", "&", "^"])
        if not final_line:
            return "Error: Timeout waiting for frame select"
        if final_line[1] == "error":
            return f"Error: Frame select failed - {final_line[2]}"
        return "\n".join(output) if output else ""

    @logm(NAME, True)
    def read_memory(self, address: str, size: int = 1, count: int = 16, fmt: str = "x") -> str:
        """
        Read target memory at a concrete address using LLDB's memory command.

        This intentionally does not evaluate C/C++ expressions. Callers should
        pass a concrete address such as 0x7fffffffcb98.
        """
        try:
            size_i = max(1, min(int(size), 8))
        except Exception:
            size_i = 1
        try:
            count_i = max(1, min(int(count), 256))
        except Exception:
            count_i = 16

        fmt_s = str(fmt or "x").strip()
        if fmt_s not in {"x", "d", "u", "o", "b", "c"}:
            fmt_s = "x"

        address_s = str(address).strip()
        if not re.fullmatch(r"(?:0x[0-9a-fA-F]+|\d+)", address_s):
            return (
                "Error: read_memory requires a concrete address like 0x7fffffffcb98. "
                "Use print_value on a simple address expression first, e.g. print_value('r')."
            )

        self._ensure_frame_selected()
        cmd = f'memory read --format {fmt_s} --size {size_i} --count {count_i} {address_s}'
        escaped = cmd.replace("\\", "\\\\").replace('"', '\\"')
        self._execute(f'-interpreter-exec console "{escaped}"')
        output, final_line = self._collect_mi_output(["~", "&", "^"], timeout=5)
        if not final_line:
            return "Error: Timeout waiting for memory read"
        if final_line[1] == "error":
            return f"Error: Memory read failed - {final_line[2]}"
        text = "\n".join(output).strip()
        return text if text else "Error: No memory read output"

    def _ensure_frame_selected(self) -> None:
        """
        Some lldb-mi builds become unstable when evaluating expressions without a selected frame.
        Best-effort: query current frame; if unavailable, select frame 0.
        Never raise here; callers will handle actual failures.
        """
        try:
            # Prefer MI-native introspection
            self._execute("-stack-info-frame")
            _, final_line = self._collect_mi_output_best_effort(["^"], timeout=LLDB_FRAME_TIMEOUT)
            if (not final_line) or final_line[1] == "error":
                self._execute("-stack-select-frame 0")
                self._collect_mi_output_best_effort(["^"], timeout=LLDB_FRAME_TIMEOUT)
        except Exception:
            # Fallback to CLI command; ignore all errors
            try:
                self._execute("frame select 0", ignore=True)
            except Exception:
                pass

    def _classify_eval_error(self, error_msg: str) -> str:
        """
        Classify LLDB expression-evaluation failures into stable error codes so
        upper layers can apply deterministic retry/降级策略.
        """
        s = (error_msg or "").lower()
        if "lldb process has exited" in s or "process is not running" in s:
            return "PROCESS_EXITED"
        if "no frame selected" in s or "invalid frame" in s or "frame" in s and "not selected" in s:
            return "NO_FRAME"
        if "timeout" in s:
            return "TIMEOUT"
        # Unretryable: expression/scope errors. Retrying won't help.
        if "undeclared identifier" in s:
            return "UNRETRYABLE"
        return "MI_UNSTABLE"

    def _console_expr_eval(self, expression: str) -> Tuple[bool, str]:
        """
        Fallback path: use CLI expr through MI console interpreter.
        This is best-effort and only used when MI-native eval appears unstable.
        """
        try:
            escaped = str(expression).replace("\\", "\\\\").replace('"', '\\"')
            self._execute(f'-interpreter-exec console "expr {escaped}"')
            output, final_line = self._collect_mi_output(["^"], timeout=LLDB_PRINT_TIMEOUT)
            if not final_line:
                return False, "Error[LLDB_EVAL_TIMEOUT]: console expr timeout"
            if final_line[1] == "error":
                return False, f"Error[LLDB_EVAL_CONSOLE_ERROR]: {final_line[2]}"
            # Keep raw console output; caller decides how to parse/display.
            return True, "\n".join(output).strip()
        except Exception as e:
            return False, f"Error[LLDB_EVAL_CONSOLE_EXCEPTION]: {e}"

    @logm(NAME, True)
    def print(self, expression) -> str:
        # 使用更稳定的 MI 原生指令而非 CLI 别名
        # Best-effort to stabilize evaluation by ensuring a selected frame.
        self._ensure_frame_selected()

        timeout_s = LLDB_PRINT_TIMEOUT
        expr_preview = expression[:80] + "..." if len(expression) > 80 else expression
        self.logger.info(f"[DEBUG] print({expr_preview}): starting eval, timeout={timeout_s}s")

        def _eval_once():
            t0 = time.monotonic()
            self._bump_cost_stat("eval_requests")
            self._execute(f"-data-evaluate-expression \"{expression}\"")
            out, line = self._collect_mi_output(["^"], timeout=timeout_s)
            elapsed = time.monotonic() - t0
            self._bump_cost_stat("total_eval_seconds", elapsed)
            if elapsed > 5:
                self._bump_cost_stat("slow_evals")
                self.logger.warning(f"[DEBUG] print({expression[:50]}...): eval took {elapsed:.1f}s")
            return out, line

        output, final_line = _eval_once()
        
        if not final_line:
            self._bump_cost_stat("eval_timeouts")
            self.logger.error(f"Critical Timeout ({timeout_s}s) evaluating: {expr_preview}")
            # One extended retry: large ASan/fuzzer binaries often need >5–12s for heavy expressions.
            retry_timeout = min(
                int(timeout_s * LLDB_PRINT_TIMEOUT_RETRY_MULT),
                LLDB_PRINT_TIMEOUT_MAX,
            )
            if retry_timeout > timeout_s:

                def _eval_once_retry():
                    t0 = time.monotonic()
                    self._bump_cost_stat("eval_requests")
                    self._execute(f"-data-evaluate-expression \"{expression}\"")
                    out, line = self._collect_mi_output(["^"], timeout=retry_timeout)
                    elapsed = time.monotonic() - t0
                    self._bump_cost_stat("total_eval_seconds", elapsed)
                    if elapsed > 8:
                        self._bump_cost_stat("slow_evals")
                        self.logger.warning(
                            f"[DEBUG] print(retry {retry_timeout}s): eval took {elapsed:.1f}s"
                        )
                    return out, line

                self.logger.warning(
                    f"Retrying LLDB eval with extended timeout={retry_timeout}s for: {expr_preview}"
                )
                self._bump_cost_stat("eval_retries")
                output, final_line = _eval_once_retry()
            if not final_line:
                # Use "Error: Timeout" so debugger_print's respawn logic triggers
                return "Error: Timeout (LLDB eval)"
            
        if final_line[1] == "error":
            self._bump_cost_stat("eval_errors")
            err = final_line[2]
            err_code = self._classify_eval_error(err)
            # Unretryable (e.g. undeclared identifier): return immediately, no retry.
            if err_code == "UNRETRYABLE":
                return (
                    f"{expression} not available in current LLDB expression context "
                    f"(error_code=LLDB_EVAL_{err_code}; error: {err}). "
                    "This does not necessarily mean the variable was optimized out; "
                    "prefer simpler subexpressions or a different breakpoint/frame."
                )
            if err_code == "PROCESS_EXITED":
                return f"{expression} not available (error_code=LLDB_EVAL_PROCESS_EXITED; error: LLDB process has exited: {err})"

            # One retry after re-selecting frame 0 (common fix for MI state issues)
            try:
                self._execute("-stack-select-frame 0")
                _ = self._collect_mi_output_best_effort(["^"], timeout=LLDB_FRAME_TIMEOUT)
            except Exception:
                pass
            try:
                output, final_line2 = _eval_once()
                if final_line2 and final_line2[1] != "error":
                    final_line = final_line2
                else:
                    err = final_line2[2] if final_line2 else err
                    err_code = self._classify_eval_error(err)
                    # Retry with CLI expr fallback when MI channel seems unstable/frame-related.
                    if err_code in {"NO_FRAME", "MI_UNSTABLE"}:
                        ok, console_out = self._console_expr_eval(expression)
                        if ok and console_out:
                            return console_out
                    if err_code == "PROCESS_EXITED":
                        return f"{expression} not available (error_code=LLDB_EVAL_PROCESS_EXITED; error: LLDB process has exited: {err})"
                    return (
                        f"{expression} not available in current LLDB expression context "
                        f"(error_code=LLDB_EVAL_{err_code}; error: {err}). "
                        "This does not necessarily mean the variable was optimized out; "
                        "prefer simpler subexpressions or a different breakpoint/frame."
                    )
            except Exception:
                return (
                    f"{expression} not available in current LLDB expression context "
                    f"(error_code=LLDB_EVAL_{err_code}; error: {err}). "
                    "This does not necessarily mean the variable was optimized out; "
                    "prefer simpler subexpressions or a different breakpoint/frame."
                )
            
        # MI 输出格式: ^done,value="xxx"
        if "value=" in final_line[2]:
            match = re.search(r'value="(.*)"', final_line[2])
            if match:
                return match.group(1)
        
        return "\n".join(output) if output else f"{expression} = (no output)"

    @logm(NAME, True)
    def get_variable_type(self, variable_name) -> str:
        try:
            print_result = self.print(variable_name)
            match = re.search(r'^\(([^)]+)\)\s*\$\d+', print_result)
            if match: return match.group(1).strip()
            
            match = re.search(r'^([^=]+?)\s*\$\d+\s*=', print_result)
            if match: return match.group(1).strip().rstrip('()').strip()
        except Exception: pass
        
        try:
            # Route through print() so we benefit from frame-selection + retry logic.
            t = self.print(f"__typeof__({variable_name})")
            if t and "not available" not in t.lower() and "error" not in t.lower():
                return str(t).strip()
        except Exception: pass
        return "unknown"

    def _detect_const_error(self, error_msg: str, variable: str, value: str) -> Optional[str]:
        msg_lower = error_msg.lower()
        if "const-qualified" not in msg_lower and "cannot assign" not in msg_lower:
            return None
        
        if "&" in msg_lower or "reference" in msg_lower:
            type_match = re.search(r"const\s+([^&]+)\s*&", error_msg, re.IGNORECASE)
            base_type = type_match.group(1).strip() if type_match else "Type"
            return (f"\n\n**Hint for const reference type:** The variable '{variable}' is a const reference. "
                    f"Try: `const_cast<{base_type}&>({variable}) = {value}`")
        
        return (f"\n\n**Hint for const variable:** The variable '{variable}' is const-qualified. "
                f"Try modifying an upstream variable or the non-const source.")

    @logm(NAME, True)
    def assign(self, variable, value) -> Tuple[bool, str]:
        self._bump_cost_stat("assign_requests")
        val_str = str(value).strip()
        
        # 优化判断逻辑：识别纯数字（包括十六进制 0x...）
        is_numeric = re.match(r'^-?\d+$', val_str) or re.match(r'^0x[0-9a-fA-F]+$', val_str)
        is_complex = any(c in val_str for c in "()*-&>") or val_str.startswith('"') or val_str.upper() == "NULL" or val_str.isidentifier()
        
        if is_numeric or is_complex:
            formatted_value = val_str
        else:
            # 只有真正的字符串内容才需要加引号
            escaped_val = val_str.replace('"', '\\"')
            formatted_value = f'"{escaped_val}"'

        self._execute(f"expr {variable} = {formatted_value}")
        output, final_line = self._collect_mi_output(["~", "&", "^"])
        
        output_str = "\n".join(output)
        if not final_line:
            return False, "Error: Timeout assigning value (LLDB expr)"
        error_msg = output_str if "error:" in output_str.lower() else ""
        if final_line and final_line[1] == "error":
            error_msg = final_line[2]
        
        if error_msg:
            hint = self._detect_const_error(error_msg, variable, formatted_value)
            return False, f"Error assigning value: {error_msg}{hint or ''}"
        
        return True, "Assignment successful"

    @logm(NAME, True)
    def assign_expression(self, expression: str) -> Tuple[bool, str]:
        self._bump_cost_stat("assign_expression_requests")
        self._execute(f"expr {expression}")
        output, final_line = self._collect_mi_output(["~", "&", "^"])
        
        output_str = "\n".join(output)
        if not final_line:
            return False, "Error: Timeout executing expression (LLDB expr)"
        if "error:" in output_str.lower():
            return False, f"Error executing expression: {output_str}"
        if final_line and final_line[1] == "error":
            return False, f"Error executing expression: {final_line[2]}"
        
        return True, f"Expression executed successfully: {expression}"

    @logm(NAME, True)
    def set_breakpoint(self, file, line, ignore_count=None, condition=None, logger=None) -> Tuple[str, int]:
        cmd_parts = ["-break-insert"]
        if ignore_count: cmd_parts.extend(["-i", str(ignore_count)])
        if condition: cmd_parts.extend(["-c", f'"{condition}"'])
        cmd_parts.extend(["-f", f"{file}:{line}"])
        
        self._execute(" ".join(cmd_parts))
        try:
            line_out = self._get_output(timeout=10)
            while line_out[0] != "^":
                if line_out[0] == "~" and "no locations" in line_out[2]:
                    return f"Invalid breakpoint at {file}:{line}", -1
                line_out = self._get_output(timeout=2)
            
            if line_out[1] == "error":
                return f"Error setting breakpoint: {line_out[2]}", -1
            
            info = parse_lldb_info(line_out[2])
            if "bkpt" in info:
                bkpt = info["bkpt"]
                return f"Breakpoint set at {file}:{line} in function {bkpt.get('func')}", int(bkpt.get("number", -1))
        except Exception as e:
            return f"Error: {e}", -1
        return f"Breakpoint set at {file}:{line}", -1

    @logm(NAME, True)
    def get_breakpoint_hit_count(self, breakpoint_id: int, logger=None) -> int:
        self._execute("-break-list")
        try:
            _, final_line = self._collect_mi_output(["^"])
            if final_line and final_line[1] == "done":
                info = parse_lldb_info(final_line[2])
                body = info.get("BreakpointTable", {}).get("body", [])
                if isinstance(body, dict): body = [body]
                for item in body:
                    bkpt = item.get("bkpt", {})
                    if int(bkpt.get("number", -1)) == breakpoint_id:
                        return int(bkpt.get("times", "0"))
        except Exception: pass
        return 0

    @logm(NAME, True)
    def clear_breakpoints(self) -> str:
        self._execute("breakpoint delete -f", True)
        return "All breakpoints cleared"

    @logm(NAME, True)
    def run_to_last_hit(self, file: str, line: int, logger=None) -> Tuple[dict, str]:
        res, bkpt_id = self.set_breakpoint(file, line)
        if bkpt_id == -1: return {"reason": "error", "error": res}, ""
        
        dbg_out, target_out = self.run()
        hit_count = self.get_breakpoint_hit_count(bkpt_id)
        if hit_count == 0: return {"reason": "error", "error": "Never hit"}, ""
        
        self.clear_breakpoints()
        self.kill()
        self.start()
        self.set_breakpoint(file, line, ignore_count=hit_count-1)
        return self.run()

    @logm(NAME, True)
    def kill(self):
        # Housekeeping only: killing a fresh target commonly returns
        # "Process must be launched". Drain and ignore that MI response so it
        # cannot poison the next `run()` parse after a respawn.
        self._execute("process kill", ignore=True)
        # 增加延迟，给 lldb-mi 反应时间处理进程退出
        sleep(0.5)
        try:
            # 尝试消耗掉残留的输出，防止干扰下一次 run 的解析
            if self._stdout_has_pending_output(timeout=1):
                line = self._get_output_best_effort(timeout=0.2)
                while line and (line[0], line[1]) != ("*", "stopped"):
                    if line[0] == "&" and "not running" in line[2]:
                        break
                    if not self._stdout_has_pending_output(timeout=0.2):
                        break
                    line = self._get_output_best_effort(timeout=0.2)
        except Exception:
            pass
        
        # 确保管道被清理干净
        self.logger.debug("Debug process killed and buffer cleared.")

    @logm(NAME, True)
    def add_functional_guard(self, file, line, condition, return_value) -> Tuple[bool, str]:
        """
        在指定位置设置一个功能哨兵（Guard）。
        如果满足 condition，则强行执行 thread return [return_value] 并 continue。
        等效于在源码中插入: if (condition) return return_value;
        """
        # 1. 先插入一个带条件的断点
        # 注意：我们这里不直接设置 MI 的条件，因为稍后会在 CLI 命令中一起处理
        res_msg, bkpt_id = self.set_breakpoint(file, line)
        if bkpt_id == -1:
            return False, f"Failed to set guard breakpoint: {res_msg}"
        
        # 2. 为该断点设置条件 (使用 CLI)
        # 这一步是为了确保 condition 语法被正确解析
        modify_msg = self.execute(f'-interpreter-exec console "breakpoint modify -c \\"{condition}\\" {bkpt_id}"')
        if isinstance(modify_msg, str) and modify_msg.startswith("Error:"):
            return False, f"Failed to configure guard condition: {modify_msg}"

        # 3. 添加自动化指令序列 (使用 CLI 回退方案，因为 -break-commands-add 不受支持)
        # 构建一个单行 Python 脚本或者多行 CLI 命令
        # lldb 的 breakpoint command add 需要交互式输入，或者使用 -o 选项
        
        commands = [
            f'expr (void)printf("[GUARD] hit at {file}:{line}, condition ({condition}) met, forcing return {return_value}\\n")',
            f'thread return {return_value}',
            'continue'
        ]
        
        # 使用 -o 选项逐条添加命令
        for cmd in commands:
            # -interpreter-exec console "breakpoint command add -o 'cmd' id"
            # 注意转义：外层是 Python 字符串，中间是 MI 命令参数，内层是 LLDB CLI 参数
            escaped_cmd = cmd.replace('"', '\\"')
            full_cmd = f'-interpreter-exec console "breakpoint command add -o \\"{escaped_cmd}\\" {bkpt_id}"'
            cmd_msg = self.execute(full_cmd)
            if isinstance(cmd_msg, str) and cmd_msg.startswith("Error:"):
                return False, f"Failed to configure guard command: {cmd_msg}"

        return True, (
            f"Successfully installed logical guard breakpoint: if ({condition}) return {return_value}. "
            "It will only affect execution when the target process hits this breakpoint; "
            "if the process has already exited, use run_to_line to start a fresh run."
        )

    @logm(NAME, True)
    def exit(self, logger=None):
        self._controller.exit()
        logger.warning("LLDB exited")
