import os
import subprocess
from typing import Tuple
from utils.logger import logm, get_logger

class DebuggerProcessExitedError(Exception):
    """Exception raised when the debugger process has exited unexpectedly."""
    pass


class DebuggerStreamDesyncedError(TimeoutError):
    """Exception raised when an MI command result cannot be synchronized."""
    pass

class LldbController:
    def __init__(
        self, executable="lldb-mi", cwd=os.getcwd(), env={}, stderr=subprocess.DEVNULL
    ) -> None:
        self._cwd = cwd
        self._process = subprocess.Popen(
            [executable, "--nx", "--quiet", "--interpreter=mi3"],
            env={**os.environ, **env},
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            # LldbServer uses select() before readline(). A buffered stdout can
            # already hold the next MI record in Python while the OS fd appears
            # unreadable, producing false timeouts and stale command responses.
            bufsize=0,
            stderr=stderr,
            cwd=cwd,
        )
        if self._process.poll() is not None:
            raise Exception("Failed to start LLDB")

    def _match_until(self, until, token):
        if until is None:
            return True
        if isinstance(until, str):
            return until == token
        if isinstance(until, list):
            return token in until
        return False

    @logm("lldb")
    def get_output(self, until=None, logger=None) -> Tuple[str, str, str]:
        """
        Get a single line of output from LLDB. If until is provided, keep reading
        until the output match the token.
        """
        logger.debug("[DEBUG] LldbController.get_output: About to call readline()...")
        try:
            raw_line = self._process.stdout.readline().decode("utf-8")
        except (BrokenPipeError, OSError) as e:
            logger.error(f"[DEBUG] Broken pipe error when reading from LLDB stdout: {e}")
            raise DebuggerProcessExitedError(f"LLDB process has exited: {e}")
        
        if not raw_line:
            # EOF reached, process likely exited
            exit_code = self._process.poll()
            logger.error(f"[DEBUG] EOF reached on LLDB stdout. Process poll: {exit_code}")
            raise DebuggerProcessExitedError(f"LLDB process has exited with code {exit_code}")

        logger.debug(f"LLDB_RAW_RECV: {raw_line.strip()}")
        line = raw_line.strip()
        while line == "" or line == "(gdb)" or (not self._match_until(until, line[0])):
            if line != "" and line != "(gdb)":
                logger.debug(line)
            logger.debug("[DEBUG] LldbController.get_output: Reading next line (in while loop)...")
            try:
                raw_line = self._process.stdout.readline().decode("utf-8")
            except (BrokenPipeError, OSError) as e:
                logger.error(f"[DEBUG] Broken pipe error when reading from LLDB stdout (in loop): {e}")
                raise DebuggerProcessExitedError(f"LLDB process has exited: {e}")
            
            if not raw_line:
                exit_code = self._process.poll()
                logger.error(f"[DEBUG] EOF reached on LLDB stdout (in loop). Process poll: {exit_code}")
                raise DebuggerProcessExitedError(f"LLDB process has exited with code {exit_code}")

            logger.debug(f"LLDB_RAW_RECV: {raw_line.strip()}")
            line = raw_line.strip()
        logger.debug(f"LLDB_PROCESSED_LINE: {line}")

        return self._parse_line(line)

    def _parse_line(self, line: str) -> Tuple[str, str, str]:
        if line[0] == "^":
            index = line.find(",")
            if index == -1:
                return (line[0], line[1:], "")
            return (line[0], line[1:index], line[index + 1 :])
        if line[0] == "=" or line[0] == "*":
            index = line.find(",")
            return (line[0], line[1:index], line[index + 1 :])
        if line[0] == "~":
            return (
                line[0],
                "stdout",
                line[2:-1].replace("\\r", "").replace("\\n", "\n").replace("\\t", "\t"),
            )
        if line[0] == "&":
            return (line[0], "stderr", line[2:-1])
        if line[0] == "@":
            return (
                line[0],
                "target",
                line[2:-1].replace("\\r", "").replace("\\n", "\n").replace("\\t", "\t"),
            )
        return (
            "@",
            "target",
            line.replace("\\r", "").replace("\\n", "\n").replace("\\t", "\t"),
        )

    @logm("lldb")
    def execute(self, command: str, logger=None):
        """
        Execute a command in LLDB.
        """
        logger.debug(command)
        if self._process.poll() is not None:
            self._handle_process_exit(command, logger)
        
        try:
            self._process.stdin.write(f"{command}\n".encode("utf-8"))
            self._process.stdin.flush()
        except (BrokenPipeError, OSError) as e:
            logger.error(f"[DEBUG] Broken pipe error when executing command '{command}': {e}. LLDB process may have exited.")
            raise DebuggerProcessExitedError(f"LLDB process has exited, cannot execute command: {e}")

    def _handle_process_exit(self, command: str, logger):
        exit_code = self._process.poll()
        meanings = {
            -11: " (SIGSEGV - segmentation fault)",
            -6: " (SIGABRT - abort signal)",
            -9: " (SIGKILL - killed)",
        }
        exit_code_meaning = meanings.get(exit_code, f" (signal {-exit_code})" if exit_code < 0 else f" (exit code {exit_code})")
        logger.error(f"[DEBUG] LLDB process has exited (return code: {exit_code}{exit_code_meaning}). Cannot execute command: {command}")
        raise DebuggerProcessExitedError(f"LLDB process has exited (return code: {exit_code}{exit_code_meaning}), cannot execute command")

    def exit(self):
        try:
            self.execute("quit")
        except:
            pass
        self._process.terminate()
