"""
Angelic Agent: Finds an "angelic value" to prevent crashes.

This agent uses a debugger to iteratively mutate a variable at a specific
breakpoint until the program no longer crashes. This discovered "angelic value"
is then used to guide patch generation.
"""
import json
from .generic_agent import GenericAgent
from tools.debugger.functions import (
    debugger_run_to_line,
    debugger_print,
    debugger_assign,
    debugger_continue,
    debugger_clear_breakpoints,
)
from tools.file.functions import file_get_decorated_content
from utils.logger import get_logger
from utils.llm_helper import LLMHelper

NAME = "agent-angelic"
MAX_RETRIES = 5

# =============================================================================
# Prompt definitions
# =============================================================================
SYSTEM_PROMPT = (
    "You are an expert debugger. Your task is to find a 'safe value' for a variable "
    "at a specific point in a program's execution to prevent a crash."
    # <hr>
    "You will be given the context of a crash: the file, the line number, the variable name, "
    "and the variable's current 'malicious value' that causes the crash."
    # <hr>
    "Based on this information and the surrounding code, you must propose a new, "
    "safer value for this variable. Your goal is to find a value that allows the "
    "program to continue without crashing."
    # <hr>
    "Call the `propose_safe_value` function with your suggestion. I will apply it and "
    "tell you if the program still crashes. If it does, I will ask you for another value. "
    "If it succeeds, the process is over."
)

INITIAL_PROMPT = (
    "The program crashes at {file}:{line}.\n"
    "The variable '{variable}' has the value: {malicious_value}\n"
    "Here is the surrounding code:\n"
    "```c\n{code_context}\n```\n"
    "Please propose a new, safe value for the variable '{variable}' to prevent the crash."
)

RETRY_PROMPT = (
    "The value '{proposed_value}' did not prevent the crash. "
    "The program still crashed with the following reason: {crash_reason}\n"
    "Please analyze this and propose a different safe value for the variable '{variable}'."
)

# =============================================================================
# Agent hooks and state
# =============================================================================

GLOBAL_STATE = {
    "proposed_value": None,
}

def reset_global_state():
    global GLOBAL_STATE
    GLOBAL_STATE["proposed_value"] = None

def propose_safe_value(value) -> str:
    """
    Propose a new, safe value for the variable.
    The value should be a string that can be assigned to the variable in the debugger.
    For C/C++ strings, this means it should be enclosed in double quotes.
    For numbers or pointers, it should be a valid literal (e.g., '123', '0', 'NULL').
    """
    logger = get_logger(NAME)
    logger.info(f"Invoking propose_safe_value({value})")
    GLOBAL_STATE["proposed_value"] = value
    # The actual testing of the value happens in the main loop,
    # so we just return a confirmation message here.
    return "Value has been proposed and will be tested."


class AngelicAgent(GenericAgent):
    def __init__(self, file, line, variable, profile, **kwargs):
        super().__init__(prompt=SYSTEM_PROMPT, **kwargs)
        self.file = file
        self.line = line
        self.variable = variable
        self.profile = profile
        self.logger = get_logger(NAME)
        self.register_hook(propose_safe_value, "Propose a new, safe value for the variable.")

    def run(self):
        self.logger.info(f"Starting angelic value search for {self.variable} at {self.file}:{self.line}")

        # 1. Run to the suspicious line
        debugger_clear_breakpoints()
        lldb_output, _ = debugger_run_to_line(self.file, self.line)
        if lldb_output.get("reason") != "breakpoint-hit":
            self.logger.error("Failed to hit the initial breakpoint. Aborting.")
            return None

        # 2. Get the malicious value
        malicious_value = debugger_print(self.variable)
        self.logger.info(f"Hit breakpoint. Malicious value for '{self.variable}' is: {malicious_value}")

        # 3. Get code context for the prompt
        start_line = max(1, self.line - 10)
        end_line = self.line + 10
        code_context = file_get_decorated_content(self.file, start_line, end_line)

        # 4. Start the mutation loop
        initial_prompt = INITIAL_PROMPT.format(
            file=self.file,
            line=self.line,
            variable=self.variable,
            malicious_value=malicious_value,
            code_context=code_context,
        )

        reset_global_state()
        chat_log = self.initiate(initial_prompt)

        for i in range(MAX_RETRIES):
            proposed_value = GLOBAL_STATE["proposed_value"]

            if proposed_value is None:
                self.logger.warning(f"Attempt {i+1}: No value proposed yet, stepping conversation...")
                chat_log = self.step(chat_log)
                proposed_value = GLOBAL_STATE["proposed_value"]

            if proposed_value is None:
                self.logger.error("LLM did not propose a value. Aborting.")
                return None

            self.logger.info(f"Attempt {i+1}/{MAX_RETRIES}: Testing value '{proposed_value}' for variable '{self.variable}'")

            # 5. Assign the new value and continue
            success, assign_result_msg = debugger_assign(self.variable, proposed_value)
            self.logger.debug(f"Assign result: {success}, {assign_result_msg}")

            if not success:
                self.logger.warning(f"Assignment failed: {assign_result_msg}")
                if i < MAX_RETRIES - 1:
                    # Provide feedback to the LLM about the assignment failure
                    retry_prompt = (
                        f"I could not assign the value '{proposed_value}' to '{self.variable}'.\n"
                        f"Debugger error: {assign_result_msg}\n"
                        "Please analyze the error and propose a different value or a different way to assign it (e.g., using a cast if it's a pointer or const variable)."
                    )
                    reset_global_state()
                    chat_log = self.step(chat_log, new_message=retry_prompt)
                    continue
                else:
                    self.logger.error("Failed to assign value after all retries.")
                    break

            lldb_output, _ = debugger_continue()
            crash_reason = lldb_output.get("reason")

            # 6. Check the result
            if crash_reason is None or "exited" in crash_reason:
                self.logger.info(f"SUCCESS! Angelic value found: '{proposed_value}'")
                result = {
                    "file": self.file,
                    "line": self.line,
                    "variable": self.variable,
                    "malicious_value": malicious_value,
                    "angelic_value": proposed_value,
                }
                self._save_result(result)
                debugger_clear_breakpoints()
                return result
            else:
                self.logger.warning(f"Value '{proposed_value}' did not prevent crash. Reason: {crash_reason}")
                if i < MAX_RETRIES - 1:
                    # Prepare for the next loop iteration
                    retry_prompt = RETRY_PROMPT.format(
                        proposed_value=proposed_value,
                        crash_reason=crash_reason,
                        variable=self.variable
                    )
                    reset_global_state()
                    chat_log = self.step(chat_log, new_message=retry_prompt)
                else:
                    self.logger.error("Failed to find an angelic value after all retries.")

        debugger_clear_breakpoints()
        return None

    def _save_result(self, result):
        # Save the found angelic value to a file for the patch agent
        output_path = self.profile.get("angelic_output", "/tmp/angelic_value.json")
        self.logger.info(f"Saving angelic value result to {output_path}")
        with open(output_path, "w") as f:
            json.dump(result, f, indent=4)