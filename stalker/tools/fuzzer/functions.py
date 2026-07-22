# In-Debugger Fuzzing Tool API
from .engine import InDebuggerFuzzer
from utils.logger import logf

NAME = "fuzzer"

@logf(NAME, True)
def fuzz_variables(suspect_object: dict, profile: dict, debugger, llm_agent) -> dict:
    """
    Performs in-debugger fuzzing on a set of suspect variables.

    Args:
        suspect_object: The object returned by the DebugAgent, containing all suspect info.
        profile: The main project profile.
        debugger: The active debugger instance.
        llm_agent: An LLM agent instance for constraint deduction.

    Returns:
        A dictionary containing the fuzzing results.
    """
    fuzzer = InDebuggerFuzzer(debugger, llm_agent)
    results = fuzzer.run(
        suspect_object=suspect_object,
        profile=profile
    )

    return results
