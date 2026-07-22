"""
Constraint generation module for fuzzer engine.
"""
from agent.generic_agent import GenericAgent
from tools.file.functions import file_get_decorated_content
from tools.lsp.functions import lsp_get_function, lsp_get_symbol_definition, lsp_get_symbol_summary
from tools.debugger.functions import debugger_backtrace, debugger_print, debugger_run_to_line, debugger_assign
from utils.logger import get_logger
from utils.llm_helper import LLMHelper
from utils.files import load_json
from utils.seed_records import angelic_seed_records
import os
import glob
import json
import re
from typing import Optional, Tuple


def _is_truthy_eval(eval_result: str) -> bool:
    """
    LLDB MI print/eval formats are not stable across versions and wrappers.
    Be robust to common outputs:
    - "1" / "0"
    - "... = 1" / "... = 0"
    - "true" / "false"
    """
    s = (eval_result or "").strip().lower()
    if s in {"1", "true"}:
        return True
    if s.endswith(" = 1") or s.endswith("=1"):
        return True
    return False


def _is_falsy_eval(eval_result: str) -> bool:
    s = (eval_result or "").strip().lower()
    if s in {"0", "false"}:
        return True
    if s.endswith(" = 0") or s.endswith("=0"):
        return True
    return False


def _looks_like_debugger_exited(err: str) -> bool:
    s = (err or "").lower()
    return (
        ("lldb process has exited" in s)
        or ("debuggerprocessitederror" in s)
        or ("lldb_eval_process_exited" in s)
    )


def _looks_like_eval_unavailable(err: str) -> bool:
    s = (err or "").lower()
    return (
        _looks_like_debugger_exited(s)
        or ("lldb_eval_timeout" in s)
        or ("lldb_eval_no_frame" in s)
        or ("lldb_eval_mi_unstable" in s)
    )


def _safe_eval_constraint_int(constraint: str, file: str, line: int, logger) -> Tuple[Optional[str], Optional[str]]:
    """
    Evaluate `(int)(constraint)` with one self-healing retry.
    Returns (eval_result, error_reason). If eval_result is None, caller should
    treat this sample as unverifiable and degrade gracefully.
    """
    try:
        eval_result = debugger_print(f"(int)({constraint})")
    except Exception as e:
        return None, f"eval_exception: {e}"

    if _looks_like_eval_unavailable(eval_result):
        logger.warning(
            f"Constraint eval unavailable at first try: {eval_result}. "
            "Re-running to breakpoint and retrying once..."
        )
        try:
            debugger_run_to_line(file, line)
            eval_result = debugger_print(f"(int)({constraint})")
        except Exception as e:
            return None, f"retry_exception: {e}"
        if _looks_like_eval_unavailable(eval_result):
            return None, f"eval_unavailable_after_retry: {eval_result}"

    return eval_result, None


def _extract_scalar_int(v) -> Optional[int]:
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, int):
        return v
    s = str(v).strip()
    if not s or s.startswith("LOGIC:"):
        return None
    if re.match(r"^-?\d+$", s):
        return int(s, 10)
    if re.match(r"^0x[0-9a-fA-F]+$", s):
        return int(s, 16)
    return None


def _validate_estimated_safe_range(range_expr: str, var_name: str, angelic_values: list, demonic_values: list, logger) -> str:
    """
    Validate model-provided estimated_safe_range against observed samples.
    If it cannot be validated, degrade it to 'None' so downstream steps won't
    accidentally over-trust hallucinated inequalities.
    """
    expr = str(range_expr or "").strip()
    if not expr or expr.lower() in {"none", "null", "n/a"}:
        return "None"

    # Conservative: only allow one identifier (the target variable) in this check.
    identifiers = set(re.findall(r"\b[a-zA-Z_][a-zA-Z0-9_]*\b", expr))
    keywords = {"and", "or", "not", "true", "false"}
    identifiers = {x for x in identifiers if x.lower() not in keywords}
    if identifiers - {var_name}:
        logger.warning(
            f"estimated_safe_range contains extra identifiers {identifiers - {var_name}}; "
            "marking as untrusted."
        )
        return "None"

    py_expr = expr.replace("&&", " and ").replace("||", " or ")
    py_expr = re.sub(r"!\s*(?!=)", " not ", py_expr)

    def _eval_for(val: int) -> Optional[bool]:
        try:
            local_env = {var_name: val}
            return bool(eval(py_expr, {"__builtins__": {}}, local_env))
        except Exception:
            return None

    angelic_scalars = [_extract_scalar_int(v) for v in angelic_values]
    demonic_scalars = [_extract_scalar_int(v) for v in demonic_values]
    angelic_scalars = [v for v in angelic_scalars if v is not None]
    demonic_scalars = [v for v in demonic_scalars if v is not None]

    # If we don't have scalar samples, keep as advisory only.
    if not angelic_scalars or not demonic_scalars:
        return "None"

    angelic_ok = all(_eval_for(v) is True for v in angelic_scalars[:20])
    demonic_ok = all(_eval_for(v) is False for v in demonic_scalars[:20])
    if angelic_ok and demonic_ok:
        return expr

    logger.warning(
        "estimated_safe_range failed sample consistency check; "
        "downgrading to None."
    )
    return "None"

def load_debugger_agent_context(profile, suspect_object, logger=None):
    """Load debugger agent's conversation history to provide context for constraint generation."""
    if logger is None:
        logger = get_logger("fuzzer-engine")
    
    if not profile or "chat_dir" not in profile:
        logger.warning("Profile or chat_dir not available, skipping debugger agent context.")
        return ""

    

    chat_dir = profile["chat_dir"]

    if not os.path.exists(chat_dir):

        logger.warning(f"Chat directory does not exist: {chat_dir}")

        return ""

    

    # Find debug chat files matching this suspect_object (by file and line)

    debug_chat_files = glob.glob(os.path.join(chat_dir, "debug-*.json"))

    if not debug_chat_files:

        logger.warning(f"No debug chat files found in {chat_dir}")

        return ""

    

    # Load the most recent debug chat file (usually the one that generated this suspect_object)

    # We can also match by file/line if needed, but for now use the most recent

    debug_chat_files.sort(key=os.path.getmtime, reverse=True)

    

    context_summary = ""

    for chat_file in debug_chat_files[:1]:  # Load only the most recent one

        try:

            chat_data = load_json(chat_file)

            

            # Handle different chat file formats

            # Format 1: {"system": "...", "history": [...]}

            # Format 2: [...] (direct list)

            if isinstance(chat_data, dict):

                chat_history = chat_data.get("history", [])

            elif isinstance(chat_data, list):

                chat_history = chat_data

            else:

                logger.warning(f"Unexpected chat file format in {chat_file}")

                continue

            

            if not isinstance(chat_history, list) or len(chat_history) == 0:

                continue

            

            # Extract key insights from the conversation

            # Focus on assistant messages that contain analysis or reasoning

            key_messages = []

            for msg in chat_history:

                if not isinstance(msg, dict):

                    continue

                    

                role = msg.get("role", "")

                content = msg.get("content", "")

                

                # Extract assistant's analysis and reasoning

                if role == "assistant" and content:

                    # Look for messages that contain analysis keywords

                    analysis_keywords = ["analyze", "reason", "root cause", "problematic", "variable", 

                                       "constraint", "boundary", "safe", "unsafe", "overflow", "underflow",

                                       "crash", "offset", "length", "size", "bounds", "malicious"]

                    if any(keyword in content.lower() for keyword in analysis_keywords):

                        # Truncate very long messages to keep context manageable

                        if len(content) > 800:

                            content = content[:800] + "..."

                        key_messages.append(content)

            

            if key_messages:

                context_summary = "**Debugger Agent Analysis Context:**\n"

                context_summary += "The following insights come from the debugger agent's root cause analysis:\n"

                context_summary += "(These help you understand the code context and variable relationships)\n\n"

                for i, msg in enumerate(key_messages[:5], 1):  # Limit to top 5 insights for better context

                    context_summary += f"**Insight {i}:**\n{msg}\n\n"

                logger.info(f"Loaded {len(key_messages)} key insights from debugger agent conversation ({chat_file})")

            

        except Exception as e:

            logger.warning(f"Failed to load debug chat file {chat_file}: {e}")

            continue

    

    return context_summary


def extract_constraint_from_chat_result(chat_result, _submitted_constraint=None, logger=None):

    """

    Extract constraint from chat result. First checks _submitted_constraint,

    then falls back to parsing tool_calls and tool responses from chat history.

    """

    response = ""

    

    # Method 1: Check if constraint was stored via submit_constraint tool

    if _submitted_constraint:

        response = _submitted_constraint

        logger.info(f"Extracted constraint from submit_constraint tool: {response}")

        return response

    

    # Method 2: Parse from chat history

    if not isinstance(chat_result, dict):

        if logger:

            logger.warning("Invalid chat result type while extracting constraint: %s", type(chat_result).__name__)

        return ""

    if chat_result.get("error"):

        if logger:

            logger.warning("Chat result contains error while extracting constraint: %s", chat_result.get("error"))

        return ""

    history = chat_result.get("history", [])

    if not history:

        if logger:

            logger.warning("No chat result or history available to extract constraint.")

        return ""

    if not isinstance(history, list):

        if logger:

            logger.warning("Invalid chat history type while extracting constraint: %s", type(history).__name__)

        return ""

    import json

    import re

    

    for msg in reversed(history):

        if not isinstance(msg, dict):

            if logger:

                logger.warning("Skipping invalid chat history item while extracting constraint: %s", type(msg).__name__)

            continue

        # Look for submit_constraint in tool_calls (assistant message)

        if msg.get("role") == "assistant":

            tool_calls = msg.get("tool_calls", [])

            for tool_call in tool_calls:

                func_info = tool_call.get("function", {})

                if func_info.get("name") == "submit_constraint":

                    try:

                        args_str = func_info.get("arguments", "{}")

                        args = json.loads(args_str)

                        constraint = args.get("constraint", "")

                        if constraint:

                            response = constraint.strip()

                            logger.info(f"Extracted constraint from tool_calls: {response}")

                            return response

                    except (json.JSONDecodeError, AttributeError, KeyError) as e:

                        logger.warning(f"Failed to parse submit_constraint arguments: {e}")

        

        # Look for submit_constraint in tool responses (tool message)

        elif msg.get("role") == "tool":

            tool_name = msg.get("name", "")

            tool_content = msg.get("content", "")

            if tool_name == "submit_constraint" or "Constraint submitted successfully" in tool_content:

                # Extract constraint from response message

                match = re.search(r'Constraint submitted successfully:\s*(.+?)(?:\.\s*Your|$)', tool_content, re.DOTALL)

                if match:

                    response = match.group(1).strip()

                    logger.info(f"Extracted constraint from tool response: {response}")

                    return response

    

    logger.warning("No constraint found from submit_constraint tool. Constraint agent may not have called the tool properly.")

    return ""


def deduce_constraint(suspect_object, angelic_values, demonic_values, profile=None, llm=None, debugger=None, llm_helper=None, logger=None, _submitted_constraint=None):
    """Deduce constraint from fuzzing results."""
    if logger is None:
        logger = get_logger("fuzzer-engine")

    # 1. Check for logical angelic paths (JIT-Synthesis results)
    logic_angelic = [v for v in angelic_values if isinstance(v, str) and v.startswith("LOGIC:")]
    if logic_angelic:
        logger.info(f"Found logical angelic paths: {logic_angelic}")
        import re
        match = re.search(r'IF\((.*)\) THEN RETURN', logic_angelic[0])
        if match:
            extracted_cond = match.group(1)
            logger.info(f"Synthesized logic-based initial constraint: !({extracted_cond})")
            return f"!({extracted_cond})"

    if not llm:
        logger.error("LLM agent not provided, cannot deduce constraint.")
        return "false"

    if not angelic_values:
        return "false" # No way to succeed



    var_name = suspect_object["variable_names"][0]

    context_vars = suspect_object.get("context_variables", {})

    file = suspect_object["file"]

    line = suspect_object["line"]



    # Get the full function body for context

    function_body = lsp_get_function(file, suspect_object.get("function_name", "")) # Assumes function_name is in suspect_object

    if not function_body:

        logger.warning("Could not get function body, falling back to line context.")

        start_line = max(1, line - 15)

        end_line = line + 15

        function_body = file_get_decorated_content(file, start_line, end_line)



    # Check if we have debugger agent's chat history in memory

    debugger_chat_history = suspect_object.get("debugger_chat_history")

    debugger_system_prompt = suspect_object.get("debugger_system_prompt")

    

    # Build the new message with fuzzing results

    # Check for optional fields

    normal_examples = suspect_object.get("normal_examples", None)

    angelic_metadata = suspect_object.get("angelic_metadata", None)

    

    optional_fields = ""

    if normal_examples:

        optional_fields += f"- Normal Success Examples (optional): `{normal_examples}`\n"

    if angelic_metadata:

        optional_fields += f"- Angelic Run Metadata (optional): `{angelic_metadata}`\n"

        optional_fields += "  (e.g., for each angelic value: whether the run still visited the original crashing site or instead bypassed it by taking an alternative path.)\n"

    

    validated_estimated_range = _validate_estimated_safe_range(
        suspect_object.get("estimated_safe_range", "None"),
        var_name,
        angelic_values,
        demonic_values,
        logger,
    )
    typed_evidence = suspect_object.get("typed_angelic_evidence", {}) or {}
    bug_type_profile = suspect_object.get("bug_type_profile", {}) or {}

    fuzzing_output_prompt = (

        "You are a C/C++ expert collaborating with a debugger/fuzzing agent. Based on the fuzzing results and the previous conversation, generate the simplest possible C boolean expression (or a small disjunction of such expressions) that serves as a constraint to separate 'angelic' (safe) values from 'demonic' (unsafe) values for the target variable.\n\n"

        "Crucially, use:\n\n"

        "- The previous debugging conversation (hypotheses about root cause, pointer relationships, buffer bounds, etc.).\n\n"

        "- The full function body to understand program logic, variable definitions, and control-flow.\n\n"

        "- The fuzzing results (angelic/demonic values and any estimated safe range) as concrete examples.\n\n"

        "**Fuzzing Results:**\n"

        f"- Variable Name: `{var_name}`\n"

        f"- Context Variables: `{context_vars}`\n"

        f"- Known Angelic Seed Records (optional): `{angelic_seed_records(suspect_object)}`\n"

        f"- Angelic Values (safe): `{angelic_values}`\n"

        f"- Demonic Values (unsafe): `{demonic_values}`\n"

        f"- Estimated Safe Range (Insight, validated): `{validated_estimated_range}`\n"

        f"- Full Function Body (from {file}):\n"

        "```c\n"

        f"{function_body}\n"

        "```\n"

    )
    if bug_type_profile:
        fuzzing_output_prompt += (
            "\n**Typed Bug Profile:**\n"
            f"- Bug Type: `{bug_type_profile.get('bug_type', 'unknown')}`\n"
            f"- Angelic Shape: `{bug_type_profile.get('angelic_shape', 'generic_state_or_relation')}`\n"
            f"- Constraint Hint: `{bug_type_profile.get('constraint_hint', '')}`\n"
        )
    if typed_evidence:
        fuzzing_output_prompt += (
            "\n**Typed Angelic Evidence:**\n"
            f"- Generalized Spec: `{typed_evidence.get('generalized_spec', {})}`\n"
            f"- Preferred Repair Locations: `{typed_evidence.get('repair_locations', [])}`\n"
            f"- Forbidden Patch Patterns: `{typed_evidence.get('forbidden_patch_patterns', [])}`\n"
            f"- Demonic Trace Summary: `{typed_evidence.get('demonic_trace_summary', {})}`\n"
        )

    

    if optional_fields:

        fuzzing_output_prompt += f"\n{optional_fields}\n"

    

    fuzzing_output_prompt += (

        "**Requirements:**\n\n"

        "1. The constraint MUST be true for all angelic values and false for all demonic values.\n"

        "   - If normal success examples are provided, they SHOULD also satisfy the constraint unless the original behavior is clearly unsafe.\n\n"

        "2. **STRICTLY FORBIDDEN:** Do NOT use hardcoded memory addresses (e.g., `0x12345678`) or magic numbers that look like addresses.\n\n"

        "3. You MUST use the `Variable Name` and `Context Variables` to construct the expression (e.g., `uc < ue`, `len > 0`).\n"

        "   - Prefer semantic relationships between variables (pointer ranges, length vs capacity, index vs size, etc.), not arbitrary constants.\n\n"

        "4. Use the full function body and conversation history to infer the logical relationship between the target variable and the context variables.\n"

        "   - For example, if safe values always satisfy something like `var < end` and demonic values violate it, infer a constraint of that form.\n\n"

    )

    

    if angelic_metadata:

        fuzzing_output_prompt += (

            "5. If angelic run metadata is provided:\n"

            "   - Treat angelic runs that still visit the original crashing location (in-place angels) as the primary positive examples of **safe behavior on the original path**.\n"

            "   - Treat angelic runs that bypass the crashing location as potential **alternative safe paths**. They may justify additional disjunctive cases, but should NOT be used as the sole reason to remove or trivially bypass important logic.\n\n"

            "6. It is acceptable, when necessary, for the final constraint to be logically equivalent to a disjunction of several specific safe cases (e.g., \"(safe_original_path) OR (safe_alternative_path) ...\"), as long as:\n"

            "   - All demonic values are rejected.\n"

            "   - The cases are consistent with the intended semantics of the function.\n"

            "   - You do NOT introduce overly broad conditions that accidentally admit demonic states.\n\n"

            "7. Do NOT assume any fixed syntactic template for the condition (no requirement on the number of clauses or a specific pattern). Choose whatever boolean expression best separates safe and unsafe states while preserving the intended behavior.\n\n"

            "8. After you have generated the constraint expression, you MUST call `submit_constraint(constraint_expression)` to submit it. Do NOT output the constraint directly in your message.\n"

            "9. After calling `submit_constraint`, your task is complete. You MUST reply with TERMINATE.\n\n"

        )

    else:

        fuzzing_output_prompt += (

            "5. It is acceptable, when necessary, for the final constraint to be logically equivalent to a disjunction of several specific safe cases, as long as:\n"

            "   - All demonic values are rejected.\n"

            "   - The cases are consistent with the intended semantics of the function.\n"

            "   - You do NOT introduce overly broad conditions that accidentally admit demonic states.\n\n"

            "6. Do NOT assume any fixed syntactic template for the condition (no requirement on the number of clauses or a specific pattern). Choose whatever boolean expression best separates safe and unsafe states while preserving the intended behavior.\n\n"

            "7. After you have generated the constraint expression, you MUST call `submit_constraint(constraint_expression)` to submit it. Do NOT output the constraint directly in your message.\n"

            "8. After calling `submit_constraint`, your task is complete. You MUST reply with TERMINATE.\n\n"

        )

    

    # Create constraint agent with debugging tools

    logger.info("Creating constraint agent with debugging tools for deeper code analysis")

    constraint_agent = create_constraint_agent_with_tools(suspect_object, logger)

    

    # Build initial prompt that includes fuzzing results and encourages tool usage

    if debugger_chat_history and debugger_system_prompt:

        # Build prompt with debugger history context

        initial_prompt = (

            f"{fuzzing_output_prompt}\n\n"

            "**CRITICAL WORKFLOW: Explore First, Then Generate**\n\n"

            "DO NOT immediately generate a constraint. Instead, follow this workflow:\n\n"

            "**Step 1: Explore Code Context**\n"

            "Use the available debugging tools to gain deep understanding:\n"

            "- `search_in_repo(pattern, path=None, max_hits=20, context=2)` - Find variable/guard/function locations first. Pass a file path for single-file search or a directory path for recursive search.\n"
            "- `file_content(start_line, end_line)` - Read focused local context after search\n"

            "- `definition(symbol)` - Look up variable type definitions and declarations\n"

            "- `summary(symbol)` - Get quick information about variables or functions\n"

            "- `function_body(function_name)` - Analyze related functions and understand control flow\n"

            "- `debugger_backtrace()` - Understand the call stack and execution context\n"

            "- `print_value(expression)` - Check variable values (if debugger is at a breakpoint)\n\n"

            "**Step 2: Understand Variable Relationships**\n"

            "After exploring:\n"

            "- Identify how the target variable relates to context variables (bounds checks, pointer arithmetic, size comparisons)\n"

            "- Understand semantic relationships (e.g., index < size, pointer within bounds)\n"

            "- Analyze why angelic values are safe and demonic values are unsafe\n\n"

            "**Step 3: Generate and Submit the Constraint**\n"

            "Only after thorough exploration:\n"

            "- Generate a C boolean expression that correctly separates safe and unsafe values\n"

            "- Call `submit_constraint(constraint_expression)` to submit your generated constraint\n"

            "- The constraint expression should be a valid C boolean expression\n"

            "- After submitting, your task is complete. You MUST reply with TERMINATE\n\n"

            "Remember: A well-explored constraint is better than a quick guess. Take time to understand the code first."

        )

        

        # Format history into the prompt (for LLM context, but not logged separately)

        previous_chat_log = {

            "system": debugger_system_prompt,

            "history": debugger_chat_history.get("history", [])

        }

        

        # Build prompt with history included as context

        history_text = "**Previous Debugging Conversation History (for context):**\n\n"

        for msg in previous_chat_log.get("history", []):

            role = msg.get("role", "")

            content = msg.get("content", "")

            if role == "user":

                history_text += f"User: {content}\n\n"

            elif role == "assistant":

                tool_calls = msg.get("tool_calls", [])

                history_text += f"Assistant: {content}\n"

                if tool_calls:

                    history_text += "\n[Tool Calls]:\n"

                    for tool_call in tool_calls:

                        func_info = tool_call.get("function", {})

                        func_name = func_info.get("name", "unknown")

                        func_args = func_info.get("arguments", "{}")

                        history_text += f"- {func_name}({func_args})\n"

                    history_text += "\n"

            elif role == "tool":

                tool_name = msg.get("name", "tool")

                tool_content = content if content else ""

                tool_responses = msg.get("tool_responses", [])

                if tool_responses and not tool_content:

                    for resp in tool_responses:

                        resp_content = resp.get("content", "")

                        if resp_content:

                            tool_content = resp_content

                            break

                if tool_content:

                    history_text += f"Tool Feedback ({tool_name}):\n{tool_content}\n\n"

        

        # Combine history + initial prompt

        full_prompt = f"{history_text}\n{initial_prompt}"

        

        # Use constraint agent to initiate conversation with tools available

        # History is included in the prompt as context, but won't be logged separately

        chat_result = constraint_agent.initiate(full_prompt, logger=logger)

        

        # Extract constraint from submit_constraint tool call

        response = extract_constraint_from_chat_result(chat_result, _submitted_constraint, logger)

    else:

        # Fallback: Load from file if not in memory

        debugger_context = ""

        if profile:

            debugger_context = load_debugger_agent_context(profile, suspect_object, logger)

        

        # Build prompt with debugger agent context (from file)

        # Check for optional fields

        normal_examples = suspect_object.get("normal_examples", None)

        angelic_metadata = suspect_object.get("angelic_metadata", None)

        

        prompt_parts = [

            "You are a C/C++ expert. Your task is to find the simplest possible C boolean expression (or a small disjunction of such expressions) that serves as a constraint to separate 'angelic' (safe) values from 'demonic' (unsafe) values for a variable.",

            "Crucially, use the provided full function body to understand the program logic, variable definitions, control-flow, and the intended behavior. Use the value samples and any additional metadata as concrete evidence of which states are safe and which are unsafe."

        ]

        

        if debugger_context:

            prompt_parts.append(debugger_context)

            prompt_parts.append("\n**Please use the debugger agent's analysis above to better understand the code context and variable relationships when generating the constraint.**\n")

        

        prompt_parts.extend([

            "Context:",

            f"- Variable Name: `{var_name}`",

            f"- Context Variables: `{context_vars}`",

            f"- Angelic Values (safe): `{angelic_values}`",

            f"- Demonic Values (unsafe): `{demonic_values}`",

            f"- Estimated Safe Range (Insight, validated): `{validated_estimated_range}`",

            f"- Typed Bug Profile: `{bug_type_profile}`",

            f"- Typed Angelic Evidence: `{typed_evidence}`",

            f"- Full Function Body (from {file}):",

            "```c",

            f"{function_body}",

            "```"

        ])

        

        # Add optional fields if available

        if normal_examples:

            prompt_parts.append(f"- Normal Success Examples (optional): `{normal_examples}`")

        if angelic_metadata:

            prompt_parts.append(f"- Angelic Run Metadata (optional): `{angelic_metadata}`")

            prompt_parts.append("  (e.g., per angelic value: flags indicating whether the run still visited the original crashing site or instead followed an alternative path.)")

        

        prompt_parts.extend([

            "",

            "**CRITICAL WORKFLOW: Explore First, Then Generate**",

            "",

            "DO NOT immediately generate a constraint. Instead, follow this workflow:",

            "",

            "**Step 1: Explore Code Context**",

            "Use the available debugging tools to gain deep understanding:",

            "- `search_in_repo(pattern, path=None, max_hits=20, context=2)` - Find variable/guard/function locations first. Pass a file path for single-file search or a directory path for recursive search.",
            "- `file_content(start_line, end_line)` - Read focused local context after search",

            "- `definition(symbol)` - Look up variable type definitions and declarations",

            "- `summary(symbol)` - Get quick information about variables or functions",

            "- `function_body(function_name)` - Analyze related functions and understand control flow",

            "- `debugger_backtrace()` - Understand the call stack and execution context",

            "- `print_value(expression)` - Check variable values (if debugger is at a breakpoint)",

            "",

            "**Step 2: Understand Variable Relationships**",

            "After exploring:",

            "- Identify how the target variable relates to context variables (bounds checks, pointer arithmetic, size comparisons)",

            "- Understand semantic relationships (e.g., index < size, pointer within bounds)",

            "- Analyze why angelic values are safe and demonic values are unsafe",

            "",

            "**Step 3: Generate and Submit the Constraint**",

            "Only after thorough exploration:",

            "- Generate a C boolean expression that correctly separates safe and unsafe values",

            "- Call `submit_constraint(constraint_expression)` to submit your generated constraint",

            "- The constraint expression should be a valid C boolean expression",

            "- After submitting, your task is complete. You MUST reply with TERMINATE",

            "",

            "Remember: A well-explored constraint is better than a quick guess. Take time to understand the code first.",

            "",

            "Requirements:",

            "1. The constraint MUST be true for all angelic values and false for all demonic values.",

            "   - If normal success examples are provided, they SHOULD also satisfy the constraint, unless they clearly correspond to unsafe behavior that should be rejected.",

            "",

            "2. **STRICTLY FORBIDDEN:** Do NOT use hardcoded memory addresses (e.g., `0x12345678`) or magic numbers that look like addresses.",

            "",

            "3. You MUST use the `Variable Name` and `Context Variables` to construct the expression (e.g., `uc < ue`, `len > 0`, `index < size`). Do not invent variables that do not exist in the context.",

            "",

            "4. Infer the relationship between the values and the context variables using both the samples and the function body.",

            "   - Prefer semantic relationships (pointer within [begin, end), index vs length, non-negative size, etc.) over arbitrary thresholds.",

            ""

        ])

        

        if angelic_metadata:

            prompt_parts.extend([

                "5. If angelic run metadata is provided:",

                "   - Consider in-place angelic runs (that still visit the original crashing code) as primary positive examples on the original path.",

                "   - Consider bypass angelic runs (that avoid the crashing code) as evidence that certain alternative paths may also be safe, but only if they are consistent with the function's intended behavior.",

                "",

                "6. When necessary, you may represent multiple legitimate safe behaviors as a disjunction:",

                "   - One or more disjuncts capture strengthened preconditions for the original crashing path.",

                "   - Additional disjuncts may capture clearly valid alternative safe paths inferred from consistent bypass angelic runs.",

                "   - Do NOT add broad disjuncts that would allow any demonic value to satisfy the constraint.",

                "",

                "7. Do NOT assume any fixed syntactic template (such as a specific number of clauses or a pattern like `!a && !b || extra_condition`). Choose the boolean expression that best separates safe from unsafe states while preserving the intended semantics implied by the function body.",

                "",

                "8. After you have generated the constraint expression, you MUST call `submit_constraint(constraint_expression)` to submit it. Do NOT output the constraint directly in your message.",

                "9. After calling `submit_constraint`, your task is complete. You MUST reply with TERMINATE.",

                ""

            ])

        else:

            prompt_parts.extend([

                "5. When necessary, you may represent multiple legitimate safe behaviors as a disjunction:",

                "   - One or more disjuncts capture strengthened preconditions for the original path.",

                "   - Additional disjuncts may capture clearly valid alternative safe paths.",

                "   - Do NOT add broad disjuncts that would allow any demonic value to satisfy the constraint.",

                "",

                "6. Do NOT assume any fixed syntactic template (such as a specific number of clauses or a pattern like `!a && !b || extra_condition`). Choose the boolean expression that best separates safe from unsafe states while preserving the intended semantics implied by the function body.",

                "",

                "7. After you have generated the constraint expression, you MUST call `submit_constraint(constraint_expression)` to submit it. Do NOT output the constraint directly in your message.",

                "8. After calling `submit_constraint`, your task is complete. You MUST reply with TERMINATE.",

                ""

            ])

        

        prompt = "\n".join(prompt_parts)

        

        # Use constraint agent to initiate conversation with tools available

        chat_result = constraint_agent.initiate(prompt, logger=logger)

        

        # Extract constraint from submit_constraint tool call

        response = extract_constraint_from_chat_result(chat_result, _submitted_constraint, logger)

    

    # Use the helper to validate and clean the constraint

    constraint = llm_helper.validate_and_simplify_constraint(response, context_vars)



    # --- Online Verification ---

    logger.info(f"Verifying constraint online using debugger: {constraint}")

    

    verification_passed = True

    

    # Verify Angelic values (Constraint should be TRUE)

    for val in angelic_values:

        # Reset state

        debugger_run_to_line(file, line)

        

        # Assign value

        var_type = (suspect_object.get("llm_inferred_type") or "unknown")

        assign_val = str(val)

        if '*' in var_type and not assign_val.startswith('('):

             assign_val = f"({var_type}){val}"

        

        debugger_assign(var_name, assign_val)

        

        # Evaluate constraint (cast to int for stable 0/1)
        eval_result, eval_err = _safe_eval_constraint_int(constraint, file, line, logger)
        if eval_result is None:
            logger.warning(
                f"Skipping angelic verification sample due to debugger instability "
                f"(value={val}, reason={eval_err})."
            )
            continue

        

        # Check for True (1)
        if _is_truthy_eval(eval_result):

            logger.info(f"Constraint check PASSED for Angelic value {val} (Result: True)")

        else:

            logger.warning(f"Constraint check FAILED for Angelic value {val} (Result: {eval_result}, Expected: True)")

            verification_passed = False



    # Verify Demonic values (Constraint should be FALSE)

    # Sample a few if too many

    for val in demonic_values[:5]: 

        val_str = str(val)

        if val_str == "NULL" or "not available" in val_str: continue



        # Reset state

        debugger_run_to_line(file, line)

         

        # Assign value

        var_type = (suspect_object.get("llm_inferred_type") or "unknown")

        assign_val = str(val)

        if '*' in var_type and not assign_val.startswith('('):

             assign_val = f"({var_type}){val}"



        debugger_assign(var_name, assign_val)

        

        # Evaluate constraint
        eval_result, eval_err = _safe_eval_constraint_int(constraint, file, line, logger)
        if eval_result is None:
            logger.warning(
                f"Skipping demonic verification sample due to debugger instability "
                f"(value={val}, reason={eval_err})."
            )
            continue

        

        # Check for False (0)
        if _is_falsy_eval(eval_result):

            logger.info(f"Constraint check PASSED for Demonic value {val} (Result: False)")

        else:

            logger.warning(f"Constraint check FAILED for Demonic value {val} (Result: {eval_result}, Expected: False)")

            verification_passed = False



    if not verification_passed:

        logger.error("Online constraint verification failed! The generated constraint does not correctly separate Angelic and Demonic values.")

    else:

        logger.info("Online constraint verification passed successfully.")



    return constraint



def create_constraint_agent_with_tools(suspect_object, logger=None):
    """Create constraint agent with tools."""
    if logger is None:
        logger = get_logger("fuzzer-engine")

    """

    Create a constraint generation agent with debugging tools.

    This allows the constraint agent to explore code context and understand variable relationships

    before generating constraints.

    """

    # Store suspect_object context for tool functions to access
    _constraint_context = suspect_object
    
    # Use a list to allow nested function to modify the value (closure workaround)
    _submitted_constraint_container = [None]

    

    # Constraint agent system prompt

    constraint_system_prompt = (

        "You are a C/C++ expert specializing in program analysis and constraint generation. "

        "Your task is to analyze debugging conversations and fuzzing results to generate accurate safety constraints.\n\n"

        "**CRITICAL WORKFLOW: Explore First, Then Generate**\n\n"

        "DO NOT immediately generate a constraint based only on the initial prompt. Instead, follow this workflow:\n\n"

        "**Step 1: Explore Code Context**\n"

        "Use the available debugging tools to gain deep understanding of the code:\n"

        "- Use `search_in_repo(pattern, path=None, max_hits=20, context=2)` first to locate variable/guard/function references. Pass a file path for single-file search or a directory path for recursive search.\n"
        "- Then use `file_content(start_line, end_line)` to inspect local context around the crash location\n"

        "- Use `definition(symbol)` to look up variable type definitions and declarations\n"

        "- Use `summary(symbol)` to get quick information about variables or functions\n"

        "- Use `function_body(function_name)` to analyze related functions and understand control flow\n"

        "- Use `debugger_backtrace()` to understand the call stack and execution context\n"

        "- Use `print_value(expression)` to check variable values (if debugger is at a breakpoint)\n\n"

        "**Step 2: Understand Variable Relationships**\n"

        "After exploring the code:\n"

        "- Identify how the target variable relates to context variables (e.g., bounds checks, pointer arithmetic, size comparisons)\n"

        "- Understand the semantic relationships (e.g., index < size, pointer within bounds, non-negative length)\n"

        "- Analyze why angelic values are safe and demonic values are unsafe\n\n"

        "**Step 3: Generate and Submit the Constraint**\n"

        "Only after you have thoroughly explored the code context and understood the variable relationships:\n"

        "- Generate a C boolean expression that correctly separates angelic (safe) values from demonic (unsafe) values\n"

        "- Call `submit_constraint(constraint_expression)` to submit your generated constraint\n"

        "- The constraint expression should be a valid C boolean expression (e.g., `pe_offset <= packet->payload_packet_len - 4`)\n"

        "- After submitting, your task is complete. You MUST reply with TERMINATE\n\n"

        "**Important Restrictions:**\n"

        "- Do NOT modify program state (no assignments or continues - these tools are read-only)\n"

        "- Do NOT use hardcoded memory addresses or magic numbers\n"

        "- Use semantic relationships between variables, not arbitrary constants\n\n"

        "Remember: A well-explored constraint is better than a quick guess. Take time to understand the code before generating."

    )

    

    agent = GenericAgent("ConstraintAgent", constraint_system_prompt)

    

    # Register read-only debugging tools

    file = suspect_object["file"]

    line = suspect_object.get("line", 0)

    

    # Create tool wrapper functions with access to suspect_object context

    def constraint_file_content(start_line: int, end_line: int) -> str:

        """Get the content of a file for code analysis."""

        content = file_get_decorated_content(file, start_line, end_line)

        # Include filename in the response so the agent knows which file it's viewing

        if content:

            return f"File: {file}\nLines {start_line}-{end_line}:\n{content}"

        else:

            return f"File: {file}\nLines {start_line}-{end_line}: (empty or invalid range)"

    

    def constraint_print_value(expression: str) -> str:

        """Print the value of an expression at the current debugger stop (if available)."""

        try:

            result = debugger_print(expression)

            if len(result) > 500:

                return result[:500] + "... (truncated)"
            
            # 检测调试器是否崩溃
            if "DebuggerProcessExitedError" in result or "LLDB process has exited" in result:
                # 尝试自愈
                from tools.debugger.driver import debugger_respawn
                debugger_respawn()
                
                # 重新运行到断点
                file = suspect_object["file"]
                line = suspect_object.get("line", 0)
                if file and line:
                     debugger_run_to_line(file, line)
                     
                # 重试一次
                result = debugger_print(expression)
                return result

            return result

        except Exception as e:

            return f"Error printing value: {str(e)}. Debugger may not be at a breakpoint."

    

    def constraint_backtrace() -> str:

        """Get the call stack (backtrace) showing the current function and all calling functions."""

        try:

            frames = debugger_backtrace()

            return "\n".join(frames) if frames else "No backtrace available."

        except Exception as e:

            return f"Error getting backtrace: {str(e)}"

    

    def constraint_definition(symbol: str) -> str:

        """Get the definition of a symbol in the code."""

        try:

            return lsp_get_symbol_definition(file, line, symbol)

        except Exception as e:

            return f"Error getting definition: {str(e)}"

    

    def constraint_summary(symbol: str) -> str:

        """Get the summary/hover information of a symbol."""

        try:

            return lsp_get_symbol_summary(file, line, symbol)

        except Exception as e:

            return f"Error getting summary: {str(e)}"

    

    def constraint_function_body(function: str) -> str:

        """Get the complete definition of a function."""

        try:

            return lsp_get_function(file, function)

        except Exception as e:

            return f"Error getting function body: {str(e)}"

    def constraint_search_in_repo(pattern: str, path: str = None, max_hits: int = 20, context: int = 2) -> str:
        """
        Search within a file or directory for a keyword/regex and return line numbers with small context.
        This avoids repeated paging via file_content for large files.
        """
        try:
            search_path = path or file
            if not search_path or not os.path.exists(search_path):
                return f"Error: Path not found for search: {search_path}"

            try:
                max_hits_i = max(1, int(max_hits))
            except Exception:
                max_hits_i = 20
            try:
                ctx_i = max(0, int(context))
            except Exception:
                ctx_i = 2

            try:
                rx = re.compile(str(pattern))
            except re.error:
                rx = re.compile(re.escape(str(pattern)))

            source_exts = {
                ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx",
                ".inl", ".inc", ".ipp", ".m", ".mm", ".s", ".S",
            }

            def iter_candidate_files(root: str):
                if os.path.isfile(root):
                    yield root
                    return
                for dirpath, dirnames, filenames in os.walk(root):
                    dirnames[:] = [
                        dirname for dirname in dirnames
                        if dirname not in {".git", "build", "cmake-build-debug", "cmake-build-release", "__pycache__"}
                    ]
                    for filename in sorted(filenames):
                        file_path = os.path.join(dirpath, filename)
                        _, ext = os.path.splitext(filename)
                        if ext in source_exts or filename in {"Makefile", "CMakeLists.txt"}:
                            yield file_path

            out = [f"Search path: {search_path}", f"Pattern: {pattern}", f"Showing up to {max_hits_i} matches", ""]
            total_hits = 0
            for file_path in iter_candidate_files(search_path):
                try:
                    with open(file_path, "r", errors="ignore") as f:
                        lines = f.readlines()
                except Exception:
                    continue

                hits = []
                for idx, line_text in enumerate(lines, start=1):
                    if rx.search(line_text):
                        hits.append(idx)
                        total_hits += 1
                        if total_hits >= max_hits_i:
                            break

                for h in hits:
                    start = max(1, h - ctx_i)
                    end = min(len(lines), h + ctx_i)
                    out.append(f"--- {file_path}:{h} ---")
                    for ln in range(start, end + 1):
                        prefix = ">>" if ln == h else "  "
                        out.append(f"{prefix} L{ln}: {lines[ln-1].rstrip()}")
                    out.append("")

                if total_hits >= max_hits_i:
                    break

            if total_hits == 0:
                return f"No matches for pattern '{pattern}' under {search_path}"

            out.insert(2, f"Hits: {total_hits}")
            return "\n".join(out).strip()
        except Exception as e:
            return f"Error searching repo: {e}"

    def submit_constraint(constraint: str) -> str:
        """Submit the generated constraint expression. Call this after you have finished exploring the code and generated a constraint."""
        _submitted_constraint_container[0] = constraint.strip()
        logger.info(f"Constraint agent submitted constraint: {constraint}")
        return f"Constraint submitted successfully: {constraint}. Your task is complete. You MUST reply with TERMINATE."

    

    # Register all tools

    agent.register_hook(constraint_file_content, 

                      "Get the content of a file for code analysis. Use this to examine code context around variables and control flow.")

    agent.register_hook(constraint_print_value, 

                      "Print the value of an expression at the current debugger stop (if available). Use this to inspect variable values.")

    agent.register_hook(constraint_backtrace, 

                      "Get the call stack (backtrace) showing the current function and all calling functions. Use this to understand the execution context.")

    agent.register_hook(constraint_definition, 

                      "Get the definition of a symbol in the code. Use this to understand variable types and declarations.")

    agent.register_hook(constraint_summary, 

                      "Get the summary/hover information of a symbol. Use this to get quick information about variables or functions.")

    agent.register_hook(constraint_function_body, 

                      "Get the complete definition of a function. Use this to analyze function logic and understand control flow.")

    agent.register_hook(constraint_search_in_repo,

                      "Search for a keyword/regex under a file or directory path and return matching line numbers with small context. Use this to find symbols, assignments, guards, and function references before paging large files with file_content.")

    agent.register_hook(submit_constraint,

                      "Submit the generated constraint expression. Call this after you have finished exploring the code context and generated a constraint. The constraint should be a valid C boolean expression that separates angelic (safe) values from demonic (unsafe) values.")

    
    # Return both agent and a getter function for submitted constraint
    # We'll need to modify the caller to handle this
    # For now, store in a way that can be accessed
    agent._submitted_constraint_container = _submitted_constraint_container
    return agent
