from utils.logger import get_logger

class LLMHelper:
    """
    A helper class to encapsulate complex LLM interactions for robustness.
    """
    def __init__(self, llm_agent):
        self.llm = llm_agent
        self.logger = get_logger("llm-helper")

    def _query(self, prompt: str) -> str | None:
        """Helper to perform a single-turn query using the GenericAgent."""
        try:
            # Use the agent's chat mechanism for a single query
            chat_log = self.llm.initiate(prompt)
            # The response should be in the last message from the assistant in history
            history = chat_log.get("history", [])
            if history:
                response = history[-1].get("content", "")
                return response
            return None
        except Exception as e:
            self.logger.error(f"LLM query failed: {e}")
            return None

    def resolve_variable_type(self, var_name: str, error_message: str, code_context: str) -> str | None:
        """
        Attempts to determine the correct type of a variable after a debugger assignment error.
        """
        self.logger.info(f"Attempting to resolve type for variable '{var_name}' after assignment error.")
        
        prompt = (
            "You are a C/C++ debugging expert. Your task is to determine the correct type of a variable "
            "based on a debugger error and the surrounding code.\n"
            "Context:\n"
            f"- Variable Name: `{var_name}`\n"
            f"- LLDB Assignment Error: `{error_message}`\n"
            "- Surrounding Code:\n"
            f"```c\n{code_context}\n```\n\n"
            "The error message indicates that the previous assumed type was incorrect. Analyze the error and the code "
            "to infer the most likely correct C/C++ type for this variable.\n"
            "Provide only the type string itself, without any explanation (e.g., 'int', 'char *', 'unsigned long').\n"
            "After providing the type, you MUST reply with the single word TERMINATE.\n\n"
            "Correct Type:"
        )

        response = self._query(prompt)
        if response:
            # The response might contain the type and the terminate signal.
            # We need to extract just the type.
            corrected_type = response.replace("TERMINATE", "").strip().replace("`", "")
            self.logger.info(f"LLM proposed corrected type: '{corrected_type}' for variable '{var_name}'.")
            return corrected_type
        return None

    def validate_and_simplify_constraint(self, constraint: str, context: dict) -> str:
        """
        Validates that a string is a valid C boolean expression and simplifies it.
        """
        self.logger.info(f"Validating and simplifying constraint: '{constraint}'")

        prompt = (
            "You are a C/C++ expert. Your task is to validate and simplify a boolean expression.\n"
            "Context:\n"
            f"- Original Expression: `{constraint}`\n"
            f"- Available Variables: `{list(context.keys())}`\n\n"
            "Analyze the original expression. Is it a valid C/C++ boolean expression?\n"
            "1. If it is valid and simple, return it as is.\n"
            "2. If it is valid but can be simplified, return the simplified version.\n"
            "3. If it contains syntax errors, fix them and return the corrected version.\n"
            "4. If it contains explanatory text, remove it.\n\n"
            "Provide only the final, valid C/C++ boolean expression, without any explanation.\n"
            "After providing the expression, you MUST reply with the single word TERMINATE.\n\n"
            "Final Expression:"
        )
        
        response = self._query(prompt)
        if response:
            clean_constraint = response.replace("TERMINATE", "").strip().replace("`", "")
            if clean_constraint != constraint:
                self.logger.info(f"Constraint was refined from '{constraint}' to '{clean_constraint}'.")
            return clean_constraint
        
        # Fallback to the original constraint on error
        return constraint

    def find_upstream_variable(self, var_name: str, file: str, line: int, function_body: str, error_message: str) -> tuple[str | None, int | None]:
        """
        Finds an upstream variable that can be modified to affect the const variable.
        Returns (upstream_var_name, upstream_line) or (None, None) if not found.
        """
        self.logger.info(f"Attempting to find upstream variable for const variable '{var_name}' at {file}:{line}")
        
        prompt = (
            "You are a C/C++ code analysis expert. Your task is to find an upstream variable that can be modified "
            "to affect a const-qualified variable that cannot be directly assigned.\n"
            "Context:\n"
            f"- Const Variable Name: `{var_name}`\n"
            f"- Current Location: `{file}:{line}`\n"
            f"- Assignment Error: `{error_message}`\n"
            "- Full Function Body:\n"
            f"```c\n{function_body}\n```\n\n"
            "Analyze the function body to find:\n"
            "1. The variable(s) that are used to compute or assign the value to `{var_name}`\n"
            "2. The earliest line number where such a variable can be modified (before it's used to set `{var_name}`)\n\n"
            "Consider:\n"
            "- Function parameters that are passed to compute the const variable\n"
            "- Intermediate variables that are assigned before being used\n"
            "- Variables in earlier assignments or function calls\n\n"
            "If you find a suitable upstream variable, provide:\n"
            "1. The variable name (as it appears in the code, with proper scope resolution like `param_name` or `struct_ptr->field`)\n"
            "2. The line number where it can be modified (must be before line {line})\n\n"
            "Provide your answer in this exact format (one per line, no extra text):\n"
            "UPSTREAM_VAR: <variable_name>\n"
            "UPSTREAM_LINE: <line_number>\n\n"
            "If you cannot find a suitable upstream variable, respond with:\n"
            "UPSTREAM_VAR: None\n"
            "UPSTREAM_LINE: None\n\n"
            "After providing your answer, you MUST reply with the single word TERMINATE.\n\n"
            "Analysis:"
        )

        response = self._query(prompt)
        if not response:
            return None, None

        # Parse the response
        upstream_var = None
        upstream_line = None
        
        for line in response.split('\n'):
            line = line.strip()
            if line.startswith('UPSTREAM_VAR:'):
                upstream_var = line.replace('UPSTREAM_VAR:', '').strip()
                if upstream_var.lower() == 'none':
                    upstream_var = None
            elif line.startswith('UPSTREAM_LINE:'):
                line_str = line.replace('UPSTREAM_LINE:', '').strip()
                if line_str.lower() != 'none':
                    try:
                        upstream_line = int(line_str)
                    except ValueError:
                        self.logger.warning(f"Could not parse upstream line number: {line_str}")
                        upstream_line = None

        if upstream_var and upstream_line:
            self.logger.info(f"Found upstream variable '{upstream_var}' at line {upstream_line} for const variable '{var_name}'")
            return upstream_var, upstream_line
        else:
            self.logger.warning(f"Could not find upstream variable for const variable '{var_name}'")
            return None, None

    def resolve_reference_type(self, var_name: str, var_type: str, code_context: str, error_message: str) -> tuple[str | None, str | None]:
        """
        Resolves a reference type to find the original variable or an alternative assignment method.
        Returns (target_var_name, assignment_expression) or (None, None).
        
        For const references like 'const uint32_t &', this tries to find:
        1. The original variable being referenced
        2. An alternative way to modify the value (e.g., through the original variable)
        """
        self.logger.info(f"Attempting to resolve reference type for '{var_name}' of type '{var_type}'")
        
        prompt = (
            "You are a C/C++ debugging expert. Your task is to resolve a reference type variable "
            "to enable its modification in a debugger.\n"
            "Context:\n"
            f"- Variable Name: `{var_name}`\n"
            f"- Variable Type: `{var_type}`\n"
            f"- Assignment Error: `{error_message}`\n"
            "- Surrounding Code:\n"
            f"```c\n{code_context}\n```\n\n"
            "Analyze the code to determine:\n"
            "1. If this is a reference type (contains '&'), find the original variable it references\n"
            "2. For const references, find where the original variable was assigned or passed\n"
            "3. Suggest an alternative assignment expression that might work (e.g., modifying the original variable)\n\n"
            "Provide your answer in this exact format:\n"
            "TARGET_VAR: <variable_name_or_expression>\n"
            "ASSIGN_EXPR: <assignment_expression_or_None>\n\n"
            "Examples:\n"
            "- If `pe_offset` is `const uint32_t &pe_offset = some_var`, then TARGET_VAR: some_var\n"
            "- If you cannot find a way, respond with: TARGET_VAR: None, ASSIGN_EXPR: None\n\n"
            "After providing your answer, you MUST reply with the single word TERMINATE.\n\n"
            "Analysis:"
        )

        response = self._query(prompt)
        if not response:
            return None, None

        target_var = None
        assign_expr = None

        for line in response.split('\n'):
            line = line.strip()
            if line.startswith('TARGET_VAR:'):
                target_var = line.replace('TARGET_VAR:', '').strip()
                if target_var.lower() == 'none':
                    target_var = None
            elif line.startswith('ASSIGN_EXPR:'):
                assign_expr = line.replace('ASSIGN_EXPR:', '').strip()
                if assign_expr.lower() == 'none':
                    assign_expr = None

        if target_var:
            self.logger.info(f"Resolved reference '{var_name}' to target variable '{target_var}'")
            return target_var, assign_expr
        else:
            self.logger.warning(f"Could not resolve reference type for '{var_name}'")
            return None, None
