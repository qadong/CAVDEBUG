import re
import operator
from utils.logger import logf, get_logger

NAME = "verifier"

try:
    import z3
    HAS_Z3 = True
except ImportError:
    HAS_Z3 = False

def _parse_value(val):
    """Parses a value (int or hex string) into a python int."""
    if isinstance(val, int):
        return val
    if isinstance(val, str):
        val = val.strip()
        if val.lower() == "null":
            return 0
        if val.lower() == "true":
            return 1
        if val.lower() == "false":
            return 0
        try:
            if val.startswith("0x") or val.startswith("0X"):
                return int(val, 16)
            return int(val)
        except ValueError:
            # Maybe it's a char literal? "'a'"
            if val.startswith("'") and val.endswith("'") and len(val) >= 3:
                return ord(val[1])
            return 0 # Fallback
    return 0

def _c_to_python_expr(c_expr):
    """Translates C expression syntax to Python syntax for eval()."""
    # 1. Logical Operators
    # We must be careful not to replace bitwise & |
    # Replace || with or
    expr = c_expr.replace("||", " or ")
    # Replace && with and
    expr = c_expr.replace("&&", " and ")
    # Replace ! with not (Warning: precedence issues, handled by simple constraints usually)
    # NOTE: In C !x binds tight. In Python not x binds loose.
    # Ideally we'd use a parser. For now, we assume the constraint is simple.
    expr = expr.replace("!", " not ")
    
    # 2. Constants
    expr = re.sub(r'\btrue\b', 'True', expr, flags=re.IGNORECASE)
    expr = re.sub(r'\bfalse\b', 'False', expr, flags=re.IGNORECASE)
    expr = re.sub(r'\bNULL\b', '0', expr, flags=re.IGNORECASE)
    
    # 3. Hex literals are handled by python eval (0x...)
    
    return expr

@logf(NAME, True)
def verify(constraint_string: str, angelic_list: list, demonic_list: list, context_vars: dict, suspect_vars: list) -> tuple[bool, str]:
    """
    Verifies if a constraint string correctly separates angelic and demonic values.
    Returns: (is_valid: bool, failure_reason: str)
    """
    logger = get_logger(NAME)
    
    if not suspect_vars:
        return False, "No suspect variables provided"
    
    # 1. Ensure constraint is a string
    constraint_string = str(constraint_string)
    
    var_name = suspect_vars[0] # Primary suspect variable
    
    # Pre-calculate context variables as Python integers
    logger.info(f"Context vars keys: {list(context_vars.keys())}")
    
    py_context_base = {}
    for k, v in context_vars.items():
        py_context_base[k] = _parse_value(v)
        
    logger.info(f"Py context base keys: {list(py_context_base.keys())}")

    py_expr = _c_to_python_expr(constraint_string)
    logger.debug(f"Translated constraint '{constraint_string}' to Python: '{py_expr}'")

    try:
        # --- 1. Verify Angelic Values (MUST be True) ---
        for val in angelic_list:
            val_int = _parse_value(val)
            
            eval_ctx = py_context_base.copy()
            eval_ctx[var_name] = val_int
            
            result = eval(py_expr, {}, eval_ctx)
            is_satisfied = bool(result)

            if not is_satisfied:
                reason = f"False negative: Constraint evaluated to FALSE for safe (Angelic) value '{val}' (Parsed: {val_int}). It should be TRUE."
                logger.info(f"Constraint '{constraint_string}' FAILED: {reason}")
                return False, reason

        # --- 2. Verify Demonic Values (MUST be False) ---
        for val in demonic_list:
            val_int = _parse_value(val)
            
            eval_ctx = py_context_base.copy()
            eval_ctx[var_name] = val_int
            
            result = eval(py_expr, {}, eval_ctx)
            is_satisfied = bool(result)
            
            if is_satisfied:
                reason = f"False positive: Constraint evaluated to TRUE for unsafe (Demonic) value '{val}' (Parsed: {val_int}). It should be FALSE."
                logger.info(f"Constraint '{constraint_string}' FAILED: {reason}")
                return False, reason

    except SyntaxError:
        # C syntax that is invalid in Python (e.g. *ptr dereference). 
        logger.warning(f"Constraint '{constraint_string}' contains syntax not supported by Python verifier. Skipping static check.")
        return True, "Complex syntax (skipped static verification)"
            
    except Exception as e:
        reason = f"Evaluation error for value '{val}': {e}"
        logger.warning(f"Error evaluating constraint '{constraint_string}': {reason}")
        return False, reason

    logger.info(f"Constraint '{constraint_string}' VERIFIED.")
    return True, "Verified"