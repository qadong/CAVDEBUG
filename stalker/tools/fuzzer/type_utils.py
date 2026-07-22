"""
Type-related utility functions for fuzzer engine.
"""
from tools.debugger.functions import debugger_run_to_line, debugger_get_type
from utils.logger import get_logger
from .mutators.int import IntMutator
from .mutators.pointer import PointerMutator
from .handles import should_skip_debugger_type_probe


def get_actual_variable_type(suspect_object: dict, logger=None) -> str:
    """
    Get the actual variable type directly from the debugger using ptype.
    This is more accurate than LLM inference.
    """
    if logger is None:
        logger = get_logger("fuzzer-engine")
    
    var_name = suspect_object.get("variable_names", [None])[0]
    if not var_name:
        logger.warning("No variable name found in suspect_object. Cannot get type from debugger.")
        return "unknown"
    
    file = suspect_object.get("file")
    line = suspect_object.get("line")
    
    if not file or not line:
        logger.warning(f"Missing file or line in suspect_object. Cannot run to breakpoint to get type.")
        return "unknown"

    fallback = (suspect_object.get("llm_inferred_type") or "").strip()
    if should_skip_debugger_type_probe(suspect_object):
        logger.info(f"Skipping debugger type probe for '{var_name}' and using inferred type: '{fallback}'")
        return fallback or "unknown"
    
    try:
        # First, run to the breakpoint to ensure we're at the right location
        logger.info(f"Running to breakpoint at {file}:{line} to get variable type...")
        lldb_output, _ = debugger_run_to_line(file, line)
        
        if lldb_output.get("reason") != "breakpoint-hit":
            logger.warning(f"Failed to hit breakpoint. Cannot get variable type. Reason: {lldb_output.get('reason')}")
            return "unknown"
        
        # Now get the type using ptype
        logger.info(f"Getting type for variable '{var_name}' using ptype...")
        actual_type = debugger_get_type(var_name)
        
        if actual_type and actual_type != "unknown":
            logger.info(f"Successfully got type from debugger: '{actual_type}'")
            return actual_type
        else:
            logger.warning(f"Failed to get type from debugger for '{var_name}'. Result: '{actual_type}'")
            if fallback and fallback.lower() != "unknown":
                logger.info(f"Using llm_inferred_type fallback for '{var_name}': '{fallback}'")
                return fallback
            return "unknown"
            
    except Exception as e:
        logger.error(f"Exception while getting variable type from debugger: {e}")
        return "unknown"


def get_mutator(var_type: str, mutator_cache: dict, logger=None):
    """Factory function to select the appropriate mutator."""
    if logger is None:
        logger = get_logger("fuzzer-engine")
    
    var_type_lower = var_type.lower()
    
    # Normalize reference types: remove 'const', '&', and 'volatile' qualifiers
    # to get the underlying type for mutator selection
    normalized_type = var_type_lower
    normalized_type = normalized_type.replace('const', '').replace('volatile', '').replace('&', '').strip()
    
    if var_type_lower in mutator_cache:
        return mutator_cache[var_type_lower]

    mutator = None
    if '*' in normalized_type:
        logger.info(f"Selected PointerMutator for type: {var_type}")
        mutator = PointerMutator(logger)
    elif 'int' in normalized_type or 'size_t' in normalized_type or 'char' in normalized_type:
        logger.info(f"Selected IntMutator for type: {var_type} (normalized: {normalized_type})")
        mutator = IntMutator(logger)
    else:
        logger.warning(f"No specific mutator for type '{var_type}'. Falling back to IntMutator.")
        mutator = IntMutator(logger)
        
    mutator_cache[var_type_lower] = mutator
    return mutator












