"""
Filtering module for angelic values.
"""

from utils.seed_records import demonic_seed_records, record_values

def filter_angelic_outliers(angelic_values: list, suspect_object: dict, logger=None) -> list:
    """
    Filter out angelic values caused by:
    1. Integer truncation/overflow (e.g., 2^32-1, 2^31-1 for uint32_t/int32_t)
    2. Statistical outliers ("lucky" out-of-bounds reads)
    
    Args:
        angelic_values: List of angelic value strings
        suspect_object: Suspect object containing variable type information
    
    Returns:
        Filtered list of angelic values
    """
    if not angelic_values or len(angelic_values) < 3:
        # Need at least 3 values to detect outliers statistically
        return angelic_values
    
    # Convert to integers for processing
    angelic_ints = []
    value_to_str = {}  # Map integer back to original string representation
    
    for val_str in angelic_values:
        try:
            # Try to parse as integer
            val_int = int(val_str)
            angelic_ints.append(val_int)
            value_to_str[val_int] = val_str
        except (ValueError, TypeError):
            # If not a number, keep it (e.g., "NULL", addresses)
            angelic_ints.append(None)
            continue
    
    if len(angelic_ints) < 3:
        return angelic_values
    
    filtered_ints = []
    filtered_original = []
    
    # Get variable type to determine type boundaries
    var_type = (suspect_object.get("debugger_reported_type") or 
               suspect_object.get("llm_inferred_type") or 
               "unknown")
    var_type_lower = var_type.lower().replace(" ", "")
    
    # Define type boundaries for common integer types
    TYPE_BOUNDARIES = {
        # Unsigned types
        "uint8_t": (0, 2**8 - 1),
        "unsignedchar": (0, 2**8 - 1),
        "u8": (0, 2**8 - 1),
        "uint16_t": (0, 2**16 - 1),
        "unsignedshort": (0, 2**16 - 1),
        "u16": (0, 2**16 - 1),
        "uint32_t": (0, 2**32 - 1),
        "unsignedint": (0, 2**32 - 1),
        "unsigned": (0, 2**32 - 1),
        "u32": (0, 2**32 - 1),
        "uint64_t": (0, 2**64 - 1),
        "unsignedlong": (0, 2**64 - 1),
        "u64": (0, 2**64 - 1),
        # Signed types
        "int8_t": (-2**7, 2**7 - 1),
        "char": (-2**7, 2**7 - 1),
        "int16_t": (-2**15, 2**15 - 1),
        "short": (-2**15, 2**15 - 1),
        "int32_t": (-2**31, 2**31 - 1),
        "int": (-2**31, 2**31 - 1),
        "int64_t": (-2**63, 2**63 - 1),
        "long": (-2**63, 2**63 - 1),
    }
    
    # Find matching type boundary
    type_min, type_max = None, None
    for type_name, (min_val, max_val) in TYPE_BOUNDARIES.items():
        if type_name in var_type_lower:
            type_min, type_max = min_val, max_val
            break
    
    # Filter 1: Remove type boundary values (truncation/overflow indicators)
    # These are often false positives from integer truncation
    boundary_values = set()
    if type_max is not None:
        # Check for values near type boundaries (within 10000 of the max for large types)
        # For uint32_t (2^32-1 = 4294967295), check values >= 2^32 - 10000
        boundary_threshold = 10000 if type_max > 1000000 else 5
        for val_int in angelic_ints:
            if val_int is not None:
                # Check if value is near type maximum (truncation)
                if type_max - boundary_threshold <= val_int <= type_max:
                    boundary_values.add(val_int)
                    logger.warning(f"Discarding angelic value {val_int} (near type boundary {type_max}, likely truncation/overflow)")
                
                # Check for values near type minimum (for signed types)
                if type_min is not None and type_min <= val_int <= type_min + boundary_threshold:
                    boundary_values.add(val_int)
                    logger.warning(f"Discarding angelic value {val_int} (near type boundary {type_min}, likely truncation/overflow)")
    
    # Common truncation patterns (even if type is unknown)
    # Values that are 2^n - 1, 2^n - 2, etc. are often truncation artifacts
    truncation_patterns = [
        2**8 - 1, 2**8 - 2, 2**8 - 3, 2**8 - 4, 2**8 - 5,  # uint8_t boundary
        2**16 - 1, 2**16 - 2, 2**16 - 3, 2**16 - 4, 2**16 - 5,  # uint16_t boundary
        2**32 - 1, 2**32 - 2, 2**32 - 3, 2**32 - 4, 2**32 - 5,  # uint32_t boundary
        2**31 - 1, 2**31 - 2, 2**31 - 3,  # int32_t max boundary
    ]
    
    for val_int in angelic_ints:
        if val_int is not None and val_int in truncation_patterns:
            if val_int not in boundary_values:  # Avoid duplicate logging
                boundary_values.add(val_int)
                logger.warning(f"Discarding angelic value {val_int} (matches truncation pattern, likely integer overflow)")
    
    # Filter 1.5: Detect large values near 2^32 (even if not exact boundary match)
    # Values in range [2^32 - 100000, 2^32] are likely truncation artifacts
    for val_int in angelic_ints:
        if val_int is not None:
            # Check for values close to 2^32 (uint32_t overflow range)
            if 2**32 - 100000 <= val_int <= 2**32:
                if val_int not in boundary_values:
                    boundary_values.add(val_int)
                    logger.warning(f"Discarding angelic value {val_int} (near 2^32, likely uint32_t truncation/overflow)")
            
            # Check for values close to 2^31 (int32_t max overflow range)
            if 2**31 - 100000 <= val_int <= 2**31:
                if val_int not in boundary_values:
                    boundary_values.add(val_int)
                    logger.warning(f"Discarding angelic value {val_int} (near 2^31, likely int32_t truncation/overflow)")
    
    # Filter 2: Statistical outlier detection using IQR (Interquartile Range)
    # Remove values that are statistical outliers (likely "lucky" reads)
    valid_ints = [v for v in angelic_ints if v is not None and v not in boundary_values]
    
    if len(valid_ints) >= 4:  # Need at least 4 values for IQR
        sorted_ints = sorted(valid_ints)
        n = len(sorted_ints)
        
        # Calculate quartiles
        q1_idx = n // 4
        q3_idx = (3 * n) // 4
        q1 = sorted_ints[q1_idx]
        q3 = sorted_ints[q3_idx]
        iqr = q3 - q1
        
        if iqr > 0:  # Avoid division by zero
            # Use 1.5 * IQR as the outlier threshold (standard IQR method)
            # But be more aggressive for large gaps
            lower_bound = q1 - 1.5 * iqr
            upper_bound = q3 + 1.5 * iqr
            
            # Check ALL values that are outliers, not just min/max
            for val_int in valid_ints:
                if val_int not in boundary_values:
                    is_outlier = False
                    reason = ""
                    
                    # Check if value is above upper bound
                    if val_int > upper_bound:
                        # Check for large gap to previous value
                        idx = sorted_ints.index(val_int)
                        if idx > 0:
                            gap = val_int - sorted_ints[idx - 1]
                            if gap > 5 * iqr:  # Large gap indicates outlier
                                is_outlier = True
                                reason = f"statistical outlier (gap={gap} > 5*IQR={5*iqr}, > upper_bound={upper_bound})"
                            elif val_int > q3 + 3 * iqr:  # Very far from Q3
                                is_outlier = True
                                reason = f"statistical outlier (> 3*IQR from Q3, value={val_int}, Q3={q3}, IQR={iqr})"
                        else:
                            is_outlier = True
                            reason = f"statistical outlier (> upper_bound={upper_bound}, IQR={iqr})"
                    
                    # Check if value is below lower bound
                    elif val_int < lower_bound:
                        idx = sorted_ints.index(val_int)
                        if idx < len(sorted_ints) - 1:
                            gap = sorted_ints[idx + 1] - val_int
                            if gap > 5 * iqr:  # Large gap indicates outlier
                                is_outlier = True
                                reason = f"statistical outlier (gap={gap} > 5*IQR={5*iqr}, < lower_bound={lower_bound})"
                            elif val_int < q1 - 3 * iqr:  # Very far from Q1
                                is_outlier = True
                                reason = f"statistical outlier (< 3*IQR from Q1, value={val_int}, Q1={q1}, IQR={iqr})"
                        else:
                            is_outlier = True
                            reason = f"statistical outlier (< lower_bound={lower_bound}, IQR={iqr})"
                    
                    if is_outlier:
                        boundary_values.add(val_int)
                        logger.warning(f"Discarding angelic value {val_int} ({reason})")
        
        # Additional filter: If most values are in a small range but some are very large/small
        # This catches cases where we have many small values and a few huge outliers
        if len(valid_ints) >= 5:
            # Calculate median and median absolute deviation (MAD) as a robust measure
            median = sorted_ints[n // 2]
            # Calculate MAD
            deviations = [abs(x - median) for x in sorted_ints]
            mad = sorted(deviations)[n // 2] if sorted(deviations)[n // 2] > 0 else 1
            
            # Values that are more than 5 * MAD away from median are likely outliers
            mad_threshold = 5 * mad
            for val_int in valid_ints:
                if val_int not in boundary_values:
                    deviation = abs(val_int - median)
                    if deviation > mad_threshold:
                        # Only filter if the value is significantly larger/smaller than others
                        # and there's a large gap
                        idx = sorted_ints.index(val_int)
                        if idx > 0 and idx < len(sorted_ints) - 1:
                            gap_before = val_int - sorted_ints[idx - 1] if idx > 0 else 0
                            gap_after = sorted_ints[idx + 1] - val_int if idx < len(sorted_ints) - 1 else 0
                            if gap_before > mad_threshold or gap_after > mad_threshold:
                                boundary_values.add(val_int)
                                logger.warning(f"Discarding angelic value {val_int} (MAD outlier, deviation={deviation} > {mad_threshold}, median={median}, MAD={mad})")
    
    # Build filtered list
    filtered_angelic = []
    for val_str in angelic_values:
        try:
            val_int = int(val_str)
            if val_int not in boundary_values:
                filtered_angelic.append(val_str)
        except (ValueError, TypeError):
            # Non-numeric values (e.g., "NULL") are kept
            filtered_angelic.append(val_str)
    
    removed_count = len(angelic_values) - len(filtered_angelic)
    if removed_count > 0:
        logger.info(f"Rule-based filtering: Removed {removed_count} outlier angelic values. Remaining: {len(filtered_angelic)}")
    
    return filtered_angelic



def filter_angelic_values_with_agent(angelic_values: list, suspect_object: dict, profile: dict, logger=None) -> list:
    """Use LLM agent to intelligently filter angelic values."""
    from utils.logger import get_logger
    from agent.generic_agent import GenericAgent
    from tools.file.functions import file_get_decorated_content
    from tools.debugger.functions import debugger_print
    import json
    import re

    if logger is None:
        logger = get_logger("fuzzer-engine")
    """
    Use LLM agent to intelligently filter angelic values based on code context and semantics.
    This complements rule-based filtering by understanding why certain values might be false positives.
    
    Args:
        angelic_values: List of angelic value strings (already rule-filtered)
        suspect_object: Suspect object containing variable information
        profile: Profile containing chat_dir for loading context
    
    Returns:
        Filtered list of angelic values
    """
    if not angelic_values or len(angelic_values) == 0:
        return angelic_values
    
    try:
        # Create a filtering agent
        agent = GenericAgent(
            "AngelicValueFilter",
            system_prompt=(
                "You are a C/C++ security expert specializing in program analysis. "
                "Your task is to filter out false positive 'angelic values' that are likely artifacts of:\n"
                "1. Integer truncation/overflow (e.g., values near 2^32-1 for uint32_t)\n"
                "2. 'Lucky' out-of-bounds reads (values that happened to work but aren't semantically correct)\n"
                "3. Values that don't make semantic sense in the code context\n\n"
                "You have access to debugging tools to understand the code context. "
                "Use these tools to analyze the variable's usage and determine which values are legitimate safe values "
                "versus false positives that should be filtered out."
            )
        )
        
        # Store context for tools
        _filter_context = suspect_object
        _filter_submitted_values = None
        
        # Create tool functions for the agent
        file = suspect_object.get("file")
        line = suspect_object.get("line")
        var_name = suspect_object.get("variable_names", [None])[0]
        var_type = (suspect_object.get("debugger_reported_type") or 
                   suspect_object.get("llm_inferred_type") or 
                   "unknown")
        
        # Get cleaned_demonic_values for context (from the current scope)
        cleaned_demonic_values = list(set(record_values(demonic_seed_records(suspect_object))))
        demonic_values_str = ", ".join([str(v) for v in cleaned_demonic_values[:5]]) if cleaned_demonic_values else "None"
        
        def filter_file_content(start_line: int, end_line: int) -> str:
            """Get code context around the variable usage."""
            content = file_get_decorated_content(file, start_line, end_line)
            if content:
                return f"File: {file}\nLines {start_line}-{end_line}:\n{content}"
            return f"File: {file}\nLines {start_line}-{end_line}: (empty or invalid range)"
        
        def filter_print_value(expression: str) -> str:
            """Print the value of an expression at current breakpoint (if available)."""
            try:
                return debugger_print(expression)
            except Exception as e:
                return f"Error: {str(e)}"
        
        def submit_filtered_values(kept_values: list, removed_values: list = None) -> str:
            """
            Submit the filtered list of angelic values.
            
            Args:
                kept_values: List of values that should be KEPT (legitimate safe values)
                removed_values: Optional list of values that should be REMOVED (with reasons)
            """
            nonlocal _filter_submitted_values  # Allow modifying outer scope variable
            
            # Handle different input formats
            if isinstance(kept_values, str):
                # Try to parse as JSON list
                try:
                    import json
                    kept_values = json.loads(kept_values)
                except:
                    # Try to extract list from string
                    import re
                    match = re.search(r'\[(.*?)\]', kept_values)
                    if match:
                        kept_values = [v.strip().strip('"\'') for v in match.group(1).split(',') if v.strip()]
                    else:
                        kept_values = [kept_values.strip()]
            elif not isinstance(kept_values, list):
                kept_values = [str(kept_values)]
            
            # Convert to strings for consistency
            kept_values = [str(v).strip() for v in kept_values if v is not None and str(v).strip()]
            
            if removed_values:
                if isinstance(removed_values, str):
                    try:
                        import json
                        removed_values = json.loads(removed_values)
                    except:
                        import re
                        match = re.search(r'\[(.*?)\]', removed_values)
                        if match:
                            removed_values = [v.strip().strip('"\'') for v in match.group(1).split(',') if v.strip()]
                        else:
                            removed_values = [removed_values.strip()]
                removed_values = [str(v).strip() for v in removed_values if v is not None and str(v).strip()]
            
            _filter_submitted_values = {
                "kept": kept_values,
                "removed": removed_values if removed_values else []
            }
            logger.info(f"Filter agent submitted: {len(kept_values)} kept, {len(removed_values) if removed_values else 0} removed")
            return f"Filtered values submitted successfully. Kept {len(kept_values)} values, removed {len(removed_values) if removed_values else 0} values."
        
        # Register tools
        agent.register_hook(filter_file_content, 
                          f"Get code context around the variable usage. The variable '{var_name}' is used at {file}:{line}.")
        agent.register_hook(filter_print_value, 
                          "Print the value of an expression at the current debugger stop (if available).")
        agent.register_hook(submit_filtered_values,
                          "**REQUIRED**: Submit the filtered list of angelic values. You MUST call this function to complete the task. "
                          "Parameters: 'kept_values' (list of strings - values to KEEP), 'removed_values' (optional list of strings - values to REMOVE). "
                          "Example: submit_filtered_values(kept_values=['1', '2', '3'], removed_values=['4294967295', '4294907390'])")
        
        # Build prompt with context
        context_vars = suspect_object.get("context_variable_names", [])
        
        prompt = f"""Analyze the following angelic values and filter out false positives.

**Context:**
- Variable: `{var_name}` (type: `{var_type}`) at {file}:{line}
- Demonic values (cause crashes): [{demonic_values_str}{'...' if len(cleaned_demonic_values) > 5 else ''}]
- Context variables: {', '.join(context_vars) if context_vars else 'None'}

**Angelic Values to Filter:**
{angelic_values}

**Your Task:**
1. Use `filter_file_content` to examine the code context around the variable usage (start_line={max(1, line-20)}, end_line={line+10})
2. Analyze which values are:
   - **Legitimate safe values**: Values that make semantic sense and are truly safe (e.g., valid indices, reasonable sizes, meaningful constants)
   - **False positives**: 
     * Integer truncation/overflow artifacts (e.g., 2^32-1, 2^32-2 for uint32_t, values very close to type boundaries)
     * "Lucky" out-of-bounds reads (large values that happened to work but aren't semantically correct)
     * Values that don't make sense in the code context (e.g., -999 when most values are small positive numbers)

3. **CRITICAL**: You MUST call `submit_filtered_values` to submit your filtered results. Do NOT just return text.
   - `kept_values`: List of value strings that should be KEPT (e.g., `['1', '2', '3', '10', '100']`)
   - `removed_values`: Optional list of value strings that should be REMOVED (e.g., `['4294967295', '4294907390']`)
   - All values must be provided as strings matching the original format in the input list
   - After calling `submit_filtered_values`, your task is complete. You MUST reply with TERMINATE.

**Guidelines:**
- Be conservative: If unsure, keep the value (better to have more values than to filter out legitimate ones)
- Focus on filtering obvious false positives:
  * Values very close to type boundaries (e.g., 4294967295, 4294967294 for uint32_t)
  * Extreme outliers that are clearly separate from the main cluster of values
  * Values that don't match the semantic pattern (e.g., if most values are 0-1000, filter out values like 4294907390)
- Consider the variable type and typical value ranges
- Look at the code context to understand what values make semantic sense

**Example:**
If angelic values are: `['1', '2', '3', '10', '100', '4294967295', '4294907390']`
- Call: `submit_filtered_values(kept_values=['1', '2', '3', '10', '100'], removed_values=['4294967295', '4294907390'])`
- Keep: `['1', '2', '3', '10', '100']` (semantic values)
- Remove: `['4294967295', '4294907390']` (near uint32_t boundary, truncation artifacts)

**IMPORTANT**: You MUST call `submit_filtered_values` with the filtered lists. Do NOT just describe the values in text."""
        
        # Execute agent
        chat_result = agent.initiate(prompt)
        
        # Extract filtered values from agent's submission
        # Priority 1: Direct submission via tool (stored in _filter_submitted_values)
        if _filter_submitted_values:
            kept_values = _filter_submitted_values.get("kept", [])
            removed_values = _filter_submitted_values.get("removed", [])
            
            # Validate: Ensure kept_values is not empty
            if not kept_values or len(kept_values) == 0:
                logger.warning("Agent submitted empty kept_values list. This is likely an error. Keeping original values.")
                return angelic_values
            
            # Convert to strings for comparison (normalize format)
            kept_values_str = [str(v).strip() for v in kept_values]
            original_values_str = [str(v).strip() for v in angelic_values]
            
            # Filter the original list: only keep values that agent explicitly said to keep
            filtered = [v for v in angelic_values if str(v).strip() in kept_values_str]
            
            # Validation: Check if all kept values actually exist in original list
            missing_values = [v for v in kept_values_str if v not in original_values_str]
            if missing_values:
                logger.warning(f"Agent kept values that don't exist in original list: {missing_values}. Ignoring them.")
            
            # Safety check: If agent filtered out too many values (>90%), it might be an error
            if len(filtered) < len(angelic_values) * 0.1:
                logger.warning(f"Agent filtered out >90% of values ({len(filtered)}/{len(angelic_values)}). "
                                  "This might be an error. Keeping original values.")
                return angelic_values
            
            # Log results
            if removed_values:
                logger.info(f"Agent-based filtering: Kept {len(filtered)}/{len(angelic_values)} values. "
                               f"Removed: {removed_values}")
            else:
                logger.info(f"Agent-based filtering: Kept {len(filtered)}/{len(angelic_values)} values")
            
            return filtered
        
        # Priority 2: Extract from tool_calls in chat history (similar to constraint agent)
        logger.warning("Filter agent did not submit via direct tool call, trying to extract from chat history...")
        try:
            import json
            history = chat_result.get("history", [])
            for msg in reversed(history):
                if msg.get("role") == "assistant":
                    tool_calls = msg.get("tool_calls", [])
                    for tool_call in tool_calls:
                        func_info = tool_call.get("function", {})
                        if func_info.get("name") == "submit_filtered_values":
                            try:
                                args_str = func_info.get("arguments", "{}")
                                args = json.loads(args_str)
                                kept_values = args.get("kept_values", [])
                                if kept_values and isinstance(kept_values, list):
                                    kept_values_str = [str(v).strip() for v in kept_values]
                                    filtered = [v for v in angelic_values if str(v).strip() in kept_values_str]
                                    if len(filtered) > 0:
                                        logger.info(f"Extracted filtered values from tool_calls: {len(filtered)}/{len(angelic_values)} values")
                                        return filtered
                            except (json.JSONDecodeError, KeyError, AttributeError) as e:
                                logger.debug(f"Failed to parse tool_call arguments: {e}")
        except Exception as e:
            logger.debug(f"Failed to extract from tool_calls: {e}")
        
        # Priority 3: Try to parse agent's text response for a list (fallback)
        try:
            import json
            import re
            history = chat_result.get("history", [])
            for msg in reversed(history):
                content = msg.get("content", "")
                if not content:
                    continue
                
                # Look for patterns like: kept_values: ['1', '2', '3'] or ["1", "2", "3"]
                patterns = [
                    r'kept_values[:\s]*\[(.*?)\]',
                    r'keep[:\s]*\[(.*?)\]',
                    r'\[(.*?)\]',  # Generic list pattern (last resort)
                ]
                
                for pattern in patterns:
                    match = re.search(pattern, content, re.IGNORECASE | re.DOTALL)
                    if match:
                        try:
                            # Try to parse the matched list
                            list_str = f"[{match.group(1)}]"
                            parsed = json.loads(list_str)
                            if isinstance(parsed, list) and len(parsed) > 0:
                                # Assume this is the kept values
                                kept_values_str = [str(p).strip() for p in parsed]
                                filtered = [v for v in angelic_values if str(v).strip() in kept_values_str]
                                if len(filtered) > 0:
                                    logger.info(f"Extracted filtered values from agent text response: {len(filtered)}/{len(angelic_values)} values")
                                    return filtered
                        except (json.JSONDecodeError, ValueError):
                            continue
        except Exception as e:
            logger.debug(f"Failed to extract from text response: {e}")
        
        # Final fallback: keep original values
        logger.warning("Failed to extract filtered values from agent response. Agent may not have called submit_filtered_values properly. Keeping original values.")
        return angelic_values
            
    except Exception as e:
        logger.error(f"Error in agent-based filtering: {e}. Falling back to rule-filtered values.")
        import traceback
        logger.debug(traceback.format_exc())
        return angelic_values
