import re
from .base import MutatorBase
from utils.seed_records import angelic_seed_records

class IntMutator(MutatorBase):
    """
    Generates intelligent candidate values for integer-like types.
    Uses context-aware strategies to generate meaningful mutation candidates.
    """
    
    def _parse_integer(self, value_str: str) -> int | None:
        """Extract integer value from various formats like debugger output."""
        if not isinstance(value_str, str):
            return None
        
        # Try to extract number from strings like "(uint32_t) $8 = 4294967295"
        # First, try to match the value after "=" (most reliable for debugger output)
        match = re.search(r'=\s*(-?\d+)', value_str)
        if match:
            try:
                return int(match.group(1))
            except (ValueError, TypeError):
                pass
        
        # Fallback: match the last large number in the string (for cases without "=")
        # This handles cases where the format is different
        matches = list(re.finditer(r'(-?\d+)', value_str))
        if matches:
            # Try to find a large number (likely the actual value, not type info like "32" in "uint32_t")
            for match in reversed(matches):  # Start from the end (last number is usually the value)
                try:
                    val = int(match.group(1))
                    # If the number is large (>1000) or negative, it's likely the actual value
                    # Small positive numbers might be type info (like "32" in "uint32_t")
                    if abs(val) > 1000 or val < 0:
                        return val
                    # For small numbers, check if it appears after "=" or at the end
                    match_str = match.group(0)
                    if '=' in value_str and value_str.find('=') < value_str.find(match_str):
                        return val
                except (ValueError, TypeError):
                    continue
        
        return None
    
    def _detect_type_bounds(self, var_type: str) -> tuple[int | None, int | None]:
        """
        Detect type boundaries based on variable type.
        Returns (min_bound, max_bound) or (None, None) if unknown.
        """
        var_type_lower = var_type.lower()
        
        # Remove const, volatile, & qualifiers
        normalized = var_type_lower.replace('const', '').replace('volatile', '').replace('&', '').strip()
        
        # uint32_t, unsigned int, u_int32_t
        if 'uint32' in normalized or ('unsigned' in normalized and 'int' in normalized and 'long' not in normalized):
            return (0, 0xFFFFFFFF)  # 4294967295
        
        # int32_t, int (usually 32-bit)
        if 'int32' in normalized or ('int' in normalized and 'unsigned' not in normalized and 'long' not in normalized):
            return (-0x80000000, 0x7FFFFFFF)  # -2147483648 to 2147483647
        
        # uint16_t, unsigned short
        if 'uint16' in normalized or ('unsigned' in normalized and 'short' in normalized):
            return (0, 0xFFFF)  # 65535
        
        # int16_t, short
        if 'int16' in normalized or ('short' in normalized and 'unsigned' not in normalized):
            return (-0x8000, 0x7FFF)  # -32768 to 32767
        
        # uint64_t, unsigned long long
        if 'uint64' in normalized or ('unsigned' in normalized and 'long' in normalized):
            return (0, None)  # No practical max for testing
        
        # int64_t, long long
        if 'int64' in normalized or ('long' in normalized and 'unsigned' not in normalized):
            return (None, None)  # Too large for practical testing
        
        # size_t (usually unsigned, platform-dependent)
        if 'size_t' in normalized:
            return (0, None)
        
        return (None, None)
    
    def _extract_size_from_context(self, context_vars: dict, size_vars: dict) -> int | None:
        """Extract a size value from context or size variables."""
        # First, try explicit size variables
        for size_var, size_val in size_vars.items():
            size = self._parse_integer(str(size_val))
            if size is not None and 0 < size < 65536:  # Reasonable size limit
                self.logger.info(f"Found size from size_variables: {size_var} = {size}")
                return size
        
        # Then, try context variables with size/len in name
        for ctx_var, ctx_val in context_vars.items():
            if "size" in ctx_var.lower() or "len" in ctx_var.lower():
                size = self._parse_integer(str(ctx_val))
                if size is not None and 0 < size < 65536:
                    self.logger.info(f"Found size from context: {ctx_var} = {size}")
                    return size
        
        return None
    
    def _generate_boundary_candidates(self, demonic_value: int, type_min: int | None, type_max: int | None) -> set:
        """Generate candidates around type boundaries and demonic value."""
        candidates = set()
        
        # Boundary values for common integer types
        common_boundaries = [0, 1, -1, 127, 128, 255, 256, 1024, 4096]
        candidates.update([b for b in common_boundaries if type_min is None or b >= type_min])
        candidates.update([b for b in common_boundaries if type_max is None or b <= type_max])
        
        # Type-specific boundaries
        if type_max == 0xFFFFFFFF:  # uint32_t
            # Near upper bound (potential overflow cases)
            candidates.update([
                0xFFFFFFFF - 4,  # Common offset that might cause overflow
                0xFFFFFFFF - 1,
                0xFFFFFFFF,
            ])
        elif type_max == 0x7FFFFFFF:  # int32_t
            candidates.update([
                0x7FFFFFFF - 1,
                0x7FFFFFFF,
                -0x80000000,
                -0x80000000 + 1,
            ])
        
        # Explore around demonic value (boundary region)
        # Generate candidates in a focused range around demonic value
        if demonic_value is not None:
            # Close neighbors (±10 for fine-grained search)
            for offset in range(-10, 11):
                val = demonic_value + offset
                if (type_min is None or val >= type_min) and (type_max is None or val <= type_max):
                    candidates.add(val)
            
            # Medium range (±100 with step)
            for offset in range(-100, 101, 10):
                if offset == 0:
                    continue
                val = demonic_value + offset
                if (type_min is None or val >= type_min) and (type_max is None or val <= type_max):
                    candidates.add(val)
            
            # Large jumps (for far boundaries)
            for offset in [1000, 10000, 100000, -1000, -10000, -100000]:
                val = demonic_value + offset
                if (type_min is None or val >= type_min) and (type_max is None or val <= type_max):
                    candidates.add(val)
        
        return candidates
    
    def _generate_angelic_demonic_range_candidates(
        self, 
        demonic_value: int | None, 
        angelic_values: list[int],
        size_limit: int | None
    ) -> set:
        """Generate candidates in the range between angelic and demonic values."""
        candidates = set()
        
        if not angelic_values:
            return candidates
        
        # Parse angelic values to integers
        angelic_ints = sorted([a for a in angelic_values if a is not None])
        
        if not angelic_ints:
            return candidates
        
        min_angelic = min(angelic_ints)
        max_angelic = max(angelic_ints)
        
        # Strategy 1: Explore between min_angelic and demonic
        if demonic_value is not None and demonic_value > max_angelic:
            # Binary search-like candidates between max_angelic and demonic
            gap = demonic_value - max_angelic
            
            # Generate candidates in the gap
            if gap <= 100:
                # Small gap: test all values
                for val in range(max_angelic, demonic_value):
                    candidates.add(val)
            else:
                # Large gap: sample strategically
                # Start with binary search points
                step = max(1, gap // 20)  # ~20 samples
                for val in range(max_angelic, demonic_value, step):
                    candidates.add(val)
                # Add values just before demonic (critical boundary)
                for offset in range(1, min(20, gap)):
                    candidates.add(demonic_value - offset)
        
        # Strategy 2: Extend beyond max_angelic (to find upper bound)
        if demonic_value is not None:
            # Test values just above max_angelic
            for offset in range(1, min(100, max(10, demonic_value - max_angelic))):
                val = max_angelic + offset
                if size_limit is None or val <= size_limit:
                    candidates.add(val)
        
        # Strategy 3: Explore below min_angelic (might be negative)
        if min_angelic > 0:
            # Test values below min_angelic
            for offset in range(1, min(min_angelic + 1, 100)):
                candidates.add(min_angelic - offset)
        
        return candidates
    
    def _generate_size_aware_candidates(self, size_value: int, demonic_value: int | None) -> set:
        """Generate candidates based on size constraints."""
        candidates = set()
        
        # Size-related boundaries
        candidates.update([
            0,
            size_value - 4,  # Common offset pattern
            size_value - 1,
            size_value,
        ])
        
        # If demonic value is close to or exceeds size, explore that region
        if demonic_value is not None:
            if demonic_value >= size_value:
                # Explore boundary around size
                for offset in range(-10, 11):
                    val = size_value + offset
                    if val >= 0:
                        candidates.add(val)
            
            # Common patterns: size - offset (for safe access)
            for offset in [4, 8, 16, 32]:
                if size_value > offset:
                    candidates.add(size_value - offset)
        
        return candidates
    
    def generate_candidates(self, suspect_object: dict) -> set:
        candidates = set()
        
        # Extract inputs
        demonic_value_str = str(next(iter(self._available_seed_values(suspect_object)), None))
        v0 = (suspect_object.get("variable_names") or [None])[0]
        known_angelic = [
            record["value"]
            for record in angelic_seed_records(suspect_object)
            if v0 is None or record["variable"] == v0
        ]
        context_vars = suspect_object.get("context_variables", {})
        size_vars = suspect_object.get("size_variables", {})
        var_type = (suspect_object.get("llm_inferred_type") or 
                   suspect_object.get("debugger_reported_type") or 
                   "unknown")
        
        # Parse values
        demonic_value = self._parse_integer(demonic_value_str) if demonic_value_str else None
        angelic_ints = []
        for av in known_angelic:
            parsed = self._parse_integer(str(av))
            if parsed is not None:
                angelic_ints.append(parsed)
        
        # Detect type boundaries
        type_min, type_max = self._detect_type_bounds(var_type)
        if type_min is not None or type_max is not None:
            self.logger.info(f"Detected type bounds for '{var_type}': min={type_min}, max={type_max}")
        
        # Extract size from context
        size_limit = self._extract_size_from_context(context_vars, size_vars)
        
        # Strategy 1: Boundary and magic numbers
        boundary_candidates = self._generate_boundary_candidates(demonic_value, type_min, type_max)
        candidates.update(boundary_candidates)
        self.logger.debug(f"Generated {len(boundary_candidates)} boundary candidates")
        
        # Strategy 2: Size-aware candidates (if we have a size limit)
        if size_limit is not None:
            size_candidates = self._generate_size_aware_candidates(size_limit, demonic_value)
            candidates.update(size_candidates)
            self.logger.debug(f"Generated {len(size_candidates)} size-aware candidates")
        
        # Strategy 3: Angelic-Demonic range exploration
        if demonic_value is not None and angelic_ints:
            range_candidates = self._generate_angelic_demonic_range_candidates(
                demonic_value, angelic_ints, size_limit
            )
            candidates.update(range_candidates)
            self.logger.debug(f"Generated {len(range_candidates)} range candidates between angelic and demonic")
        
        # Strategy 4: Context variable values
        for ctx_var, ctx_val in context_vars.items():
            ctx_int = self._parse_integer(str(ctx_val))
            if ctx_int is not None:
                # Add context value and nearby values
                candidates.add(ctx_int)
                if ctx_int > 0:
                    candidates.add(ctx_int - 1)
                candidates.add(ctx_int + 1)
        
        # Filter candidates by type bounds
        filtered_candidates = set()
        for val in candidates:
            if (type_min is None or val >= type_min) and (type_max is None or val <= type_max):
                filtered_candidates.add(val)
            elif type_min is None and type_max is None:
                # Unknown type, include all
                filtered_candidates.add(val)
        
        # Remove demonic value itself (we already know it's bad)
        if demonic_value is not None:
            filtered_candidates.discard(demonic_value)
        
        self.logger.info(f"Generated {len(filtered_candidates)} total candidates for type '{var_type}' "
                        f"(demonic={demonic_value}, angelic={angelic_ints}, size_limit={size_limit})")
        
        return filtered_candidates
