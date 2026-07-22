import re
from .base import MutatorBase
from utils.seed_records import angelic_seed_records

class PointerMutator(MutatorBase):
    """
    Generates candidate values for pointer types using context-aware strategies.
    """
    def _parse_address(self, address_str: str) -> int | None:
        """Parses a hex address string into an integer."""
        if not isinstance(address_str, str):
            return None
        match = re.search(r'(0x[0-9a-fA-F]+)', address_str)
        if not match:
            return None
        try:
            return int(match.group(1), 16)
        except (ValueError, TypeError):
            self.logger.warning(f"Could not parse address from string: '{address_str}'")
            return None

    def generate_candidates(self, suspect_object: dict) -> set:
        candidates = set()

        var_type = (suspect_object.get("llm_inferred_type") or 
                    suspect_object.get("debugger_reported_type") or 
                    "void *")
        if '*' not in var_type:
            var_type = "void *" # Fallback to generic pointer

        demonic_value_str = str(next(iter(self._available_seed_values(suspect_object)), None))
        v0 = (suspect_object.get("variable_names") or [None])[0]
        known_angelic = [
            record["value"]
            for record in angelic_seed_records(suspect_object)
            if v0 is None or record["variable"] == v0
        ]
        context_vars = suspect_object.get("context_variables", {})

        # --- Strategy 1: Special Pointer Values ---
        self.logger.debug("Adding special pointer values (NULL, -1, 1).")
        candidates.update(["NULL", f"({var_type})-1", f"({var_type})1"])

        # --- Strategy 2: Demonic Value Neighborhood ---
        demonic_addr = self._parse_address(demonic_value_str)
        if demonic_addr is not None:
            self.logger.debug(f"Exploring neighborhood around demonic address {hex(demonic_addr)}.")
            # Granular probing: test every byte offset from 1 to 8
            for offset in range(1, 9):
                candidates.add(hex(demonic_addr + offset))
                candidates.add(hex(demonic_addr - offset))

        # --- Strategy 3: Context-Aware Mutations ---
        base_addr = None
        # Prioritize known angelic values as a base for mutation
        if known_angelic:
            base_addr = self._parse_address(known_angelic[0])
            if base_addr:
                self.logger.info(f"Using angelic pointer {hex(base_addr)} as mutation base.")

        # Fallback to other context pointers if no angelic base is found
        if base_addr is None:
            for ctx_val in context_vars.values():
                addr = self._parse_address(ctx_val)
                if addr is not None:
                    base_addr = addr
                    self.logger.info(f"Using context pointer {hex(base_addr)} as mutation base.")
                    break
        
        # If we have a base address, perform boundary and in-bounds testing
        if base_addr is not None:
            # 1. Use explicit size variables from Agent (if provided)
            explicit_sizes = suspect_object.get("size_variables", {})
            for size_var, size_val_str in explicit_sizes.items():
                try:
                    # Value might be like "(int) $1 = 10" or just "10"
                    size_match = re.search(r'(-?\d+)', str(size_val_str))
                    if size_match:
                        size = int(size_match.group(1))
                        self.logger.info(f"Using explicit size variable '{size_var}' with value {size}.")
                        # A) Boundary checks
                        candidates.add(hex(base_addr + size))
                        candidates.add(hex(base_addr - 1))
                        # B) In-bounds checks
                        if size > 0:
                            candidates.add(hex(base_addr))
                            candidates.add(hex(base_addr + size - 1))
                except (ValueError, TypeError):
                    pass

            # 2. Heuristic: Treat any small integer in context as a potential size
            MAX_REASONABLE_SIZE = 4096 
            for ctx_var, ctx_val in context_vars.items():
                try:
                    # Check if the variable name suggests it's a size, or if it's a small integer value
                    is_size_like_name = "size" in ctx_var.lower() or "len" in ctx_var.lower()
                    
                    # Attempt to parse the value as an integer
                    size_val_str = re.search(r'(-?\d+)', str(ctx_val))
                    if not size_val_str:
                        continue
                    
                    size = int(size_val_str.group(1))

                    if is_size_like_name or (0 < size < MAX_REASONABLE_SIZE):
                        self.logger.info(f"Found size-like variable '{ctx_var}' with value {size}. Generating boundary/in-bounds candidates.")
                        
                        # A) Boundary checks (classic off-by-one)
                        candidates.add(hex(base_addr + size))     # Upper bound off-by-one
                        candidates.add(hex(base_addr - 1))         # Lower bound off-by-one

                        # B) In-bounds checks
                        if size > 0:
                            candidates.add(hex(base_addr)) # Start of buffer
                            candidates.add(hex(base_addr + size - 1)) # End of buffer
                        if size > 1:
                            candidates.add(hex(base_addr + 1)) # Near start
                        if size > 2:
                            candidates.add(hex(base_addr + size // 2)) # Middle of buffer

                except (ValueError, TypeError):
                    continue

        # --- Strategy 4: Pointer Aliasing ---
        # Use other pointers from the context as direct candidates
        self.logger.debug("Adding other context pointers as aliasing candidates.")
        for ctx_val in context_vars.values():
            addr = self._parse_address(ctx_val)
            if addr is not None:
                candidates.add(hex(addr))

        return candidates
