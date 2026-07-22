def int_boundaries(bits: int, signed: bool) -> list[int]:
    """Generates boundary values for a given integer type."""
    if signed:
        return [0, 1, -1, (1 << (bits - 1)) - 1, -(1 << (bits - 1))]
    else:
        return [0, 1, (1 << bits) - 1, (1 << bits) - 2]

def int_bitflip(val: int, bits: int) -> list[int]:
    """Generates values with a single bit flipped."""
    results = []
    for i in range(bits):
        results.append(val ^ (1 << i))
    return results

def int_arithmetic(val: int, range_val: int = 10) -> list[int]:
    """Generates values in a range around the original value."""
    return [val + i for i in range(-range_val, range_val + 1) if i != 0]

