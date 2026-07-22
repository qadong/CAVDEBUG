import re
from typing import Optional

def alloc_buf(debugger, size: int) -> Optional[int]:
    """
    Allocates a buffer in the target process using malloc.
    Returns the address as an integer.
    """
    # Safety Cap: 1MB. Larger buffers risk instability and are rarely needed for logic testing.
    MAX_SIZE = 1024 * 1024
    if size > MAX_SIZE:
        print(f"[WARN] alloc_buf requested size {size} > {MAX_SIZE}, capping to {MAX_SIZE}")
        size = MAX_SIZE

    # Try to call malloc in the debugger
    res = debugger.print(f"(void*)malloc({size})")
    
    # Check for failure or empty output
    if not res or "error" in res.lower() or "not available" in res.lower() or "(no output)" in res:
        # Fallback: Try mmap if malloc fails (bypass heap locks)
        # mmap(0, size, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0)
        # PROT = 7 (RWX), FLAGS = 0x22 (Private|Anon)
        # align size to 4096
        mmap_size = (size + 4095) & ~4095
        print(f"[WARN] malloc failed, trying mmap fallback: mmap(0, {mmap_size}, 7, 0x22, -1, 0)")
        res = debugger.print(f"(void*)mmap(0, {mmap_size}, 7, 0x22, -1, 0)")
        
        if not res or "error" in res.lower() or "not available" in res.lower() or "(no output)" in res:
            msg = f"alloc_buf failed (both malloc and mmap): {res}"
            print(f"[ERROR] {msg}")
            raise RuntimeError(msg)

    # Parse address from output like: (void *) $1 = 0x0000602000000110
    match = re.search(r'(0x[0-9a-fA-F]+)', res)
    if match:
        return int(match.group(1), 16)
    
    msg = f"alloc_buf failed to parse address from: {res}"
    print(f"[ERROR] {msg}")
    raise RuntimeError(msg)

def write_buf(debugger, addr: int, data: bytes):
    """
    Writes raw bytes to a memory address in the target process.
    Uses LLDB 'memory write' command for efficiency.
    """
    if not data:
        return

    # Use hex string for command
    # data.hex() returns string like "010203"
    # memory write 0xaddr 0x01 0x02 ...
    
    # Method 1: Try -data-write-memory-bytes (MI standard)
    # WARNING: Not supported by all lldb-mi versions.
    # We will try CLI 'memory write' instead which is robust.
    
    # Method 2: CLI 'memory write'
    # memory write <addr> <byte1> <byte2> ...
    # This can get too long for command line if buffer is large.
    # So we chunk it.
    
    CHUNK_SIZE = 1024 # Write 1KB at a time
    
    for i in range(0, len(data), CHUNK_SIZE):
        chunk = data[i:i+CHUNK_SIZE]
        chunk_addr = addr + i
        
        # Format: memory write 0xADDR 0xAA 0xBB ...
        # hex(b) produces '0xaa', ideal for lldb
        bytes_str = " ".join([hex(b) for b in chunk])
        
        # Use interpreter-exec to run CLI command through MI
        cmd = f'-interpreter-exec console "memory write {hex(chunk_addr)} {bytes_str}"'
        
        if hasattr(debugger, 'execute'):
             debugger.execute(cmd)
        else:
            # Fallback for mock/test objects
            for j, b in enumerate(chunk):
                debugger.assign_expression(f"((unsigned char*){hex(chunk_addr)})[{j}] = {int(b)}")

def read_buf(debugger, addr: int, size: int) -> bytes:
    """
    Reads bytes from a memory address.
    """
    data = []
    for i in range(size):
        res = debugger.print(f"(unsigned char)((unsigned char*){hex(addr)})[{i}]")
        # Parse byte value from output like: (unsigned char) $2 = '\x1f' or 31
        match = re.search(r'=\s*(\d+|0x[0-9a-fA-F]+|\'.*?\')', res)
        if match:
            val_str = match.group(1)
            if val_str.startswith("'"): # char literal
                # This is tricky due to escaping, but usually print returns decimal as well
                pass
            try:
                if val_str.startswith("0x"):
                    data.append(int(val_str, 16))
                else:
                    data.append(int(val_str))
            except ValueError:
                data.append(0)
    return bytes(data)

def get_addr(debugger, symbol: str) -> Optional[int]:
    """
    Gets the address of a symbol or variable.
    """
    res = debugger.print(f"&({symbol})")
    match = re.search(r'(0x[0-9a-fA-F]+)', res)
    if match:
        return int(match.group(1), 16)
    return None

