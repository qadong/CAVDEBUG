import re
import os
from typing import List, Tuple
from fix import apply_66163_fix
from tools.lsp.driver import lsp_instance
from utils.logger import logf


NAME = "parser"


def _is_sanitizer_path(path: str) -> bool:
    return any(x in (path or "") for x in (
        "/src/llvm-project/compiler-rt/",
        "/compiler-rt/lib/asan/",
        "/compiler-rt/lib/ubsan/",
        "/compiler-rt/lib/msan/",
        "/compiler-rt/lib/tsan/",
    ))


def _resolve_source_path(filename: str, logger=None) -> str:
    if not filename:
        return filename
    src_dir = lsp_instance().get_cwd()
    candidates = []
    if os.path.isabs(filename):
        candidates.append(filename)
    else:
        candidates.append(os.path.join(src_dir, filename))
    for candidate in candidates:
        if os.path.exists(candidate):
            return candidate

    basename = os.path.basename(filename)
    for root, dirnames, files in os.walk(src_dir):
        dirnames[:] = [
            dirname for dirname in dirnames
            if dirname not in {".git", "build", "cmake-build-debug", "cmake-build-release", "__pycache__"}
        ]
        if basename in files:
            return os.path.join(root, basename)

    if logger:
        logger.warning("Source file %s not found under %s", filename, src_dir)
    return filename


@logf(NAME)
def _parse_asan_output(output, logger=None) -> Tuple[str, List[str]]:
    index = output.find("==ERROR: AddressSanitizer:")
    if index == -1:
        return None, None
    output = output[index + 2 :]

    lines = output.split("\n")
    error = lines[0].strip()

    frames = []
    for line in lines[1:]:
        line = line.strip()
        if line.startswith("#"):
            frames.append(line)
    if len(frames) == 0:
        logger.error("No stack frame found in Address Sanitizer output")
        return None, None

    return error, frames


@logf(NAME)
def _parse_msan_output(output, logger=None) -> Tuple[str, List[str]]:
    index = output.find("==WARNING: MemorySanitizer:")
    if index == -1:
        return None, None
    output = output[index + 2 :]

    lines = output.split("\n")
    error = lines[0].strip()

    frames = []
    for line in lines[1:]:
        line = line.strip()
        if line.startswith("#"):
            frames.append(line)
    if len(frames) == 0:
        logger.error("No stack frame found in Memory Sanitizer output")
        return None, None

    return error, frames


@logf(NAME)
def _parse_runtime_error_output(output, logger=None) -> Tuple[str, List[str]]:
    # filters/in_rtp.c:123:3: runtime error: index 1024 out of bounds for type 'char[1024]'

    lines = output.split("\n")
    error = None
    frames = []
    for line in lines:
        if error is None:
            if ": runtime error:" in line:
                # >>> FIX
                if apply_66163_fix():
                    if len(line) > 1000:
                        # <NALU size="46"  forbidden_zero="0" nuh_type="0" layerID="40" temporalID="7" first_slice_segment_in_pic_flag="0" pps_id="1" slice_reserved_undetermined_flag="2" slice_type="0" short_term_ref_pic_set_sps_flag="0" num_negative_pics_0="4" num_positive_pics_0="1" delta_poc_s0_minus1_0_0="4" delta_poc_s0_minus1_0_0="0" delta_poc_s0_minus1_0_1="0" delta_poc_s0_minus1_0_1="0" delta_poc_s0_minus1_0_2="4" delta_poc_s0_minus1_0_2="0" delta_poc_s0_minus1_0_3="0" delta_poc_s0_minus1_0_3="0" delta_poc_s1_minus1_0_0="32830" used_by_curr_pic_s1_flag_0_0="1" num_ref_idx_active_override_flag="0" mvd_l1_zero_flag="1" luma_log2_weight_denom="13" luma_weights_0="0" luma_weights_1="1" luma_weights_2="1" luma_weights_3="1" luma_weights_4="0" luma_weights_5="1" luma_weights_6="0" luma_weights_7="1" luma_weights_8="1" luma_weights_9="1" luma_weights_10="1" luma_weights_11="1" luma_weights_12="1" luma_weights_13="1" luma_weights_14="1" luma_weights_15="1" luma_weights_16="1" luma_weights_17="1" luma_weights_18="1" luma_weights_19=media_tools/av_parsers.c:7140:3: runtime error: index 20 out of bounds for type 'u8[20]' (aka 'unsigned char[20]')
                        index = line.find("media_tools/av_parsers.c")
                        if index == -1:
                            raise RuntimeError(
                                "Bad runtime error message for FIX: 66163"
                            )
                        line = line[index:]
                # <<<
                error = line
        else:
            line = line.strip()
            if line.startswith("#"):
                frames.append(line)
            else:
                break
    if error is None:
        return None, None
    if len(frames) == 0:
        logger.error("No stack frame found in runtime error output")
        return None, None

    return error, frames


@logf(NAME)
def parse_sanitizer_output(output, logger=None) -> Tuple[str, List[str]]:
    """
    [error, frames]
    """
    error, frames = _parse_asan_output(output)
    if error is not None:
        return error, frames

    error, frames = _parse_msan_output(output)
    if error is not None:
        return error, frames

    error, frames = _parse_runtime_error_output(output)
    if error is not None:
        return error, frames

    logger.debug("No sanitizer report found in output")
    return None, None


@logf(NAME)
def parse_sanitizer_stack_frame(frame, logger=None) -> Tuple[str, str, int]:
    """
    Parse function, file, line in:;
    #0 0x135a1fe in _cmsReadHeader /src/mupdf/thirdparty/lcms2/src/cmsio0.c:839:27
    #2 0x13cbd5c in gf_opus_parse_packet_header /src/gpac/src/media_tools/av_parsers.c:9884:10
    """
    pattern = re.compile(
        r"#(\d+)\s+(?:0x[0-9a-fA-F]+)\s+in\s+([^\s]+)\s+(.+?\.(?:c|cc|cpp|cxx|h|hpp|hxx)):(\d+)"
    )
    matches = pattern.search(frame)
    if matches is None:
        logger.warning("Invalid stack frame: %s", frame)
        return None, None, 0

    function = matches.group(2)
    filename = matches.group(3)
    line = matches.group(4)

    if _is_sanitizer_path(filename):
        logger.warning("Invalid filepath: %s", filename)
        return None, None, 0
    filename = _resolve_source_path(filename, logger=logger)
    src_dir = lsp_instance().get_cwd()
    if os.path.isabs(filename) and not filename.startswith(src_dir):
        logger.warning("Invalid filepath: %s", filename)
        return None, None, 0

    return function, filename, int(line)


def check_sanitizer_error(target_output: str, lldb_output: dict) -> Tuple[bool, str]:
    """
    Check if target_output contains AddressSanitizer or MemorySanitizer errors.
    Returns (has_error: bool, error_msg: str).
    Handles ANSI escape codes in the output.
    """
    if target_output is None:
        return False, ""
        
    # Remove ANSI escape codes for cleaner matching
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    clean_output = ansi_escape.sub('', target_output)
    
    # Check 1: Look for AddressSanitizer ERROR pattern (most reliable)
    # Pattern: ==PID==ERROR: AddressSanitizer: error-type
    sanitizer_pattern = re.compile(r"==\d+==(ERROR|WARNING):\s*(AddressSanitizer|MemorySanitizer|LeakSanitizer)")
    for log_line in clean_output.splitlines():
        if sanitizer_pattern.search(log_line) and "breakpoint hit" not in log_line.lower():
            error_match = sanitizer_pattern.search(log_line)
            error_type = error_match.group(2) if error_match else "Sanitizer"
            return True, f"{error_type} error found: {log_line.strip()[:200]}"
    
    # Check 1.5: Look for LeakSanitizer fatal error (alternative format)
    leak_sanitizer_fatal = re.compile(r"==\d+==LeakSanitizer\s+has\s+encountered\s+a\s+fatal\s+error", re.IGNORECASE)
    for log_line in clean_output.splitlines():
        if leak_sanitizer_fatal.search(log_line):
            return True, f"LeakSanitizer fatal error found: {log_line.strip()[:200]}"
    
    # Check 2: Look for AddressSanitizer report breakpoint hit
    asan_report_pattern = re.compile(r"AddressSanitizer\s+report\s+breakpoint\s+hit", re.IGNORECASE)
    for log_line in clean_output.splitlines():
        if asan_report_pattern.search(log_line):
            return True, f"AddressSanitizer report found: {log_line.strip()[:200]}"
    
    # Check 3: Look for common ASan error patterns (more flexible)
    asan_error_patterns = [
        (r"AddressSanitizer:\s*(stack-buffer-overflow|heap-buffer-overflow|use-after-free|double-free|memory-leak)", "ASan error type"),
        (r"ERROR:\s*LeakSanitizer", "LeakSanitizer"),
        (r"SEGV on unknown address", "Segmentation fault"),
        (r"SUMMARY:\s*AddressSanitizer", "ASan summary"),
        (r"SUMMARY:\s*MemorySanitizer", "MSan summary"),
        (r"SUMMARY:\s*LeakSanitizer", "LeakSanitizer summary"),
        (r"runtime error:", "UBSan error"),
    ]
    for pattern, error_desc in asan_error_patterns:
        if re.search(pattern, clean_output, re.IGNORECASE):
            match = re.search(pattern, clean_output, re.IGNORECASE)
            matched_text = match.group(0) if match else ""
            return True, f"{error_desc} pattern found: {matched_text[:200]}"
    
    # Check 4: Look for __asan_/__msan_/__lsan_ in frame.func (function name)
    if lldb_output and "func" in lldb_output:
        func_name = lldb_output.get("func", "")
        if "__asan_" in func_name or "__lsan_" in func_name or "__msan_" in func_name:
            return True, f"Sanitizer function found in frame.func: {func_name}"
    
    return False, ""


@logf(NAME)
def parse_lldb_frame(frame, logger=None) -> Tuple[int, str, str, int]:
    """
    Parse frame id, function, file and line from lldb frame.
    """
    # frame #0: 0x0000000001357271 pdf_fuzzer`_cmsReadHeader(ContextID=<unavailable>, Icc=<unavailable>) at cmsio0.c:839:17
    # frame #0: 0x00000000005771ba FuzzCUPS`push_stack(st=0x0000602000000090, obj=<unavailable>) at raster-interpret.c:958:1
    pattern = re.compile(
        r"frame #(\d+): 0x[0-9a-f]+ (.+)`([^\s(]+)\(.*\) at ([\w/\-\.]+):(\d+):(\d+)"
    )
    matches = pattern.search(frame)
    if matches is not None:
        return (
            int(matches.group(1)),
            matches.group(3),
            matches.group(4),
            int(matches.group(5)),
        )

    # frame #0: 0x000000000054177e fuzzer_tool_flac`write_callback at decode.c:1263:26
    pattern = re.compile(
        r"frame #(\d+): 0x[0-9a-f]+ (.+)`([^\s]+) at ([\w/\-\.]+):(\d+):(\d+)"
    )
    matches = pattern.search(frame)
    if matches is not None:
        return (
            int(matches.group(1)),
            matches.group(3),
            matches.group(4),
            int(matches.group(5)),
        )

    # frame #1: 0x00000000005275ea magic_fuzzer`file_is_simh [inlined] simh_parse(uc=\"\xffffffff\v) at is_simh.c:119
    pattern = re.compile(
        r"frame #(\d+): 0x[0-9a-f]+ (.+)`([^\s]+) \[inlined\] ([^\s(]+)\(.*\) at ([\w/\-\.]+):(\d+)"
    )
    matches = pattern.search(frame)
    if matches is not None:
        return (
            int(matches.group(1)),
            matches.group(4),
            matches.group(5),
            int(matches.group(6)),
        )

    # failed
    return None, None, None, None


def parse_patch_string(patch: str) -> Tuple[str, int, int, str]:
    """
    Parse patch string into [file, start_line, end_line, patch_content].
    Format: <filename>:<start line>-<end line>\n<patch content>
    """
    file = None
    start_line = None
    end_line = None
    patch_content = None

    try:
        index = patch.find("\n")
        first = patch[:index]
        patch_content = patch[index + 1 :]
        file, location = first.split(":")
    except Exception:
        return None, None, None, None

    pattern = re.compile(r"(\d+)-(\d+)")
    matches = pattern.search(location)
    if matches is not None:
        start_line = int(matches.group(1))
        end_line = int(matches.group(2))
    else:
        pattern = re.compile(r"(\d+)")
        matches = pattern.search(location)
        if matches is None:
            return None, None, None, None
        start_line = int(matches.group(1))
        end_line = int(matches.group(1))

    return file, start_line, end_line, patch_content
