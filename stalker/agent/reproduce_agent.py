import os
import re
import shutil
import shlex
import subprocess
from pathlib import Path
from tempfile import gettempdir
from utils.command import is_secbench_profile, run_cmd, run_compile
from utils.logger import get_logger, logf

NAME = "agent-reproduce"


def _safe_decode_output(data: bytes | str | None) -> str:
    if data is None:
        return ""
    if isinstance(data, str):
        return data
    return data.decode("utf-8", errors="replace")


def _strip_ansi(text: str) -> str:
    return re.sub(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])", "", text)


def _truncate_build_output(text: str, max_lines: int = 15, max_chars: int = 800) -> str:
    """Return last N lines of text, capped by max_chars, for LLM feedback."""
    if not text or not text.strip():
        return "(no output)"
    lines = [l for l in text.strip().split("\n") if l.strip()]
    if len(lines) <= max_lines:
        out = "\n".join(lines)
    else:
        out = "\n".join(lines[-max_lines:])
    if len(out) > max_chars:
        return "..." + out[-max_chars:]
    return out


def _quote_arg(arg: str) -> str:
    text = str(arg)
    return '"' + text.replace('"', '\\"') + '"'


def _is_env_assignment(token: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", token))


def _looks_like_target_command(token: str) -> bool:
    return token.startswith("/") or token.startswith("./") or "/" in token


def _repro_body(secb_sh: str) -> str:
    match = re.search(r"repro\(\)\s*\{(?P<body>.*?)(?:\n\}\n\npatch\(\)|\n\})", secb_sh, flags=re.S)
    return match.group("body") if match else ""


def _parse_secbench_repro_command_from_text(secb_sh: str, cwd: str) -> tuple[str, list[str]]:
    ignored_commands = {
        "echo", "cd", "export", "sleep", "kill", "bash", "nc", "true", "false", "touch",
    }
    current_cwd = cwd
    for raw_line in _repro_body(secb_sh).splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        line = line.split("#", 1)[0].strip()
        line = line.split("||", 1)[0].strip()
        if "|" in line:
            line = line.rsplit("|", 1)[1].strip()
        if line.endswith("&"):
            line = line[:-1].strip()
        try:
            parts = shlex.split(line)
        except ValueError:
            continue
        if not parts:
            continue
        if parts[0] == "cd" and len(parts) >= 2:
            current_cwd = parts[1]
            continue
        while parts and _is_env_assignment(parts[0]):
            parts.pop(0)
        if len(parts) >= 3 and parts[0] == "timeout":
            parts = parts[2:]
        if not parts or parts[0] in ignored_commands:
            continue
        if not _looks_like_target_command(parts[0]):
            continue
        executable = parts[0]
        if executable.startswith("./"):
            executable = str(Path(current_cwd) / executable[2:])
        elif not executable.startswith("/"):
            executable = str(Path(current_cwd) / executable)
        if executable.startswith("/"):
            return executable, parts[1:]
    return "", []


def _parse_secbench_repro_command_from_file(profile: dict) -> tuple[str, list[str]]:
    src = str(profile.get("src") or "")
    if not src:
        return "", []
    candidates: list[Path] = [Path(src) / "secb"]
    resolved = shutil.which("secb")
    if resolved:
        candidates.append(Path(resolved))
    candidates.extend([Path("/usr/local/bin/secb"), Path("/usr/bin/secb")])

    seen: set[Path] = set()
    for secb_path in candidates:
        if secb_path in seen:
            continue
        seen.add(secb_path)
        try:
            secb_sh = secb_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        executable, args = _parse_secbench_repro_command_from_text(secb_sh, src)
        if executable:
            return executable, args
    return "", []


def _materialize_seed_mutations(seed_path: Path, max_generated: int = 8) -> list[Path]:
    if not seed_path.is_file():
        return []
    try:
        data = seed_path.read_bytes()
    except OSError:
        return []
    if not data or len(data) > 1024 * 1024:
        return []

    variants: list[bytes] = []
    variants.append(data[: max(1, len(data) // 2)])
    variants.append(data + b"\x00")
    variants.append(data + data[: min(16, len(data))])

    def _flip(buf: bytes, idx: int, mask: int) -> bytes:
        out = bytearray(buf)
        out[idx] ^= mask
        return bytes(out)

    variants.append(_flip(data, 0, 0x01))
    variants.append(_flip(data, len(data) // 2, 0x20))
    variants.append(_flip(data, len(data) - 1, 0x80))

    tmp_root = Path(gettempdir()) / "angelic_variants"
    tmp_root.mkdir(parents=True, exist_ok=True)
    out: list[Path] = []
    seen: set[bytes] = set()
    for idx, variant in enumerate(variants):
        if not variant or variant in seen:
            continue
        seen.add(variant)
        target = tmp_root / f"{seed_path.name}.mut{idx}{seed_path.suffix}"
        try:
            target.write_bytes(variant)
        except OSError:
            continue
        out.append(target)
        if len(out) >= max_generated:
            break
    return out


def build_command(profile: dict, args_override: list[str] | None = None) -> str:
    cmd = str(profile["file"])
    args = profile.get("args", []) if args_override is None else args_override
    for arg in args:
        cmd += f" {_quote_arg(arg)}"
    return cmd


def _is_sanitizer_path(path: str) -> bool:
    return any(x in (path or "") for x in [
        "/src/llvm-project/compiler-rt/",
        "/compiler-rt/lib/asan/",
        "/compiler-rt/lib/ubsan/",
        "/compiler-rt/lib/msan/",
        "/compiler-rt/lib/tsan/",
    ])


def _is_project_source_path(profile: dict, path: str) -> bool:
    if not path or path == "N/A" or _is_sanitizer_path(path):
        return False

    project_root = str(profile.get("src", "")).rstrip("/")
    if not project_root:
        return False

    if os.path.isabs(path):
        return path.startswith(project_root + "/")

    resolved = _resolve_source_path(profile, path)
    return (
        bool(resolved)
        and os.path.isabs(resolved)
        and resolved.startswith(project_root + "/")
        and os.path.exists(resolved)
    )


def _resolve_source_path(profile: dict, path: str) -> str:
    if not path or path == "N/A":
        return path
    if os.path.isabs(path) and os.path.exists(path):
        return path

    project_root = str(profile.get("src", "")).rstrip("/")
    if project_root:
        direct = path if os.path.isabs(path) else os.path.join(project_root, path)
        if os.path.exists(direct):
            return direct

        basename = os.path.basename(path)
        normalized_suffix = path.replace("\\", "/").lstrip("./")
        for root, dirnames, files in os.walk(project_root):
            dirnames[:] = [
                name for name in dirnames
                if name not in {".git", "build", "cmake-build-debug", "cmake-build-release"}
            ]
            if basename not in files:
                continue
            candidate = os.path.join(root, basename)
            if candidate.replace("\\", "/").endswith("/" + normalized_suffix):
                return candidate

        for root, dirnames, files in os.walk(project_root):
            dirnames[:] = [
                name for name in dirnames
                if name not in {".git", "build", "cmake-build-debug", "cmake-build-release"}
            ]
            if basename in files:
                return os.path.join(root, basename)
    return path


def _symbolize_binary_frame(profile: dict, executable: str, offset: str) -> tuple[str, str, int] | None:
    profile_executable = str(profile.get("file", ""))
    project_root = str(profile.get("src", "")).rstrip("/")
    if not executable or not os.path.exists(executable):
        return None
    if executable != profile_executable and not (
        project_root and executable.startswith(project_root + "/")
    ):
        return None

    symbolizer = shutil.which("addr2line") or shutil.which("llvm-addr2line")
    if not symbolizer:
        return None

    try:
        result = subprocess.run(
            [symbolizer, "-f", "-C", "-e", executable, offset],
            capture_output=True,
            text=True,
            timeout=3,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None

    lines = [line.strip() for line in (result.stdout or "").splitlines() if line.strip()]
    if len(lines) < 2:
        return None

    function = lines[0]
    location = lines[1]
    if location.startswith("??") or ":" not in location:
        return None

    source, line_text = location.rsplit(":", 1)
    try:
        line = int(line_text)
    except ValueError:
        return None

    source = _resolve_source_path(profile, source)
    if not _is_project_source_path(profile, source):
        return None
    return function, source, line


def _function_search_name(function: str) -> str:
    name = re.sub(r"\(.*", "", function or "").strip()
    name = name.rsplit("::", 1)[-1]
    name = name.split()[-1] if name.split() else name
    return name.strip("*& ")


def _find_function_line(profile: dict, function: str, preferred_source: str = "") -> tuple[str, int] | None:
    name = _function_search_name(function)
    if not name:
        return None

    project_root = str(profile.get("src", "")).rstrip("/")
    candidates: list[str] = []
    if preferred_source:
        resolved = _resolve_source_path(profile, preferred_source)
        if _is_project_source_path(profile, resolved):
            candidates.append(resolved)

    if project_root:
        for root, dirnames, files in os.walk(project_root):
            dirnames[:] = [
                dirname for dirname in dirnames
                if dirname not in {".git", "build", "cmake-build-debug", "cmake-build-release"}
            ]
            for filename in files:
                if filename.endswith((".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hxx")):
                    path = os.path.join(root, filename)
                    if path not in candidates:
                        candidates.append(path)

    pattern = re.compile(rf"\b{re.escape(name)}\b")
    for path in candidates:
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                for idx, line in enumerate(f, start=1):
                    if pattern.search(line):
                        return path, idx
        except OSError:
            continue
    return None


def _infer_project_executable_from_text(profile: dict, text: str) -> str:
    project_root = str(profile.get("src", "")).rstrip("/")
    if not project_root:
        return ""
    binary_ref_re = re.compile(r"\((?P<executable>/[^()\s]+)\+0x[0-9a-fA-F]+\)")
    for m in binary_ref_re.finditer(text):
        executable = m.group("executable")
        if executable.startswith(project_root + "/") and os.path.exists(executable):
            return executable
    return ""


def _infer_location_from_text(profile: dict, text: str) -> tuple[str, str, int] | None:
    bare_frame_re = re.compile(
        r"^[ \t]*#\d+[ \t]+0x[0-9a-fA-F]+[ \t]+in[ \t]+(?P<func>.+?)[ \t]+"
        r"(?P<file>[^\s()]+?\.(?:c|cc|cpp|cxx|h|hpp|hxx))(?:\s|$)",
        re.MULTILINE,
    )
    for m in bare_frame_re.finditer(text):
        found = _find_function_line(profile, m.group("func"), m.group("file"))
        if found:
            return m.group("func"), found[0], found[1]

    summary_binary_re = re.compile(
        r"SUMMARY:\s+\S+Sanitizer:.*?\((?P<executable>[^()]+)\+(?P<offset>0x[0-9a-fA-F]+)\)"
        r"\s+in\s+(?P<func>[^\n]+)",
        re.MULTILINE,
    )
    for m in summary_binary_re.finditer(text):
        symbolized = _symbolize_binary_frame(profile, m.group("executable"), m.group("offset"))
        if symbolized:
            return symbolized
        found = _find_function_line(profile, m.group("func"))
        if found:
            return m.group("func"), found[0], found[1]

    summary_source_re = re.compile(
        r"SUMMARY:\s+\S+Sanitizer:.*?\s(?P<file>[^\s()]+?\.(?:c|cc|cpp|cxx|h|hpp|hxx))\s+"
        r"in\s+(?P<func>[^\n]+)"
    )
    for m in summary_source_re.finditer(text):
        found = _find_function_line(profile, m.group("func"), m.group("file"))
        if found:
            return m.group("func"), found[0], found[1]

    description = str(profile.get("bug_description") or "")
    if description:
        function_match = re.search(r"(?:function|in)\s+([A-Za-z_][A-Za-z0-9_:~]*)\s*\(", description)
        path_match = re.search(r"(/[A-Za-z0-9_./+-]+\.(?:c|cc|cpp|cxx|h|hpp|hxx))", description)
        rel_path_match = re.search(r"([A-Za-z0-9_./+-]+\.(?:c|cc|cpp|cxx|h|hpp|hxx))", description)
        if function_match:
            source_hint = path_match.group(1) if path_match else (rel_path_match.group(1) if rel_path_match else "")
            found = _find_function_line(profile, function_match.group(1), source_hint)
            if found:
                return function_match.group(1), found[0], found[1]

        qualified_match = re.search(
            r"([A-Za-z_][A-Za-z0-9_:~]*::[A-Za-z_][A-Za-z0-9_:~]*)\s+in\s+"
            r"([A-Za-z0-9_./+-]+\.(?:c|cc|cpp|cxx|h|hpp|hxx))",
            description,
        )
        if qualified_match:
            found = _find_function_line(profile, qualified_match.group(1), qualified_match.group(2))
            if found:
                return qualified_match.group(1), found[0], found[1]

        plain_in_file_match = re.search(
            r"\bin\s+([A-Za-z_][A-Za-z0-9_:~]*)\s+in\s+"
            r"([A-Za-z0-9_./+-]+\.(?:c|cc|cpp|cxx|h|hpp|hxx))",
            description,
        )
        if plain_in_file_match:
            found = _find_function_line(profile, plain_in_file_match.group(1), plain_in_file_match.group(2))
            if found:
                return plain_in_file_match.group(1), found[0], found[1]

    return None


def _parse_run_output(profile: dict, return_code: int, stdout: str, stderr: str, command: str, args: list[str], logger) -> dict:
    error_msg = stdout + stderr
    clean_error_msg = _strip_ansi(error_msg)
    asan_match = re.search(r"ERROR: AddressSanitizer: ([\w\-]+)", error_msg)
    if asan_match:
        logger.info("AddressSanitizer error detected")

    func = "N/A"
    file = "N/A"
    line = -1
    frame_re = re.compile(
        r"^[ \t]*#\d+[ \t]+0x[0-9a-fA-F]+[ \t]+in[ \t]+(.+?)[ \t]+([^\n]+?\.(?:c|cc|cpp|cxx|h|hpp|hxx)):(\d+)",
        re.MULTILINE,
    )
    matches = list(frame_re.finditer(clean_error_msg))
    if matches:
        preferred = None

        for m in matches:
            if _is_project_source_path(profile, m.group(2)):
                preferred = m
                break

        if preferred is not None:
            func = preferred.group(1)
            file = _resolve_source_path(profile, preferred.group(2))
            line = int(preferred.group(3))
    if line < 0:
        binary_frame_re = re.compile(
            r"^[ \t]*#\d+[ \t]+0x[0-9a-fA-F]+[ \t]+in[ \t]+(?P<func>.+?)[ \t]+"
            r"\((?P<executable>[^()]+)\+(?P<offset>0x[0-9a-fA-F]+)\)",
            re.MULTILINE,
        )
        for m in binary_frame_re.finditer(clean_error_msg):
            symbolized = _symbolize_binary_frame(profile, m.group("executable"), m.group("offset"))
            if symbolized is not None:
                func, file, line = symbolized
                break
            found = _find_function_line(profile, m.group("func"))
            if found:
                func, file, line = m.group("func"), found[0], found[1]
                break

    if line < 0:
        ubsan_re = re.compile(
            r"(?P<file>[^\s:]+?\.(?:c|cc|cpp|cxx|h|hpp|hxx)):(?P<line>\d+):\d+:\s+runtime error:"
        )
        for m in ubsan_re.finditer(clean_error_msg):
            if _is_project_source_path(profile, m.group("file")):
                func = "N/A"
                file = _resolve_source_path(profile, m.group("file"))
                line = int(m.group("line"))
                break

    if line < 0:
        inferred = _infer_location_from_text(profile, clean_error_msg)
        if inferred is not None:
            func, file, line = inferred

    inferred_executable = _infer_project_executable_from_text(profile, clean_error_msg)
    if not inferred_executable and is_secbench_profile(profile):
        inferred_executable, inferred_args = _parse_secbench_repro_command_from_file(profile)
        if inferred_executable and not args:
            args = inferred_args

    return {
        "status": True,
        "return_code": return_code,
        "error": error_msg,
        "func": func,
        "file": file,
        "line": line,
        "executable": inferred_executable,
        "command": command,
        "args": args,
    }


def _parse_run_result(profile: dict, process: subprocess.CompletedProcess, logger) -> dict:
    stdout = _safe_decode_output(process.stdout)
    stderr = _safe_decode_output(process.stderr)
    return _parse_run_output(
        profile,
        process.returncode,
        stdout,
        stderr,
        build_command(profile),
        list(profile.get("args", [])),
        logger,
    )


@logf(NAME)
def run_profile_once(
    profile: dict,
    args_override: list[str] | None = None,
    env_override: dict | None = None,
    cwd_override: str | None = None,
    logger=None,
) -> dict:
    cmd = build_command(profile, args_override=args_override)
    process = subprocess.run(
        cmd,
        shell=True,
        capture_output=True,
        env={**os.environ, **profile.get("env", {}), **(env_override or {})},
        cwd=cwd_override or profile.get("src"),
    )
    result = _parse_run_result(profile, process, logger)
    result["command"] = cmd
    result["args"] = args_override if args_override is not None else list(profile.get("args", []))
    return result


def run_secbench_repro_once(profile: dict, logger=None) -> dict:
    return_code, stdout, stderr = run_cmd(["bash", "-c", "secb repro"], cwd=profile.get("src"), timeout=10)
    return _parse_run_output(
        profile,
        return_code,
        stdout,
        stderr,
        "secb repro",
        list(profile.get("args", [])),
        logger,
    )


def derive_input_variants(profile: dict, max_variants: int = 20) -> list[list[str]]:
    configured = profile.get("variant_inputs") or []
    if configured:
        out = []
        for item in configured[:max_variants]:
            if isinstance(item, list):
                out.append([str(v) for v in item])
            else:
                out.append([str(item)])
        return out

    args = [str(arg) for arg in profile.get("args", [])]
    if not args:
        return []
    seed = args[0]
    candidates: list[list[str]] = []
    path = Path(seed)
    if path.exists():
        candidates.append(args)
        seen = {tuple(args)}

        def _push(candidate_path: Path) -> None:
            entry = [str(candidate_path)] + args[1:]
            key = tuple(entry)
            if key in seen or not candidate_path.is_file():
                return
            seen.add(key)
            candidates.append(entry)

        # Same prefix variants near the original PoC
        for candidate in sorted(path.parent.glob(path.name + "*")):
            if str(candidate) == seed:
                continue
            _push(candidate)
            if len(candidates) >= max_variants:
                break

        # Deterministic byte-level mutations of the original seed.
        if len(candidates) < max_variants:
            for candidate in _materialize_seed_mutations(path, max_generated=min(8, max_variants - len(candidates))):
                _push(candidate)
                if len(candidates) >= max_variants:
                    break

        # Same extension siblings often act as nearby corpus seeds.
        if len(candidates) < max_variants and path.suffix:
            for candidate in sorted(path.parent.glob("*" + path.suffix)):
                if str(candidate) == seed:
                    continue
                _push(candidate)
                if len(candidates) >= max_variants:
                    break

        # Common neighboring corpus files.
        if len(candidates) < max_variants:
            patterns = ("id:*", "seed*", "crash*", "poc*", "test*")
            for pattern in patterns:
                for candidate in sorted(path.parent.glob(pattern)):
                    if str(candidate) == seed:
                        continue
                    _push(candidate)
                    if len(candidates) >= max_variants:
                        break
                if len(candidates) >= max_variants:
                    break
    return candidates[:max_variants]


@logf(NAME)
def reproduce(profile, logger=None):
    """
    Reproduce the bug with the given profile.
    """
    logger.info("Compiling project")
    ret_code, stdout, stderr = run_compile()
    if ret_code != 0:
        logger.error(f"Compilation failed:\n{stdout}\n{stderr}")
        tail = _truncate_build_output(stdout + "\n" + stderr)
        return {"status": False, "error": f"Failed to compile:\n```\n{tail}\n```"}

    logger.info("Running project")
    if is_secbench_profile(profile):
        result = run_secbench_repro_once(profile, logger=logger)
    else:
        result = run_profile_once(profile, logger=logger)
    logger.info(f"Bug reproduced {result}")
    return result
