import subprocess
from typing import List
from utils.logger import logf

DEFAULT_TIMEOUT = 60 * 60  # 1 hour


def _safe_decode_output(data) -> str:
    if data is None:
        return ""
    if isinstance(data, str):
        return data
    return data.decode("utf-8", errors="replace")


@logf("command")
def run_cmd(
    cmd: list[str],
    cwd: str = None,
    redirect: bool = True,
    timeout=DEFAULT_TIMEOUT,
    logger=None,
) -> tuple[int, str, str]:
    """
    Run a command and return the exit code, stdout and stderr
    """
    logger.debug(" ".join(cmd))

    try:
        if redirect:
            process = subprocess.run(
                cmd,
                cwd=cwd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
            )
        else:
            process = subprocess.run(cmd, cwd=cwd, timeout=timeout)
    except subprocess.TimeoutExpired:
        logger.error(f"Timed out: {' '.join(cmd)}")
        return -66, "", "Timed out"
    return (
        process.returncode,
        _safe_decode_output(process.stdout),
        _safe_decode_output(process.stderr),
    )


def is_secbench_profile(profile: dict | None) -> bool:
    return bool(profile and (profile.get("runner") == "secbench" or profile.get("secbench")))


def run_reproduce(profile: dict | None = None):
    if is_secbench_profile(profile):
        return run_cmd(["bash", "-c", "secb repro"], cwd=profile.get("src"), timeout=10)
    return run_cmd(["arvo"], timeout=10)


def run_validation_build(profile: dict | None = None):
    if is_secbench_profile(profile):
        return run_cmd(["bash", "-c", "secb build"], cwd=profile.get("src"), timeout=1800)
    return run_compile()


PRE_BUILD_CMDS = ["cd /src/file", "make clean"]
POST_BUILD_CMDS = []
BUILD_CMD = "CFLAGS='-O0 -g' CXXFLAGS='-O0 -g' bear arvo compile"
SEC_BENCH_DEBUG_CFLAGS = (
    "-O0 -g -Wno-error -Wno-strict-prototypes "
    "-Wno-incompatible-function-pointer-types -Wno-implicit-function-declaration "
    "-Wno-deprecated-non-prototype -Wno-int-conversion "
    "-Wno-unused-but-set-variable -Wno-error=unused-but-set-variable "
    "-Wno-single-bit-bitfield-constant-conversion "
    "-Wno-error=single-bit-bitfield-constant-conversion"
)
SEC_BENCH_DEBUG_CXXFLAGS = (
    "-O0 -g -Wno-error -Wno-incompatible-function-pointer-types "
    "-Wno-deprecated-declarations -Wno-register -Wno-c++11-narrowing "
    "-Wno-unused-but-set-variable -Wno-error=unused-but-set-variable "
    "-Wno-single-bit-bitfield-constant-conversion "
    "-Wno-error=single-bit-bitfield-constant-conversion -std=gnu++14"
)
SEC_BENCH_AUTOCONF_CACHE_ENV = (
    "ac_cv_func_malloc_0_nonnull=yes "
    "ac_cv_func_realloc_0_nonnull=yes "
)


def set_prebuild(commands: List[str]):
    global PRE_BUILD_CMDS
    PRE_BUILD_CMDS = commands


def set_postbuild(commands: List[str]):
    global POST_BUILD_CMDS
    POST_BUILD_CMDS = commands


def override_build(command: str):
    global BUILD_CMD
    if "/usr/local/bin/compile" in command:
        command = _normalize_secbench_debug_build(command)

    # If the command contains "bear arvo compile" or "arvo compile" but doesn't have CFLAGS/CXXFLAGS,
    # automatically add sanitizer flags
    if ("bear arvo compile" in command or "arvo compile" in command) and "CFLAGS" not in command:
        # Don't add any sanitizer flags - let arvo handle it or use default
        sanitizer_cflags = "-O0 -g"
        sanitizer_cxxflags = "-O0 -g"
        
        # If command already contains cd or &&, need to wrap it in bash -c with export
        if " && " in command or command.strip().startswith("cd "):
            # Use export to set environment variables within the bash -c context
            command = f"bash -c \"export CFLAGS='{sanitizer_cflags}'; export CXXFLAGS='{sanitizer_cxxflags}'; {command}\""
        else:
            # Simple case: just prepend environment variables
            command = f"CFLAGS='{sanitizer_cflags}' CXXFLAGS='{sanitizer_cxxflags}' {command}"
    BUILD_CMD = command


def _replace_env_assignment(command: str, name: str, value: str) -> str:
    import re

    pattern = rf"{name}=(['\"])(.*?)\1"
    replacement = f"{name}='{value}'"
    if re.search(pattern, command):
        return re.sub(pattern, replacement, command, count=1)
    return f"{replacement} {command}"


def _normalize_secbench_debug_build(command: str) -> str:
    command = _replace_env_assignment(command, "CFLAGS", SEC_BENCH_DEBUG_CFLAGS)
    command = _replace_env_assignment(command, "CXXFLAGS", SEC_BENCH_DEBUG_CXXFLAGS)

    extra_env = (
        SEC_BENCH_AUTOCONF_CACHE_ENV +
        f"CMAKE_C_FLAGS='{SEC_BENCH_DEBUG_CFLAGS}' "
        f"CMAKE_CXX_FLAGS='{SEC_BENCH_DEBUG_CXXFLAGS}' "
        "CMAKE_CXX_STANDARD=14 "
    )
    if "CMAKE_CXX_STANDARD=" not in command:
        command = extra_env + command
    elif "ac_cv_func_malloc_0_nonnull=" not in command:
        command = SEC_BENCH_AUTOCONF_CACHE_ENV + command

    submodule_cmd = "git submodule update --init --recursive || true"
    if submodule_cmd not in command:
        command = f"{submodule_cmd}; {command}"
    cmake_cxx14_patch = (
        "for _secb_build_sh in build.sh /src/build.sh; do "
        "if [ -f \"$_secb_build_sh\" ]; then "
        "if ! grep -q CMAKE_CXX_STANDARD_REQUIRED \"$_secb_build_sh\"; then "
        "perl -0pi -e 's/(^|[;&|]\\s*)(cmake)(\\s+)/$1$2 "
        "-DCMAKE_CXX_STANDARD=14 -DCMAKE_CXX_STANDARD_REQUIRED=ON$3/gm' \"$_secb_build_sh\"; "
        "fi; "
        "if ! grep -q CMAKE_COMPILE_WARNING_AS_ERROR \"$_secb_build_sh\"; then "
        "perl -0pi -e 's/(^|[;&|]\\s*)(cmake)(\\s+)/$1$2 "
        "-DCMAKE_COMPILE_WARNING_AS_ERROR=OFF -DENABLE_WERROR=OFF -DWERROR=OFF "
        "-DWARNINGS_AS_ERRORS=OFF$3/gm' \"$_secb_build_sh\"; "
        "fi; "
        "fi; "
        "done"
    )
    if "for _secb_build_sh in build.sh /src/build.sh" not in command:
        command = f"{cmake_cxx14_patch}; {command}"
    php_readdir_patch = (
        "if [ -f main/reentrancy.c ] && grep -q 'readdir_r(dirp, entry);' main/reentrancy.c; then "
        "perl -0pi -e 's/readdir_r\\(dirp, entry\\);/"
        "{ struct dirent *result = NULL; "
        "if (readdir_r(dirp, entry, \\&result) != 0) return NULL; "
        "if (result == NULL) return NULL; }/g' main/reentrancy.c; "
        "fi"
    )
    if "readdir_r(dirp, entry, \\&result)" not in command:
        command = f"{php_readdir_patch}; {command}"
    upx_werror_patch = (
        "if [ -d src ] && grep -Rqs -- '-Werror' src 2>/dev/null "
        "&& grep -Rqs 'UPX' src 2>/dev/null; then "
        "find src -maxdepth 3 -type f \\( -name 'Makefile*' -o -name '*.mk' \\) "
        "-exec sed -i 's/[[:space:]]-Werror/ -Wno-error/g' {} +; "
        "fi"
    )
    if "grep -Rqs -- '-Werror' src" not in command:
        command = f"{upx_werror_patch}; {command}"
    return command

@logf("command")
def run_compile():
    # Release debugger before compile: LLDB holds the target binary open,
    # causing "Text file busy" when build script tries to cp over it.
    try:
        from tools.debugger.driver import debugger_exit
        debugger_exit()
    except Exception:
        pass  # Debugger may not be initialized (e.g. before stalk, zero-shot)

    for cmd in PRE_BUILD_CMDS:
        run_cmd(["bash", "-c", cmd])

    # We allow maximum of 3 minutes for the build
    response = run_cmd(["bash", "-c", BUILD_CMD], timeout=1800)
    print("Build command:", BUILD_CMD)
    for cmd in POST_BUILD_CMDS:
        run_cmd(["bash", "-c", cmd])

    return response
