import os
from utils.logger import logf
from utils.command import run_cmd


PROXY_ENV_VARS = (
    "http_proxy",
    "https_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "all_proxy",
    "ALL_PROXY",
    "no_proxy",
    "NO_PROXY",
)
APT_ENV_CLEAR = "env " + " ".join(f"-u {env_var}" for env_var in PROXY_ENV_VARS)


@logf("stalker")
def check_environment(logger=None):
    """
    Check necessary commands.
    """

    commands = ["lldb-mi", "lldb-10", "clangd", "bear"]
    response = {"ready": True, "commands": {}, "missing": []}

    for command in commands:
        description = command
        return_code, stdout, _ = run_cmd(["bash", "-c", f"command -v {command}"])
        if return_code == 0:
            response["commands"][description] = stdout.strip()
        else:
            response["ready"] = False
            response["missing"].append(description)

    logger.debug(f"Environment check: {response}")

    return response["ready"]


# @logf("stalker")
# def _setup_lldb(logger=None):
#     # ========================================================================
#     # setup wget apt-transport-https
#     # ------------------------------------------------------------------------
#     logger.debug("Installing wget apt-transport-https")
#     return_code, _, stderr = run_cmd(
#         ["bash", "-c", "apt-get install -y wget apt-transport-https"]
#     )
#     if return_code == 0:
#         logger.debug(f"wget & apt-transport-https installed")
#     else:
#         logger.error(f"Failed to install wget & apt-transport-https:\n{stderr}")
#         raise Exception("Failed to install wget & apt-transport-https")

#     # ========================================================================
#     # setup llvm source
#     # ------------------------------------------------------------------------
#     logger.debug("configuring llvm source")
#     return_code, _, stderr = run_cmd(
#         [
#             "bash",
#             "-c",
#             "wget --no-check-certificate -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add -",
#         ]
#     )
#     if return_code != 0:
#         logger.error(f"Failed to get apt-key:\n{stderr}")
#         raise Exception("Failed to get apt-key")

#     return_code, _, stderr = run_cmd(
#         [
#             "bash",
#             "-c",
#             "add-apt-repository 'deb http://apt.llvm.org/bionic/   llvm-toolchain-bionic-10  main'",
#         ]
#     )
#     if return_code != 0:
#         logger.error(f"Failed to add llvm apt repository:\n{stderr}")
#         raise Exception("Failed to add llvm apt repository")

#     return_code, _, stderr = run_cmd(
#         [
#             "bash",
#             "-c",
#             "apt update",
#         ]
#     )
#     if return_code != 0:
#         logger.error(f"Failed to update apt for LLVM:\n{stderr}")
#         raise Exception("Failed to update apt for LLVM")


def _get_ubuntu_codename(logger=None):
    os_release = {}
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if "=" not in line:
                    continue
                key, value = line.strip().split("=", 1)
                os_release[key] = value.strip('"')
    except FileNotFoundError:
        pass

    codename = os_release.get("VERSION_CODENAME") or os_release.get("UBUNTU_CODENAME")
    if codename:
        return codename

    if logger:
        logger.warning("Unable to detect Ubuntu codename, falling back to focal")
    return "focal"


@logf("stalker")
def _configure_package_sources(logger=None):
    codename = _get_ubuntu_codename(logger)
    source_list = f"""
deb http://mirrors.tuna.tsinghua.edu.cn/ubuntu/ {codename} main restricted universe multiverse
deb http://mirrors.tuna.tsinghua.edu.cn/ubuntu/ {codename}-updates main restricted universe multiverse
deb http://mirrors.tuna.tsinghua.edu.cn/ubuntu/ {codename}-backports main restricted universe multiverse
deb http://mirrors.tuna.tsinghua.edu.cn/ubuntu/ {codename}-security main restricted universe multiverse
"""
    pip_config = """
[global]
index-url = https://pypi.tuna.tsinghua.edu.cn/simple
trusted-host = pypi.tuna.tsinghua.edu.cn
"""
    SOURCE_LIST_PATH = "/etc/apt/sources.list"
    PIP_CONFIG_PATHS = (
        "/etc/pip.conf",
        "/root/.config/pip/pip.conf",
        "/root/.pip/pip.conf",
    )

    for env_var in PROXY_ENV_VARS:
        os.environ.pop(env_var, None)
    run_cmd(
        [
            "bash",
            "-c",
            "rm -f /etc/apt/apt.conf.d/*proxy* /etc/apt/apt.conf.d/*Proxy* || true",
        ]
    )

    logger.warning(f"Changing apt source list to TUNA ({codename})")
    with open(SOURCE_LIST_PATH, "w") as f:
        f.write(source_list.strip() + "\n")
    run_cmd(["bash", "-c", "rm -rf /var/lib/apt/lists/*"])
    logger.debug("Apt source list changed")

    logger.warning("Changing pip source to TUNA")
    for pip_config_path in PIP_CONFIG_PATHS:
        os.makedirs(os.path.dirname(pip_config_path), exist_ok=True)
        with open(pip_config_path, "w") as f:
            f.write(pip_config.strip() + "\n")
    logger.debug("Pip source changed")


@logf("stalker")
def _setup(logger=None):
    # ========================================================================
    # update apt
    # ------------------------------------------------------------------------

    logger.debug("Updating apt")
    apt_update_cmd = (
        f"{APT_ENV_CLEAR} apt-get "
        "-o Acquire::Retries=3 "
        "-o APT::Update::Error-Mode=any "
        "update"
    )
    return_code, stdout, stderr = run_cmd(["bash", "-c", apt_update_cmd])
    if return_code == 0:
        logger.debug(f"apt updated:\n{stdout}")
    else:
        logger.error(f"Failed to update apt:\n{stdout}\n{stderr}")
        raise Exception("Failed to update apt")

    _, bear_policy, bear_policy_err = run_cmd(["bash", "-c", f"{APT_ENV_CLEAR} apt-cache policy bear"])
    logger.debug(f"Bear apt policy:\n{bear_policy}\n{bear_policy_err}")

    # ========================================================================
    # setup Bear
    # ------------------------------------------------------------------------

    logger.debug("Installing Bear")
    return_code, stdout, stderr = run_cmd(["bash", "-c", f"{APT_ENV_CLEAR} apt-get install -y bear"])
    if return_code == 0:
        logger.debug(f"Bear installed")
    else:
        _, bear_policy, bear_policy_err = run_cmd(
            ["bash", "-c", f"{APT_ENV_CLEAR} apt-cache policy bear"]
        )
        logger.error(f"Failed to install Bear:\n{stdout}\n{stderr}\n{bear_policy}\n{bear_policy_err}")
        raise Exception("Failed to install Bear")

    # ========================================================================
    # setup clangd
    # ------------------------------------------------------------------------

    logger.debug("Mounting clangd")
    if os.path.exists("/root/opt/clangd/bin/clangd"):
        run_cmd(["bash", "-c", "ln -s /root/opt/clangd/bin/clangd /usr/bin/clangd"])
        logger.debug("clangd mounted")
    else:
        logger.error("Failed to mount clangd")
        raise Exception("Failed to mount clangd")

    # ========================================================================
    # setup LLDB
    # ------------------------------------------------------------------------

    logger.debug("Installing LLDB")
    return_code, _, stderr = run_cmd(
        ["bash", "-c", f"{APT_ENV_CLEAR} apt-get install -y lldb-10 --fix-missing"]
    )
    if return_code == 0:
        logger.debug(f"LLDB installed")
    else:
        logger.error(f"Failed to install LLDB:\n{stderr}")
        raise Exception("Failed to install LLDB")

    # ========================================================================
    # setup LLDB MI
    # ------------------------------------------------------------------------

    logger.debug("Mounting lldb-mi")
    if os.path.exists("/root/opt/lldb-mi/bin/lldb-mi"):
        # we need to mend some symlinks
        run_cmd(["bash", "-c", "ln -s -f /usr/lib/llvm-10 /usr/lib/llvm"])
        run_cmd(
            [
                "bash",
                "-c",
                "ln -s -f /usr/lib/llvm/lib/liblldb.so.1 /usr/lib/llvm/lib/liblldb.so.10",
            ]
        )
        run_cmd(
            [
                "bash",
                "-c",
                "ln -s -f /usr/lib/llvm/bin/lldb-server-10.0.0 /usr/bin/lldb-server-10.0.0",
            ]
        )
        run_cmd(
            ["bash", "-c", "ln -s -f /root/opt/lldb-mi/bin/lldb-mi /usr/bin/lldb-mi"]
        )
        # export variable LLDB_DEBUGSERVER_PATH
        os.environ["LLDB_DEBUGSERVER_PATH"] = "/usr/lib/llvm/bin/lldb-server-10.0.0"

        logger.debug("lldb-mi mounted")
    else:
        logger.error("Failed to mount lldb-mi")
        raise Exception("Failed to mount lldb-mi")


@logf("stalker", True)
def setup(logger=None):
    _configure_package_sources()

    if check_environment():
        logger.info("No setup required")
        return True

    try:
        _setup()
        return True
    except Exception as e:
        logger.error(f"Failed to setup environment: {e}")
        return False


@logf("stalker", True)
def configure_environment(logger=None):
    logger.debug("Overriding CFLAGS and CXXFLAGS")
    
    # 1. 把导致 LLDB 看不到变量的两个元凶都加到黑名单里
    BANNED = ["-O1", "-gline-tables-only"] 

    if "CFLAGS" not in os.environ:
        os.environ["CFLAGS"] = ""
    cflags = os.environ["CFLAGS"]
    logger.debug(f"Current CFLAGS: {cflags}")
    
    for banned in BANNED:
        cflags = cflags.replace(banned, "")
        
    # 2. 构造新的 flag
    new_cflags = f"{cflags} -g -fno-inline -O0"
    os.environ["CFLAGS"] = new_cflags
    # 3. 修正：这里应该打印 new_cflags，原来的代码打印的是还没加 -g 的 cflags
    logger.debug(f"New CFLAGS: {new_cflags}") 

    if "CXXFLAGS" not in os.environ:
        os.environ["CXXFLAGS"] = ""
    cxxflags = os.environ["CXXFLAGS"]
    logger.debug(f"Current CXXFLAGS: {cxxflags}")
    
    for banned in BANNED:
        cxxflags = cxxflags.replace(banned, "")
        
    new_cxxflags = f"{cxxflags} -g -fno-inline -O0"
    os.environ["CXXFLAGS"] = new_cxxflags
    logger.debug(f"New CXXFLAGS: {new_cxxflags}")
