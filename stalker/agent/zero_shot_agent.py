import os
import re
import shutil
from typing import List, Tuple
from agent.generic_agent import GenericAgent
from utils.command import run_reproduce, run_validation_build
from utils.parsers import parse_sanitizer_output, parse_patch_string
from utils.files import dump_json
from utils.patch_export import export_patch_artifacts
from tools.file.functions import (
    file_apply_patches,
    file_get_content,
    file_undo_patches,
)
from tools.lsp.functions import (
    lsp_get_function,
    lsp_to_abs_path,
)
from utils.logger import get_logger, logf


NAME = "zero-shot-agent"
MAX_RETRIES = 3

# =============================================================================
# Prompt definitions
# =============================================================================
SYSTEM_PROMPT = (
    "You are an Automatic Program Repair Tool.\n"
    # <hr>
    "When you complete thinking, call `submit` to submit a patch. "
    "You should give the patch in the format of <filename>:<start line>-<end line>\\n<patch content>.\n"
    "<start line> and <end line> are the line number in the original unmodified source code.\n"
    "The patch should involve less code changes and fewer locations as possible.\n"
    "It means to replace the content from the start line to the end line (both inclusive and start from 1) with the patch content.\n"
    "If multiple unoverlapped locations are affected, you can provide multiple patches in the given format in a list.\n"
    "It will respond with whether the patch fixed the crash or not. "
    f"If the patch fails to fix the crash, you can try another patch up to {MAX_RETRIES} times.\n"
    "If you are unable to provide a patch, call `resign` to skip the current round.\n"
    "After successful fix or `resign`, stop calling any function and output TERMINATE in the next response to end this conversation.\n"
)

INITIAL_PROMPT = """
// Provide a fix for the buggy function in file /src/search/search.c

// Buggy Function
int binarySearch(int arr[], int l, int r, int x)
{{
    if (r >= l) {{
        int mid = l + (r + l) / 2;
        if (arr[mid] == x)
            return mid;
        if (arr[mid] > x)
            return binarySearch(arr, l, mid - 1, x);
        return binarySearch(arr, mid + 1, r, x);
    }}
    return -1;
}}

Let's think step by step. The bug location is in the calculation of the "mid" variable. The line is currently: int mid = l + (r + l) / 2.

// Fixed Function
int binarySearch(int arr[], int l, int r, int x)
{{
    if (r >= l) {{
        int mid = l + (r - l) / 2;
        if (arr[mid] == x)
            return mid;
        if (arr[mid] > x)
            return binarySearch(arr, l, mid - 1, x);
        return binarySearch(arr, mid + 1, r, x);
    }}
    return -1;
}}

// Provide a fix for the buggy function in file /src/count/count.c

// Buggy Function
int bitcount(int n) 
{{
    int count = 0;
    while (n != 0) {{
        n = (n ^ (n - 1));
        count++;
    }}
    return count;
}}

Let's think step by step. The bug in the bitcount function is with the expression n = (n ^ (n - 1)). This expression is used to clear the rightmost set bit of n and update the count of set bits. However, it is incorrect and will result in an infinite loop for certain inputs.

// Fixed Function
int bitcount(int n) 
{{
    int count = 0;
    while (n != 0) {{
        n = (n & (n - 1));
        count++;
    }}
    return count;
}}

// Provide a fix for the buggy function in file {}

// Buggy Function
{}

Let's think step by step. 
"""

# =============================================================================
# Agent hooks
# =============================================================================

# For the agent hook, only one debug session at a time.
# Global state
GLOBAL_STATE = {
    "session": None,
    "profile": None,
    "patches": None,
    "resign": False,
    "retry": 0,
    "valid": False,
}


def reset_global_state():
    global GLOBAL_STATE
    GLOBAL_STATE = {
        "session": None,
        "profile": None,
        "patches": None,
        "resign": False,
        "retry": 0,
        "valid": False,
    }


# @logf(NAME, True)
def function_body(file: str, function: str) -> str:
    """
    Get the complete definition of a function.
    """
    get_logger(NAME).info(f"Invoking function_body({file}, {function})")

    file = lsp_to_abs_path(str(file))
    function = str(function)

    response = lsp_get_function(file, function)
    get_logger(NAME).debug(response)

    return response


# @logf(NAME, True)
def submit(patches: List[str]) -> str:
    """
    Submit the analysis.
    """
    logger = get_logger(NAME)

    logger.info(f"Invoking submit({patches})")

    global GLOBAL_STATE

    MSG_INVALID_RESPONSE = (
        "Invalid patch format, "
        "please provide the patch in the format of <filename>:<start line>-<end line>\\n<patch content>. "
        "It means to replace the content from the start line to the end line (both inclusive) with the patch content."
    )

    parsed_patches = []
    for raw_patch in patches:
        file, start_line, end_line, patch = parse_patch_string(raw_patch)
        if file is None:
            logger.error(f"Invalid patch format: {raw_patch}")
            return MSG_INVALID_RESPONSE
        parsed_patches.append(
            {
                "file": file,
                "start_line": start_line,
                "end_line": end_line,
                "patch": patch,
            }
        )

    GLOBAL_STATE["patches"] = parsed_patches

    status, message = check_patch()
    if status:
        logger.info("Patch successfully fixed the crash")
        GLOBAL_STATE["valid"] = True
        return "Patch successfully fixed the crash"

    GLOBAL_STATE["valid"] = False
    GLOBAL_STATE["retry"] += 1
    if GLOBAL_STATE["retry"] < MAX_RETRIES:
        logger.warning("Invalid patch, retry scheduled")
        return (
            "Patch failed to fix the crash, please try another patch. "
            "The error message is as follows:\n"
            f"{message}"
        )

    logger.error("Failed to fix the crash after 3 retries")
    # failed after MAX_RETRIES retries, resign by fake success
    return "Patch successfully fixed the crash"


# @logf(NAME, True)
def resign() -> None:
    """
    Resign from the current round.
    """
    get_logger(NAME).info(f"Invoking resign")
    global GLOBAL_STATE
    GLOBAL_STATE["resign"] = True


def get_generic_agent():
    agent = GenericAgent("Wrecker", SYSTEM_PROMPT)

    agent.register_hook(submit, "Submit the patch")
    agent.register_hook(resign, "Resign from the current round")

    return agent


@logf(NAME, True)
def check_patch(logger=None) -> Tuple[bool, str]:
    """
    Return [True, ""] if the patch is valid, otherwise return [False, message].
    """

    MSG_FAILED_TO_APPLY_PATCH = (
        "Failed to apply patch, please check the location of the patch"
    )
    MSG_COMPILE_ERROR = "Compilation error: \n```\n{}\n```"
    MSG_SANITIZER_ERROR = "Patch does not fix the crash: \n```\n{}\n```"

    if not file_apply_patches(GLOBAL_STATE["patches"]):
        logger.error("Failed to apply patch")
        return False, MSG_FAILED_TO_APPLY_PATCH

    # pause and await user input
    # input("Press Enter to continue...")

    # test build
    return_code, _, stderr = run_validation_build(GLOBAL_STATE.get("profile"))
    file_undo_patches(GLOBAL_STATE["patches"])  # undo as source code no longer needed

    if return_code != 0:
        # compile error
        # xmlreader.c:1440:35: error: expected ';' after expression
        logger.error("Compilation error")
        logger.debug(stderr)
        errors = []
        for line in stderr.split("\n"):
            if "error:" in line:
                # remove the ANSI color code
                errors.append(re.sub(r"\x1b\[[0-9;]*m", "", line.strip()))
        return False, MSG_COMPILE_ERROR.format("\n".join(errors))

    return_code, stdout, stderr = run_reproduce(GLOBAL_STATE.get("profile"))
    reproduce_output = stdout + stderr
    if return_code == -66:
        # timeout
        logger.error("Reproduce timeout")
        return (
            False,
            "Program takes too long to finish, perhaps caused by infinite loop. Please provide another patch.",
        )
    if return_code != 0:
        # not fixed
        logger.error("Sanitizer error")
        error, _ = parse_sanitizer_output(reproduce_output)
        if error is None:
            logger.error("Invalid sanitizer output")
            error = "Unable to parse sanitizer output, call `resign` to quit."
        return False, MSG_SANITIZER_ERROR.format(error)

    # fixed
    return True, ""


# =============================================================================
# Patch agent
# =============================================================================


class PatchInput:
    def __init__(self, profile, file, func):
        self.profile = profile
        self.file = file
        self.func = func


class ChatPatchSession:
    def __init__(self, i: PatchInput):
        self._input = i

    @logf(NAME, True)
    def run(self, logger=None):
        global GLOBAL_STATE

        reset_global_state()
        GLOBAL_STATE["session"] = self
        GLOBAL_STATE["profile"] = self._input.profile

        initaial_prompt = self._get_initial_prompt()
        agent = get_generic_agent()
        chat = agent.initiate(initaial_prompt)
        self._save_chat(chat)

        patch = None
        if GLOBAL_STATE["resign"]:
            logger.error("Patch agent resigned")
        elif GLOBAL_STATE["patches"] is None:
            logger.error("Incomplete patch")
        else:
            patch = {"patches": GLOBAL_STATE["patches"]}
            logger.info("Patch generated")

        if patch is not None:
            patch["retry"] = GLOBAL_STATE["retry"]
            patch["valid"] = GLOBAL_STATE["valid"]
            patch["resign"] = GLOBAL_STATE["resign"]

        self._save_patch(patch)

        logger.warning("Patch generation completed")

        return patch

    def _get_initial_prompt(self):
        file = self._input.file
        func = function_body(file, self._input.func)
        if func == "":
            raise Exception(
                f"Function {self._input.func} not found in file {self._input.file}"
            )
        return INITIAL_PROMPT.format(file, func)

    def _save_chat(self, chat):
        filename = os.path.join(self._input.profile["chat_dir"], f"patch.json")
        dump_json(chat, filename)

    @logf(NAME)
    def _save_patch(self, patch, logger=None):
        logger.info("Saving patch to %s", self._input.profile["patch_output"])
        if patch is None:
            dump_json({"failed": True}, self._input.profile["patch_output"])
            return
        patch.update(export_patch_artifacts(self._input.profile, patch, logger=logger))
        dump_json(patch, self._input.profile["patch_output"])

        # save file to result
        for p in patch["patches"]:
            filename = os.path.basename(p["file"])
            if not os.path.exists(lsp_to_abs_path(filename)):
                logger.warning(
                    "File %s not found in LSP working directory, skipping copy",
                    filename,
                )
                continue
            shutil.copyfile(
                lsp_to_abs_path(filename),
                os.path.join(self._input.profile["result_dir"], filename),
            )

        # save readable patch to patch.txt
        with open(
            os.path.join(self._input.profile["result_dir"], "patch.txt"), "w"
        ) as f:
            for p in patch["patches"]:
                f.write(f"File: {p['file']}\n")
                f.write(f"Affected lines: {p['start_line']}-{p['end_line']}\n")

                content = file_get_content(p["file"], p["start_line"], p["end_line"])
                f.write(f"\n--- Original content ---\n\n{content}\n")

                content = p["patch"]
                f.write(f"\n--- Patch content ---\n\n{content}\n\n")


@logf(NAME, True)
def chat(profile, info, logger=None):
    session = ChatPatchSession(PatchInput(profile, info["file"], info["func"]))
    return session.run()
