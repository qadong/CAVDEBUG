import json
import os
from tools.file.functions import file_apply_patches, file_undo_patches
from utils.command import override_build, run_reproduce, run_validation_build
from utils.logger import logf


@logf(__name__, True)
def _validate_patch(patches, profile=None, logger=None) -> bool:
    if not file_apply_patches(patches):
        logger.error("Failed to apply patch")
        return False

    # test build
    logger.info("Testing build")
    return_code, _, stderr = run_validation_build(profile)
    file_undo_patches(patches)  # undo as source code no longer needed

    if return_code != 0:
        # compile error
        logger.error("Compilation error")
        logger.debug(stderr)
        return False

    # test reproduce
    logger.info("Trying to reproduce the bug")
    return_code, stdout, stderr = run_reproduce(profile)
    reproduce_output = stdout + stderr
    if return_code == -66:
        # timeout
        logger.error("Reproduce timeout")
        return False
    if return_code != 0:
        # not fixed
        logger.error("Sanitizer error")
        logger.debug(reproduce_output)
        return False
    logger.info("Bug not reproduced")

    # fixed
    return True


@logf(__name__, True)
def run_validate(profile, logger=None):
    patch_file = f"patches/{profile['id']}.json"
    if not os.path.exists(patch_file):
        logger.error(f"Patch file {patch_file} does not exist")
        return
    with open(patch_file, "r") as f:
        patches = json.load(f)["patches"]

    logger.info("Changing to the project source directory")
    os.chdir(profile["src"])
    logger.info("Current directory: %s", os.getcwd())

    if "build" in profile:
        build_cmd = profile["build"]
    else:
        build_cmd = "CFLAGS='-g' CXXFLAGS='-g' bear arvo compile"

    logger.warning("Overriding compile command: %s", build_cmd)
    BANNED = ["CFLAGS=-g", "CXXFLAGS=-g", "bear"]
    for banned in BANNED:
        build_cmd = build_cmd.replace(banned, "")
    logger.info("New compile command: %s", build_cmd)
    # override_build(build_cmd)

    if _validate_patch(patches, profile):
        logger.info("Patch is valid")
    else:
        logger.error("Invalid patch")

    logger.info("Validation completed")
