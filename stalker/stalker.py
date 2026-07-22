import argparse
import json
import os
import shutil
import sys
from datetime import datetime
from setup import configure_environment, setup
from test import run_tests
from agent import stalk_agent
from agent.generic_agent import load_llm_config
from fix import set_current_id
from utils.files import load_json
from utils.metrics import write_case_summary
from validate import run_validate
from utils.command import override_build, set_postbuild, set_prebuild
from utils.logger import configure_logger, get_logger, logf


@logf("stalker")
def load_project(project_id, logger=None):
    profile_path = f"profiles/{project_id}.json"
    if not os.path.exists(profile_path):
        # For compatibility with older scripts, try the workspace path
        profile_path = f"workspace/profiles/{project_id}.json"

    profile = load_json(profile_path)

    if "args" not in profile:
        profile["args"] = []
    if "env" not in profile:
        profile["env"] = {}
    if profile.get("runner") == "secbench" or profile.get("secbench"):
        if not profile.get("bug_report"):
            case_dir = (profile.get("secbench") or {}).get("case_dir")
            if case_dir:
                case_dirs = [case_dir]
                if case_dir.startswith("workspace/"):
                    case_dirs.append(case_dir.removeprefix("workspace/"))
                for candidate in case_dirs:
                    row_path = os.path.join(candidate, "row.json")
                    if os.path.exists(row_path):
                        row = load_json(row_path)
                        profile["bug_report"] = row.get("bug_report") or ""
                        break
        if not profile.get("bug_description") and profile.get("constraint"):
            profile["bug_description"] = profile.get("constraint")
        profile["constraint"] = ""

    profile["id"] = project_id

    return profile


@logf("stalker")
def main(profile, mode, logger=None):
    logger.warning("Bug Stalker started!")

    if mode == "validate":
        logger.info("Validation only, setup skipped")
    else:
        logger.info("Setting up the environment")
        if not setup():
            logger.error("Failed to setup the environment")
            exit(1)

    configure_environment()

    if "pre_build" in profile:
        set_prebuild(profile["pre_build"])
    if "post_build" in profile:
        set_postbuild(profile["post_build"])
    if "build" in profile:
        override_build(profile["build"])

    set_current_id(profile["id"])

    try:
        if mode == "test":
            logger.warning("Running tests")
            run_tests()
        elif mode == "validate":
            logger.warning("Validating the project")
            run_validate(profile)
        else:
            stalk_agent.stalk(profile)
            try:
                write_case_summary(profile, logger=logger)
            except Exception as metrics_exc:
                logger.warning(f"Failed to write case summary: {metrics_exc}")
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        logger.error(e, exc_info=True)
        raise
    finally:
        pass

    logger.error("See you later!")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="stalker.py",
        description="Bug Stalker",
        epilog="Enjoy the program! :)",
    )
    parser.add_argument(
        "--project",
        type=str,
        default="",
        required=True,
        help="Project ID",
    )
    parser.add_argument(
        "--logs",
        type=str,
        default=os.environ.get("STALKER_LOGS_DIR", "/root/logs"),
        required=False,
        help="Logs directory",
    )
    parser.add_argument(
        "--results",
        type=str,
        default=os.environ.get("STALKER_RESULTS_DIR", "/root/results"),
        required=False,
        help="Results directory",
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="Run tests",
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Run validation only",
    )
    parser.add_argument(
        "--disable-constraint",
        action="store_true",
        help="Disable constraint",
    )
    parser.add_argument(
        "--zero-shot",
        action="store_true",
        help="Use zero-shot mode",
    )
    parser.add_argument(
        "--ablation-state-only-no-angelic",
        action="store_true",
        help="Disable angelic counterfactual mutation/search; debug may only observe program state before patching.",
    )
    parser.add_argument(
        "--ablation-no-cfc",
        action="store_true",
        help="Skip CounterfactualContractAgent; run DebugAgent with angelic intervention evidence directly into PatchAgent.",
    )
    parser.add_argument(
        "--ablation-lldb-only",
        action="store_true",
        help="Run observation-only LLDB DebugAgent directly into a clean LLDB-only PatchAgent prompt.",
    )

    args = parser.parse_args()

    ablation_count = sum(
        bool(flag)
        for flag in (
            args.ablation_state_only_no_angelic,
            args.ablation_no_cfc,
            args.ablation_lldb_only,
        )
    )
    if ablation_count > 1:
        parser.error("Choose only one ablation mode: --ablation-state-only-no-angelic, --ablation-no-cfc, or --ablation-lldb-only")

    # Decide mode early, so we can isolate validate outputs before any deletion/log init.
    mode = "run"
    if args.test:
        mode = "test"
    elif args.validate:
        mode = "validate"

    # In validate mode, NEVER overwrite existing logs/results.
    # We write into a timestamped subdirectory under the provided base paths.
    if mode == "validate":
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        args.results = os.path.join(args.results, f"validate-{ts}")
        args.logs = os.path.join(args.logs, f"validate-{ts}")

    # empty results directory (non-validate only)
    if mode != "validate":
        shutil.rmtree(args.results, ignore_errors=True)

    os.makedirs(args.results, exist_ok=True)
    os.makedirs(args.logs, exist_ok=True)

    # configure logger
    configure_logger(args.logs)

    logger = get_logger("stalker")

    # load profile
    profile = load_project(project_id=args.project)
    _, clean_config = load_llm_config()

    profile["llm_config"] = clean_config
    profile["result_dir"] = args.results
    profile["chat_dir"] = os.path.join(args.results, "chat")
    profile["meta_output"] = os.path.join(args.results, "meta.json")
    profile["root_cause_output"] = os.path.join(args.results, "root_cause.json")
    profile["patch_output"] = os.path.join(args.results, "patch.json")

    profile["use_constraint"] = not args.disable_constraint
    if args.disable_constraint:
        logger.warning("Agent being jammed, constraint disabled")
    profile["zero_shot"] = args.zero_shot
    if args.zero_shot:
        logger.warning("Zero-shot mode enabled")
    if args.ablation_state_only_no_angelic:
        profile["ablation_mode"] = "state_only_no_angelic"
        profile["disable_angelic"] = True
        logger.warning("Ablation enabled: state-only, no angelic counterfactuals")
    if args.ablation_no_cfc:
        profile["ablation_mode"] = "no_cfc"
        logger.warning("Ablation enabled: no CounterfactualContractAgent; DebugAgent routes directly to PatchAgent")
    if args.ablation_lldb_only:
        profile["ablation_mode"] = "lldb_only"
        profile["disable_angelic"] = True
        logger.warning("Ablation enabled: LLDB-only DebugAgent routes directly to clean PatchAgent")

    logger.info(f"Profile loaded: {json.dumps(profile,indent=4)}")

    try:
        main(profile=profile, mode=mode)
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        sys.exit(1)
