import os
import shutil
import subprocess
from collections import defaultdict

from tools.file.functions import file_apply_patches, file_undo_patches
from utils.command import is_secbench_profile


def _git_repo_root(path: str) -> str | None:
    directory = os.path.dirname(os.path.abspath(path))
    try:
        result = subprocess.run(
            ["git", "-C", directory, "rev-parse", "--show-toplevel"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
        )
    except Exception:
        return None
    if result.returncode != 0:
        return None
    return result.stdout.strip() or None


def _git_diff_for_patches(patches: list[dict]) -> str:
    by_root: dict[str, list[str]] = defaultdict(list)
    for patch in patches:
        path = os.path.abspath(patch["file"])
        root = _git_repo_root(path)
        if root is None:
            continue
        relpath = os.path.relpath(path, root)
        if relpath not in by_root[root]:
            by_root[root].append(relpath)

    chunks = []
    for root, paths in by_root.items():
        result = subprocess.run(
            ["git", "-C", root, "diff", "--no-ext-diff", "--", *paths],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=30,
        )
        if result.returncode == 0 and result.stdout:
            # A blank context line is encoded as " \n" in a unified diff.
            # Stripping generic whitespace corrupts the hunk body while leaving
            # its header counts unchanged.
            chunks.append(result.stdout.rstrip("\n"))
    return "\n".join(chunks) + ("\n" if chunks else "")


def export_unified_diff(patches: list[dict], output_path: str, logger=None) -> bool:
    """
    Export the internal line-replacement patch format as a git unified diff.

    If the patch is already applied, the current git diff is used. If not, the
    patch is applied temporarily, diffed, then undone.
    """
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    diff_text = _git_diff_for_patches(patches)

    applied_temporarily = False
    if not diff_text:
        if not file_apply_patches(patches):
            if logger:
                logger.error("Failed to apply patch while exporting unified diff")
            return False
        applied_temporarily = True
        diff_text = _git_diff_for_patches(patches)

    if applied_temporarily:
        file_undo_patches(patches)

    with open(output_path, "w") as f:
        f.write(diff_text)
    return bool(diff_text)


def export_patch_artifacts(profile: dict, patch: dict, logger=None) -> dict:
    result_dir = profile["result_dir"]
    patch_diff = os.path.join(result_dir, "patch.diff")
    ok = export_unified_diff(patch["patches"], patch_diff, logger=logger)
    artifacts = {"unified_diff_output": patch_diff}
    if not ok and logger:
        logger.warning("Unified diff export produced an empty diff: %s", patch_diff)

    if is_secbench_profile(profile):
        model_patch = os.path.join(result_dir, "model_patch.diff")
        shutil.copyfile(patch_diff, model_patch)
        artifacts["secbench_model_patch_output"] = model_patch

    return artifacts
