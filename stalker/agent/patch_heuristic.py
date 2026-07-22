"""
Deterministic minimal patches when the LLM patch agent yields nothing but
constraints + suspect location imply a common off-by-one on __MIN bounds.
"""
from __future__ import annotations

import os
import re
from typing import Any

from tools.file.functions import file_get_content
from utils.logger import get_logger

NAME = "patch-heuristic"
logger = get_logger(NAME)


def try_heuristic_min_patch(profile: dict, suspect: dict, constraint: str) -> dict[str, Any] | None:
    """
    If the validated constraint tightens the bound by one (e.g. i_width - i_column - 1)
    and the source line has __MIN(..., p_sys->i_width - i_column) without the trailing -1,
    emit a single-line replacement patch.
    """
    _ = profile  # reserved for future workspace root resolution
    if not constraint or not suspect:
        return None
    # Constraint should mention tightening by one vs (i_column) — typical validated guards for this bug class
    if not re.search(r"i_column\s*-\s*1", constraint):
        return None

    path = suspect.get("file")
    line_no = suspect.get("line")
    try:
        line_no = int(line_no)
    except (TypeError, ValueError):
        return None
    if not path or line_no < 1 or not os.path.isfile(path):
        return None

    line_text = file_get_content(path, line_no, line_no)
    if not line_text or "__MIN" not in line_text:
        return None
    original = line_text.rstrip("\n")
    if re.search(r"i_width\s*-\s*i_column\s*-\s*1", original):
        return None

    new_line = re.sub(
        r"(p_sys->i_width\s*-\s*i_column)(\s*\))",
        r"\1 - 1\2",
        original,
        count=1,
    )
    if new_line == original:
        return None

    logger.info(f"Heuristic min patch at {path}:{line_no}")
    return {
        "patches": [{"file": path, "start_line": line_no, "end_line": line_no, "patch": new_line}],
        "retry": 0,
        "valid": False,
        "resign": False,
        "heuristic": True,
        "strategy": "loop_bound_fix",
        "location_type": "same_site",
        "semantic_risk": "low",
        "requires_regression_check": False,
    }
