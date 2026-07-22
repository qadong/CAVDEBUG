from __future__ import annotations

from typing import Any


STATE_ONLY_NO_ANGELIC = "state_only_no_angelic"
NO_CFC = "no_cfc"
LLDB_ONLY = "lldb_only"
FULL_PIPELINE_BUDGET_MAX_ROUNDS = 3
PATCH_SEARCH_BUDGET_RETRIES = 3


def ablation_mode(profile: dict[str, Any] | None) -> str:
    if not isinstance(profile, dict):
        return ""
    return str(profile.get("ablation_mode", "") or "").strip()


def state_only_no_angelic(profile: dict[str, Any] | None) -> bool:
    if not isinstance(profile, dict):
        return False
    mode = ablation_mode(profile)
    if mode == LLDB_ONLY:
        return True
    if bool(profile.get("disable_angelic", False)):
        return True
    return mode == STATE_ONLY_NO_ANGELIC


def no_cfc(profile: dict[str, Any] | None) -> bool:
    return ablation_mode(profile) == NO_CFC


def lldb_only(profile: dict[str, Any] | None) -> bool:
    return ablation_mode(profile) == LLDB_ONLY


def full_pipeline_budget_limited(profile: dict[str, Any] | None) -> bool:
    if not isinstance(profile, dict):
        return True
    if state_only_no_angelic(profile):
        return False
    if bool(profile.get("unbounded_full_pipeline", False)):
        return False
    if bool(profile.get("disable_pipeline_budget_limits", False)):
        return False
    return bool(profile.get("limit_full_pipeline_budget", True))


def patch_search_budget_limited(profile: dict[str, Any] | None) -> bool:
    return state_only_no_angelic(profile) or full_pipeline_budget_limited(profile)
