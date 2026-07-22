#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

from dotenv import load_dotenv


REPO_ROOT = Path(__file__).resolve().parents[1]
load_dotenv(REPO_ROOT / ".env", override=False)
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from stalker.judge.semantic_security import run_cli


if __name__ == "__main__":
    raise SystemExit(run_cli())
