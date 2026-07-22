#!/usr/bin/env python3
from __future__ import annotations

import argparse
import random
import re
from pathlib import Path


DEFAULT_INPUT_DIR = Path("datasets/tags/408")
DEFAULT_OUTPUT = DEFAULT_INPUT_DIR / "final_200.txt"
CHUNK_RE = re.compile(r"^(?P<start>\d{3})_(?P<end>\d{3})$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Randomly sample tags from datasets/tags/408 chunk files."
    )
    parser.add_argument("--input-dir", type=Path, default=DEFAULT_INPUT_DIR)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--count", type=int, default=200)
    parser.add_argument("--seed", type=int, default=None)
    return parser.parse_args()


def load_tags(input_dir: Path) -> list[str]:
    tags: list[str] = []
    for path in sorted(input_dir.iterdir()):
        match = CHUNK_RE.fullmatch(path.name)
        if not path.is_file() or match is None:
            continue
        start = int(match.group("start"))
        end = int(match.group("end"))
        if end - start > 99:
            continue
        for line in path.read_text(encoding="utf-8").splitlines():
            tag = line.strip()
            if tag:
                tags.append(tag)
    return tags


def main() -> None:
    args = parse_args()
    if args.count <= 0:
        raise SystemExit("--count must be positive")

    tags = load_tags(args.input_dir)
    if args.count > len(tags):
        raise SystemExit(f"cannot sample {args.count} tags from only {len(tags)} tags")

    rng = random.Random(args.seed)
    sampled = rng.sample(tags, args.count)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("\n".join(sampled) + "\n", encoding="utf-8")

    print(f"input tags: {len(tags)}")
    print(f"sampled tags: {len(sampled)}")
    print(f"output: {args.output}")


if __name__ == "__main__":
    main()
