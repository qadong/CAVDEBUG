# Export source code for a given project

import argparse
import os
import shutil

from utils.files import load_json

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="export.py",
        description="Bug Stalker Source Code Exporter",
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
        "--output",
        type=str,
        required=True,
        help="Output directory",
    )
    args = parser.parse_args()

    profile = load_json(f"profiles/{args.project}.json")

    src_path = profile["src"]
    dst_path = os.path.join(args.output, args.project)

    # remove .git directory
    BANNED = [
        ".git",
        "bin",
        "tests",
        "test",
        "doc",
        "docs",
        ".github",
        ".gitlab-ci",
        "example",
        "fuzz",
    ]
    for banned in BANNED:
        shutil.rmtree(os.path.join(src_path, banned), ignore_errors=True)

    if os.path.exists(dst_path):
        shutil.rmtree(dst_path)

    shutil.copytree(src_path, dst_path)
