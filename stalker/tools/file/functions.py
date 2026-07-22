from utils.logger import logf


NAME = "file"

# =============================================================================
# Editor functions
# =============================================================================

FILE_BACKUPS = {}


def editor_backup_file(filename: str) -> None:
    """
    Backup the given file.
    """
    global FILE_BACKUPS
    with open(filename, "r") as f:
        FILE_BACKUPS[filename] = f.read()


def editor_restore_file(filename: str) -> None:
    """
    Restore the given file.
    """
    content = FILE_BACKUPS.get(filename, None)
    if content is None:
        raise FileNotFoundError(f"File {filename} not found in backups")
    with open(filename, "w") as f:
        f.write(content)


def editor_replace(
    filename: str, start_line: int, end_line: int, new_content: str
) -> None:
    """
    Replace lines from start_line to end_line (both inclusive) with new_content.
    """
    with open(filename, "r") as f:
        lines = f.readlines()
    new_lines = [line + "\n" for line in new_content.split("\n")]
    lines = lines[: start_line - 1] + new_lines + lines[end_line:]
    with open(filename, "w") as f:
        f.write("".join(lines))


# deprecated
def editor_insert_after(filename: str, line: int, new_content: str) -> None:
    """
    Insert new_content after the given line.
    """
    with open(filename, "r") as f:
        lines = f.readlines()
    new_lines = [line + "\n" for line in new_content.split("\n")]
    lines = lines[:line] + new_lines + lines[line:]
    with open(filename, "w") as f:
        f.write("".join(lines))


# =============================================================================
# File functions
# =============================================================================


def file_get_line_count(filename: str):
    """
    Get the number of lines in a file.
    Return -1 if the file does not exist.
    """
    with open(filename, "r") as f:
        lines = f.readlines()
    return len(lines)


def file_get_content(filename: str, start_line: int, end_line: int):
    """
    Get the content of a file from start_line to end_line (both inclusive).
    Return empty string if the file does not exist or the range is invalid.
    """
    with open(filename, "r") as f:
        lines = f.readlines()
    end_line = min(end_line, len(lines) - 1)
    if start_line < 1:
        start_line = 1
    if end_line < start_line:
        return ""
    return "".join(lines[start_line - 1 : end_line])


def file_get_decorated_content(filename: str, start_line: int, end_line: int):
    """
    Get the content of a file from start_line to end_line (both inclusive)
    with line_number in each line.
    """
    with open(filename, "r") as f:
        lines = f.readlines()
    end_line = min(end_line, len(lines) - 1)
    if start_line < 1:
        start_line = 1
    if end_line < start_line:
        return ""
    content = ""
    for i, line in enumerate(lines[start_line - 1 : end_line], start_line):
        content += f"{i:3} {line}"
    return content


@logf(NAME, True)
def file_apply_patch(file, start_line, end_line, content, logger=None) -> bool:
    try:
        editor_backup_file(file)
        editor_replace(file, start_line, end_line, content)
    except Exception as e:
        logger.error(f"Error applying patch: {e}")
        return False
    return True


def _count_lines(content):
    return content.count("\n") + 1


def _apply_patch_in_file(file, patches):
    sorted_patches = sorted(patches, key=lambda x: x[0])
    line_diff = 0
    for start_line, end_line, content in sorted_patches:
        content = content.rstrip()
        lines = _count_lines(content)
        editor_replace(file, start_line + line_diff, end_line + line_diff, content)
        line_diff += lines - (end_line - start_line + 1)


@logf(NAME, True)
def file_apply_patches(patches, logger=None) -> bool:
    file_patch = {}
    for patch in patches:
        file = patch["file"]
        if file not in file_patch:
            file_patch[file] = []
        file_patch[file].append(
            (patch["start_line"], patch["end_line"], patch["patch"])
        )
    try:
        for file, patches in file_patch.items():
            editor_backup_file(file)
            _apply_patch_in_file(file, patches)
    except Exception as e:
        logger.error(f"Error applying patches: {e}")
        return False

    return True


@logf(NAME, True)
def file_undo_patch(file, logger=None) -> bool:
    try:
        editor_restore_file(file)
    except Exception as e:
        logger.error(f"Error undoing patch: {e}")
        return False

    return True


@logf(NAME, True)
def file_undo_patches(patches, logger=None) -> bool:
    files = set()
    for patch in patches:
        files.add(patch["file"])
    try:
        for file in files:
            editor_restore_file(file)
    except Exception as e:
        logger.error(f"Error undoing patches: {e}")
        return False

    return True
