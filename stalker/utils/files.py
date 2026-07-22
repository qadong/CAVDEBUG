import json
import os
import tempfile


def make_json_safe(data):
    if isinstance(data, (str, int, float, bool)) or data is None:
        return data
    if isinstance(data, dict):
        return {str(k): make_json_safe(v) for k, v in data.items()}
    if isinstance(data, (list, tuple, set)):
        return [make_json_safe(v) for v in data]
    if hasattr(data, "_asdict"):
        try:
            return make_json_safe(data._asdict())
        except Exception:
            pass
    if hasattr(data, "__dict__"):
        try:
            return {
                "__class__": data.__class__.__name__,
                **make_json_safe(vars(data)),
            }
        except Exception:
            pass
    return repr(data)


def dump_json(data, filename):
    parent = os.path.dirname(filename)
    if not os.path.exists(parent):
        os.makedirs(parent)
    safe = make_json_safe(data)
    fd, tmp_path = tempfile.mkstemp(prefix=".tmp_json_", suffix=".json", dir=parent or None)
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(safe, f, indent=4)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, filename)
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass


def load_json(filename):
    """
    Load a JSON configuration file with support for inheritance.
    
    The `inherit` field allows a configuration file to inherit settings from another file.
    When an `inherit` field is present, the parent file is loaded first, then the current
    file's fields are merged on top (overriding parent fields with the same name).
    
    Example:
        base/libplist.json:
            {"src": "/src/libplist", "file": "/out/oplist_fuzzer", "args": ["/tmp/poc"]}
        
        55035.json (with inherit: "base/libplist.json"):
            {"inherit": "base/libplist.json", "constraint": "..."}
        
        Result: All fields from base/libplist.json, with constraint from 55035.json
    
    Args:
        filename: Path to the JSON file to load
        
    Returns:
        Merged configuration dictionary
    """
    if not os.path.exists(filename):
        raise FileNotFoundError(f"{filename} does not exists")

    with open(filename, "r") as f:
        data = json.load(f)

    if "inherit" in data:
        inherit_path = data["inherit"]
        parent_path = os.path.join(os.path.dirname(filename), inherit_path)
        
        # Validate that inherit path is a file, not a directory
        if os.path.isdir(parent_path):
            raise ValueError(
                f"Invalid inherit field in {filename}: '{inherit_path}' resolves to a directory, not a file. "
                f"Please specify a file path (e.g., 'base/libplist.json') instead of a directory."
            )
        
        if not os.path.exists(parent_path):
            raise FileNotFoundError(
                f"Invalid inherit field in {filename}: parent file '{inherit_path}' (resolved to '{parent_path}') does not exist."
            )
        
        parent = load_json(parent_path)
        # Merge parent config with current config (current overrides parent)
        data = {**parent, **data}

    return data
