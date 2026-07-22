from typing import Tuple


def parse_lldb_output(line: str) -> Tuple[str, str]:
    """
    Parse the output of LLDB, e.g.

    Input:  =thread-created,id="1",group-id="i1"
    Output: ("=thread-created, "id=\"1\",group-id=\"i1\"")
    """
    if line[0] == "^":
        return (line[0], line[1:])
    if line[0] == "~" or line[0] == "&" or line[0] == "@":
        return (line[0], line[2:-1])
    # *, =
    index = line.find(",")
    return (line[:index], line[index + 1 :])


def _parse_object_impl(text: str) -> tuple[str, int]:
    """
    Return parsed object and the text length of the object.
    """
    if text[0] == '"':
        index = text.find('"', 1)
        while text[index - 1] == "\\":
            index = text.find('"', index + 1)
        return text[1:index], index + 1
    if text[0] == "[":
        arr = []
        cursor = 1
        while text[cursor] != "]":
            obj, length = _parse_object_impl(text[cursor:])
            arr.append(obj)
            cursor += length
            if text[cursor] == ",":
                cursor += 1
        return arr, cursor + 1
    if text[0] == "{":
        obj = {}
        cursor = 1
        while text[cursor] != "}":
            # find key
            index = text.find("=", cursor)
            key = text[cursor:index]
            cursor = index + 1
            # find value
            value, length = _parse_object_impl(text[cursor:])
            obj[key] = value
            cursor += length
            if text[cursor] == ",":
                cursor += 1
        return obj, cursor + 1

    raise ValueError("Invalid object")


def parse_object(text: str) -> dict:
    obj, _ = _parse_object_impl(text)
    return obj


def parse_lldb_info(info: str) -> dict[str, str]:
    """
    Parse the info output of LLDB, e.g.

    Input:  id="1",group-id="i1"
    Output: {"id": "1", "group-id": "i1"}
    """
    return parse_object("{" + info + "}")
