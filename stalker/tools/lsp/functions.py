import os
from utils.logger import logf
from tools.lsp.integration import uri_to_path
from tools.lsp.driver import lsp_instance
from tools.file.functions import (
    file_get_content,
    file_get_decorated_content,
    file_get_line_count,
)


def _get_fuzzy_position(filename, lineno, symbol, fuzzy_range=10):
    line_count = file_get_line_count(filename)

    lines_to_search = [lineno]
    for i in range(1, fuzzy_range + 1):
        if lineno - i > 0:
            lines_to_search.append(lineno - i)
        if lineno + i <= line_count:
            lines_to_search.append(lineno + i)
    for i in lines_to_search:
        line = file_get_content(filename, i, i)
        pos = line.find(symbol)
        if pos != -1:
            # replace tabs with spaces
            char = pos + len(symbol) + 1
            return i, char
    return None, None


def lsp_get_symbol_definition(filename, lineno, symbol) -> str:
    """
    Get the definition of a symbol at a given position.
    Will perform a fuzzy search around the line.
    """
    lsp = lsp_instance()
    filename = lsp_to_abs_path(filename)
    line, char = _get_fuzzy_position(filename, lineno, symbol)
    if line is None:
        return f"Symbol {symbol} not found in {filename} around line {lineno}."
    response = lsp.definition(filename, line, char)
    if response is None:
        return (
            f"Definition of {symbol} not available in {filename} around line {lineno}."
        )
    file = uri_to_path(response["uri"])
    start_line = response["range"]["start"]["line"] + 1
    end_line = response["range"]["end"]["line"] + 1
    return file_get_decorated_content(file, start_line, end_line)


def lsp_get_symbol_summary(filename, lineno, symbol) -> str:
    """
    Get the hover information of a symbol at a given position.
    Will perform a fuzzy search around the line.
    """
    lsp = lsp_instance()
    filename = lsp_to_abs_path(filename)
    line, char = _get_fuzzy_position(filename, lineno, symbol)
    if line is None:
        return f"Symbol {symbol} not found in {filename} around line {lineno}."
    response = lsp.summary(filename, line, char)
    if response is None:
        return f"Summary of {symbol} not available in {filename} around line {lineno}."
    return response["contents"]["value"]


def lsp_get_function(filename, function) -> str:
    """
    Get the function definition.
    Return "" if the function is not found.
    """
    lsp = lsp_instance()
    filename = lsp_to_abs_path(filename)
    if not os.path.exists(filename):
        return ""
    symbols = lsp.document_symbol(filename)
    body = ""
    size = 0
    for symbol in symbols:
        if symbol["name"] == function:
            start_line = symbol["location"]["range"]["start"]["line"] + 1
            end_line = symbol["location"]["range"]["end"]["line"] + 1
            if end_line - start_line + 1 > size:
                size = end_line - start_line
                body = file_get_decorated_content(filename, start_line, end_line)
    return body


@logf("lsp")
def lsp_to_abs_path(filename, logger=None) -> str:
    """
    Convert a relative path to an absolute path. It is used by LSP functions to
    convert the relative file path in GDB to an absolute path in LSP working
    directory.
    """
    lsp = lsp_instance()
    path = lsp.to_abs_path(filename)
    if os.path.exists(path):
        return path

    basename = os.path.basename(filename)
    # search for the file under cwd
    for root, _, files in os.walk(lsp.get_cwd()):
        if basename in files:
            return os.path.join(root, basename)

    logger.warning(f"File {filename} not found under {lsp.get_cwd()}")

    return filename
