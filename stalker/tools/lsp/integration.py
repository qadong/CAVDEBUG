import json
import os
import subprocess


def to_lsp_request(id, method, params):
    request = {"jsonrpc": "2.0", "id": id, "method": method}
    if params:
        request["params"] = params

    content = json.dumps(request)
    header = f"Content-Length: {len(content)}\r\n\r\n"

    return (header + content).encode("utf-8")


def to_lsp_notification(method, params):
    request = {"jsonrpc": "2.0", "method": method}
    if params:
        request["params"] = params

    content = json.dumps(request)
    header = f"Content-Length: {len(content)}\r\n\r\n"
    return (header + content).encode("utf-8")


def parse_lsp_response(id, file):
    while True:
        header = {}
        while True:
            line = file.readline().decode("utf-8").strip()
            if not line:
                break
            key, value = line.split(":", 1)
            header[key.strip()] = value.strip()

        content = file.read(int(header["Content-Length"])).decode("utf-8")
        response = json.loads(content)
        if "id" in response and response["id"] == id:
            return response


def is_lsp_available(executable="clangd"):
    try:
        lsp = subprocess.run(
            [executable, "--version"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return lsp.returncode == 0
    except FileNotFoundError:
        return False


def path_to_uri(path):
    return f"file://{path}"


def uri_to_path(uri):
    return uri[7:]
