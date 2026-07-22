import os
import subprocess

from utils.logger import get_logger, logf, logm
from tools.lsp.integration import (
    is_lsp_available,
    parse_lsp_response,
    path_to_uri,
    to_lsp_notification,
    to_lsp_request,
)


class LspController:
    """
    Low-level interface to the language server.
    """

    def __init__(
        self,
        executable="clangd",
        cwd=os.getcwd(),
        stderr=subprocess.DEVNULL,
    ) -> None:
        self.id = 0
        self._cwd = cwd
        self._process = subprocess.Popen(
            [executable],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=stderr,
            cwd=cwd,
        )
        self.initialize()

    def initialize(self):
        self.id += 1
        request = to_lsp_request(
            self.id,
            "initialize",
            {
                "processId": os.getpid(),
                "rootUri": path_to_uri(self._cwd),
            },
        )
        self._process.stdin.write(request)
        self._process.stdin.flush()
        return parse_lsp_response(self.id, self._process.stdout)

    def initialized(self):
        notification = to_lsp_notification("initialized", {})
        self._process.stdin.write(notification)
        self._process.stdin.flush()

        return None

    def didOpen(self, filename):
        """
        Open a file in the language server.
        """
        _, ext = os.path.splitext(filename)
        languageId = "c" if ext == ".c" else "cpp"

        with open(filename, "r") as file:
            text = file.read()

        notification = to_lsp_notification(
            "textDocument/didOpen",
            {
                "textDocument": {
                    "uri": path_to_uri(filename),
                    "languageId": languageId,
                    "text": text,
                }
            },
        )
        self._process.stdin.write(notification)
        self._process.stdin.flush()

        # notification has no response
        return None

    def didClose(self, filename):
        """
        Close a file in the language server.
        Should use this and didOpen in pair.
        """
        notification = to_lsp_notification(
            "textDocument/didClose",
            {"textDocument": {"uri": path_to_uri(filename)}},
        )
        self._process.stdin.write(notification)
        self._process.stdin.flush()

    def definition(self, filename, line, character):
        """
        Get the definition of a symbol at a given position.
        Must call didOpen on the file before calling this method.
        """
        self.id += 1
        request = to_lsp_request(
            self.id,
            "textDocument/definition",
            {
                "textDocument": {"uri": path_to_uri(filename)},
                "position": {
                    "line": line - 1,
                    "character": character - 1,
                },
            },
        )
        self._process.stdin.write(request)
        self._process.stdin.flush()
        return parse_lsp_response(self.id, self._process.stdout)

    def hover(self, filename, line, character):
        """
        Get the hover information at a given position.
        """
        self.id += 1
        request = to_lsp_request(
            self.id,
            "textDocument/hover",
            {
                "textDocument": {"uri": path_to_uri(filename)},
                "position": {
                    "line": line - 1,
                    "character": character - 1,
                },
            },
        )
        self._process.stdin.write(request)
        self._process.stdin.flush()
        return parse_lsp_response(self.id, self._process.stdout)

    def documentSymbol(self, filename):
        """
        Get all symbols in the document. It only get top-level symbols such as
        functions and classes.
        """
        self.id += 1
        request = to_lsp_request(
            self.id,
            "textDocument/documentSymbol",
            {"textDocument": {"uri": path_to_uri(filename)}},
        )
        self._process.stdin.write(request)
        self._process.stdin.flush()
        return parse_lsp_response(self.id, self._process.stdout)

    def exit(self):
        self._process.terminate()


class LanguageServer:
    def __init__(self, logger, executable="clangd", cwd=os.getcwd()):
        self._logger = logger

        self._logger.info(f"Starting language server")
        if not is_lsp_available(executable):
            self._logger.error(f"{executable} is not available")
            raise FileNotFoundError(f"{executable} is not available")
        self._controller = LspController(executable, cwd)
        self._cwd = cwd

        # detecting compile_commands.json
        compile_commands = os.path.join(cwd, "compile_commands.json")
        if not os.path.exists(compile_commands):
            self._logger.warning(
                f"'compile_commands.json' not found in {cwd}. "
                "Some features may not work properly."
            )
        else:
            self._logger.info(f"'compile_commands.json' found in {cwd}")

        self._logger.info(f"Language server started with {executable}")

    @logm("lsp", True)
    def definition(self, filename, line, character):
        self._controller.didOpen(filename)
        response = self._controller.definition(filename, line, character)
        self._controller.didClose(filename)

        if len(response["result"]) == 0:
            return None
        return response["result"][0]

    @logm("lsp", True)
    def summary(self, filename, line, character):
        self._controller.didOpen(filename)
        response = self._controller.hover(filename, line, character)
        self._controller.didClose(filename)

        return response["result"]

    @logm("lsp", True)
    def document_symbol(self, filename):
        self._controller.didOpen(filename)
        response = self._controller.documentSymbol(filename)
        self._controller.didClose(filename)

        return response["result"]

    @logm("lsp", True)
    def exit(self):
        self._controller.exit()
        self._logger.info("Language server stopped")

    def to_abs_path(self, filename):
        if not filename.startswith(self._cwd):
            if filename.startswith("./"):
                filename = filename[2:]
            return os.path.join(self._cwd, filename)
        return filename

    def get_cwd(self):
        return self._cwd


class LanguageServerFactory:
    def __init__(self, executable="clangd", cwd=os.getcwd()) -> None:
        self._executable = executable
        self._cwd = cwd
        self._instance: LanguageServer = None
        self._logger = get_logger("lsp")

    def _create(self):
        return LanguageServer(self._logger, self._executable, self._cwd)

    def get(self):
        if self._instance is None:
            self._instance = self._create()
        return self._instance

    def respawn(self):
        if self._instance is not None:
            self._instance.exit()
        self._instance = None


######################################################################
# LSP instance management

LSP_FACTORY = None


@logf("lsp", True)
def lsp_init(executable="clangd", cwd=os.getcwd()):
    global LSP_FACTORY
    if LSP_FACTORY is not None:
        LSP_FACTORY.respawn()
    LSP_FACTORY = LanguageServerFactory(executable, cwd)
    return LSP_FACTORY


def lsp_instance():
    if LSP_FACTORY is not None:
        return LSP_FACTORY.get()
    raise Exception("LSP not initialized")


def lsp_respawn():
    if LSP_FACTORY is None:
        raise Exception("LSP not initialized")
    LSP_FACTORY.respawn()


def lsp_exit():
    lsp_respawn()
