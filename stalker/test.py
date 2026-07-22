from agent import reproduce_agent
from tools.debugger.functions import (
    debugger_backtrace,
    debugger_frame,
    debugger_print,
    debugger_run_to_line,
)
from tools.debugger.driver import debugger_init
from tools.lsp.driver import lsp_init
from tools.lsp.functions import (
    lsp_get_function,
    lsp_get_symbol_definition,
    lsp_get_symbol_summary,
)
from utils.command import run_cmd
from utils.logger import logf

#!/bin/bash


@logf(__name__, True)
def command_test(logger=None):
    logger.warning("[TEST] Reproduce the issue")
    return_code, stdout, stderr = run_cmd(["arvo"])
    logger.debug("Return code: %s", return_code)
    logger.debug("STDOUT:\n%s", stdout)
    logger.debug("STDERR:\n%s", stderr)

    logger.warning("[TEST] Compile the project")
    return_code, stdout, stderr = run_cmd(
        ["bash", "-c", "CFLAGS='-g' CXXFLAGS='-g' bear arvo compile"]
    )
    logger.debug("Return code: %s", return_code)
    logger.debug("STDOUT:\n%s", stdout)


@logf(__name__, True)
def lsp_test(logger=None):
    filename = "/src/mupdf/source/fitz/colorspace.c"
    lineno = 406
    symbol = "profile"
    function = "fz_new_icc_colorspace"

    logger.warning("[TEST] Start LSP server")
    lsp_init(cwd="/src/mupdf")

    logger.warning("[TEST] Fetching definition")
    response = lsp_get_symbol_definition(filename, lineno, symbol)
    logger.debug(response)

    logger.warning("[TEST] Fetching summary")
    response = lsp_get_symbol_summary(filename, lineno, symbol)
    logger.debug(response)

    logger.warning("[TEST] Fetching function")
    response = lsp_get_function(filename, function)
    logger.debug(response)


@logf(__name__, True)
def debugger_test(logger=None):
    logger.warning("[TEST] Start debugger server")
    debugger_init(executable="/out/pdf_fuzzer", args=["/tmp/poc"])

    logger.warning("[TEST] Debug to line")
    dbg_output, target_output = debugger_run_to_line("cmsio0.c", 839)
    logger.debug("Debugger output:\n%s", dbg_output)
    logger.debug("Target output:\n%s", target_output)

    logger.warning("[TEST] Fetch backtrace")
    response = debugger_backtrace()
    logger.debug(response)

    logger.warning("[TEST] Switch frame")
    response = debugger_frame(2)
    logger.debug(response)

    logger.warning("[TEST] Print variable")
    response = debugger_print("size")
    logger.debug(response)
    response = debugger_print("ctx")
    logger.debug(response)


@logf(__name__, True)
def agent_test(logger=None):
    logger.warning("[TEST] Reproduce Agent")
    response = reproduce_agent.reproduce()
    logger.debug(response)


@logf(__name__, True)
def run_tests():
    command_test()
    lsp_test()
    debugger_test()
    agent_test()
