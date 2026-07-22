import os
from typing import List
from tools.debugger.server import LldbServer
from utils.logger import logf, get_logger

NAME = "debugger"

class DebuggerServerFactory:
    def __init__(self, executable, args, env, cwd=os.getcwd()) -> None:
        self._executable = executable
        self._args = args
        self._env = env
        self._cwd = cwd
        self._instance = None
        self._generation = 0
        self.logger = get_logger(NAME)

    def get(self):
        # 核心自愈逻辑：如果实例不存在，或者底层进程已经挂了，则重启
        if (
            self._instance is None
            or self._instance._controller._process.poll() is not None
            or getattr(self._instance, "_stream_desynced", False)
        ):
            if self._instance is not None:
                exit_code = self._instance._controller._process.poll()
                if getattr(self._instance, "_stream_desynced", False):
                    self.logger.warning("检测到调试器 MI 输出流失步，正在自动重启...")
                else:
                    self.logger.warning(f"检测到调试器后端已退出 (Exit Code: {exit_code})，正在自动重启...")
            
            self._instance = LldbServer(self._executable, self._args, self._env, self._cwd)
            self._generation += 1
            self._instance.start()
            self.logger.info("调试器后端已成功自愈重启。")
            
        return self._instance

    def respawn(self):
        if self._instance:
            try:
                self._instance.exit()
            except Exception:
                pass
        self._instance = None


DEBUGGER_FACTORY = None

@logf(NAME, True)
def debugger_init(executable, args=[], env={}, cwd=os.getcwd()):
    global DEBUGGER_FACTORY
    if DEBUGGER_FACTORY: DEBUGGER_FACTORY.respawn()
    DEBUGGER_FACTORY = DebuggerServerFactory(executable, args, env, cwd)
    return DEBUGGER_FACTORY

def debugger_instance() -> LldbServer:
    if DEBUGGER_FACTORY: return DEBUGGER_FACTORY.get()
    raise Exception("Debugger not initialized")

def debugger_respawn():
    if not DEBUGGER_FACTORY: raise Exception("Debugger not initialized")
    DEBUGGER_FACTORY.respawn()

def debugger_exit():
    debugger_respawn()


def debugger_respawn_if_unhealthy(reason: str = "unknown"):
    """
    Respawn the debugger when it's in a bad state (e.g. backtrace failed, target dead).
    Next debugger_instance().get() will create a fresh instance.
    """
    if not DEBUGGER_FACTORY:
        return
    logger = get_logger(NAME)
    logger.warning(f"调试器状态异常 ({reason})，正在自动重置...")
    DEBUGGER_FACTORY.respawn()
    logger.info("调试器已重置。下次 run_to_line 或 run 将恢复会话。")


def debugger_backend_generation() -> int:
    if not DEBUGGER_FACTORY:
        return 0
    return DEBUGGER_FACTORY._generation
