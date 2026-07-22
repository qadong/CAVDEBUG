import logging
import os
import functools
import coloredlogs

from utils.args import filter_kwargs

LOG_DIR = os.getcwd()
LOGGERS = {}


def configure_logger(log_dir: str):
    global LOG_DIR
    LOG_DIR = log_dir

    # disable werkzeug logs
    log = logging.getLogger("werkzeug")
    log.disabled = True

    # clear logs
    if os.path.exists(log_dir):
        for file in os.listdir(log_dir):
            os.remove(os.path.join(log_dir, file))


def get_logger(name: str, log_dir: str = None):
    FMT = "%(asctime)s %(name)s (%(filename)s:%(lineno)d) [%(levelname)s] %(message)s"
    SHORT_FMT = "%(asctime)s %(filename)s:%(lineno)d [%(levelname)s] %(message)s"
    DATE_FMT = "%m/%d/%Y %H:%M:%S"

    global LOGGERS

    if name in LOGGERS:
        return LOGGERS[name]

    if log_dir is None or log_dir == "":
        log_dir = LOG_DIR

    logger = logging.getLogger(name)
    
    # Reduce verbosity for LLDB driver to avoid spamming raw communication logs
    if name == "lldb":
        logger.setLevel(logging.INFO)
    else:
        logger.setLevel(logging.DEBUG)

    os.makedirs(log_dir, exist_ok=True)
    
    # 1. Individual Log File (existing)
    log_file = os.path.join(log_dir, f"{name.split('_')[-1]}.log")
    log_formatter = logging.Formatter(SHORT_FMT, DATE_FMT)
    file_handler = logging.FileHandler(log_file, "a")
    file_handler.setFormatter(log_formatter)
    
    if name == "lldb":
        file_handler.setLevel(logging.INFO)
    else:
        file_handler.setLevel(logging.DEBUG)
        
    logger.addHandler(file_handler)

    # 2. Aggregated Log File (new)
    # This saves ALL logs from ALL loggers to one file
    all_log_file = os.path.join(log_dir, "all.log")
    all_handler = logging.FileHandler(all_log_file, "a")
    all_handler.setFormatter(logging.Formatter(FMT, DATE_FMT)) 
    
    if name == "lldb":
        all_handler.setLevel(logging.INFO)
    else:
        all_handler.setLevel(logging.DEBUG)
        
    logger.addHandler(all_handler)

    logger.addHandler(logging.StreamHandler())

    coloredlogs.install(level=logging.INFO, logger=logger, fmt=FMT, datefmt=DATE_FMT)

    LOGGERS[name] = logger

    return logger


def logf(name: str, log_invoke=False):
    """
    Function decorator to inject a logger into the function.
    Preserves function signature and type annotations for autogen compatibility.
    """

    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            logger = get_logger(name)
            kwargs["logger"] = logger
            if log_invoke:
                logger.info(f"Invoking {func.__name__}({[*args, *kwargs]})")
            return func(*args, **filter_kwargs(kwargs, func))

        return wrapper

    return decorator


def logm(name: str, log_invoke=False):
    """
    Method decorator to inject a logger into the method.
    Preserves function signature and type annotations for autogen compatibility.
    """

    def decorator(func):
        @functools.wraps(func)
        def wrapper(self, *args, **kwargs):
            logger = get_logger(name)
            kwargs["logger"] = logger
            if log_invoke:
                logger.info(f"Invoking {func.__name__}({[*args, *kwargs]})")
            return func(self, *args, **filter_kwargs(kwargs, func))

        return wrapper

    return decorator