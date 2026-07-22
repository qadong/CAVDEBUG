import os
import builtins
from contextlib import contextmanager
import contextlib
import io
import re
import traceback
import time
from autogen import ConversableAgent, register_function
import yaml
from utils.logger import logf, logm

try:
    from autogen.oai.client import OpenAIWrapper
except Exception:
    OpenAIWrapper = None


NAME = "agent-generic"
LLM_CONFIG = None
_CACHE_AWARE_PRICE_PATCHED = False
_ENV_VALUE_PATTERN = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$")


def _clean_llm_config(config):
    clean_entries = ["model", "temperature", "reasoning_effort"]
    clean_config = {}
    for entry in clean_entries:
        if entry in config:
            clean_config[entry] = config[entry]
    return clean_config


def _llm_config_log_summary(config):
    summary = _clean_llm_config(config)
    base_url = config.get("base_url")
    if base_url:
        summary["base_url"] = base_url
    if config.get("api_key"):
        summary["api_key"] = "***"
    if config.get("price"):
        summary["price"] = config.get("price")
    return summary


def _cached_prompt_tokens(response) -> int:
    usage = getattr(response, "usage", None)
    details = getattr(usage, "prompt_tokens_details", None)
    if details is None and isinstance(usage, dict):
        details = usage.get("prompt_tokens_details")
    if details is None:
        return 0
    if isinstance(details, dict):
        cached = details.get("cached_tokens", 0)
    else:
        cached = getattr(details, "cached_tokens", 0)
    try:
        return max(0, int(cached or 0))
    except (TypeError, ValueError):
        return 0


def _usage_token_count(response, field: str) -> int:
    usage = getattr(response, "usage", None)
    if usage is None:
        return 0
    value = usage.get(field, 0) if isinstance(usage, dict) else getattr(usage, field, 0)
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _install_cache_read_price_support():
    global _CACHE_AWARE_PRICE_PATCHED
    if _CACHE_AWARE_PRICE_PATCHED or OpenAIWrapper is None:
        return

    original = OpenAIWrapper._cost_with_customized_price

    def _cost_with_cache_read_price(response, price_1k):
        if isinstance(price_1k, list):
            price_1k = tuple(price_1k)
        if not isinstance(price_1k, tuple) or len(price_1k) < 3:
            return original(response, price_1k)

        prompt_tokens = _usage_token_count(response, "prompt_tokens")
        completion_tokens = _usage_token_count(response, "completion_tokens")
        cached_tokens = min(_cached_prompt_tokens(response), prompt_tokens)
        uncached_tokens = prompt_tokens - cached_tokens
        return (
            uncached_tokens * float(price_1k[0])
            + completion_tokens * float(price_1k[1])
            + cached_tokens * float(price_1k[2])
        ) / 1000

    OpenAIWrapper._cost_with_customized_price = staticmethod(_cost_with_cache_read_price)
    _CACHE_AWARE_PRICE_PATCHED = True


def _normalize_llm_price_config(config: dict) -> dict:
    normalized = dict(config)
    price = normalized.get("price")
    cache_read_price = normalized.pop("cache_read_price", None)
    if cache_read_price is None:
        cache_read_price = normalized.pop("cache_read_input_price", None)
    if cache_read_price is not None and isinstance(price, list) and len(price) == 2:
        normalized["price"] = [price[0], price[1], cache_read_price]
    return normalized


def _resolve_env_value(value, field: str):
    if not isinstance(value, str):
        return value
    match = _ENV_VALUE_PATTERN.fullmatch(value.strip())
    if match is None:
        return value
    variable = match.group(1)
    resolved = os.environ.get(variable)
    if not resolved:
        raise ValueError(f"Environment variable {variable} required by LLM config field {field} is not set")
    return resolved


def _log_exception(logger, message: str, exc: BaseException):
    logger.error("%s: %s: %s", message, exc.__class__.__name__, exc)
    if exc.__cause__ is not None:
        logger.error("Exception cause: %s: %s", exc.__cause__.__class__.__name__, exc.__cause__)
    if exc.__context__ is not None and exc.__context__ is not exc.__cause__:
        logger.error("Exception context: %s: %s", exc.__context__.__class__.__name__, exc.__context__)
    logger.error("Full traceback:\n%s", "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)))


def _is_transient_llm_connection_error(exc: BaseException) -> bool:
    chain = []
    cur = exc
    seen = set()
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        chain.append(cur)
        cur = cur.__cause__ or cur.__context__
    text = " ".join(f"{item.__class__.__name__} {item}" for item in chain).lower()
    return any(
        marker in text
        for marker in (
            "apiconnectionerror",
            "connecterror",
            "connection error",
            "unexpected_eof_while_reading",
            "eof occurred in violation of protocol",
            "tls",
            "ssl",
        )
    )


def _llm_chat_retry_config() -> tuple[int, float]:
    attempts = int(os.environ.get("LLM_CHAT_CONNECTION_RETRIES", "3") or "3")
    delay = float(os.environ.get("LLM_CHAT_RETRY_DELAY_SECONDS", "1.0") or "1.0")
    return max(1, attempts), max(0.0, delay)


def _resolve_llm_config_path(filename: str) -> str | None:
    candidates = [filename, os.path.join("workspace", filename)]

    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    candidates.extend(
        [
            os.path.join(repo_root, filename),
            os.path.join(repo_root, "workspace", filename),
        ]
    )

    seen = set()
    for candidate in candidates:
        normalized = os.path.abspath(candidate)
        if normalized in seen:
            continue
        seen.add(normalized)
        if os.path.exists(normalized):
            return normalized
    return None


@contextmanager
def _auto_reply_stdin():
    """
    Batch runs do not have interactive stdin, but some autogen paths still call input().
    Return an empty reply instead of raising EOF so the chat can keep auto-driving.
    """
    original_input = builtins.input

    def _safe_input(prompt=""):
        if prompt:
            print(prompt, end="")
        return ""

    builtins.input = _safe_input
    try:
        yield
    finally:
        builtins.input = original_input


@logf(NAME)
def load_llm_config(filename=None, logger=None):
    global LLM_CONFIG
    if LLM_CONFIG is not None:
        _install_cache_read_price_support()
        return LLM_CONFIG, _clean_llm_config(LLM_CONFIG)

    filename = filename or os.environ.get("LLM_CONFIG_FILE", "llm.yml")
    resolved = _resolve_llm_config_path(filename)
    if resolved is None:
        logger.error(f'LLM file "{filename}" does not exists')
        exit(1)

    config = None
    entries = ["base_url", "api_key", "model", "price", "temperature", "reasoning_effort"]
    with open(resolved, "r") as f:
        CONFIG = yaml.load(f, Loader=yaml.FullLoader)
    try:
        select = os.environ.get("LLM_PROFILE") or CONFIG["llm"]["select"]
        for profile in CONFIG["llm"]["profiles"]:
            if profile["name"] == select:
                config = {}
                for entry in entries:
                    if entry in profile:
                        config[entry] = _resolve_env_value(profile[entry], entry)
                for entry in ("cache_read_price", "cache_read_input_price"):
                    if entry in profile:
                        config[entry] = profile[entry]
    except KeyError:
        raise KeyError("Config file is not valid")

    if config is None:
        logger.error(f"No selected profile found in {filename}")
        exit(1)

    config = _normalize_llm_price_config(config)
    _install_cache_read_price_support()
    LLM_CONFIG = config
    logger.info("Loaded LLM config profile %r: %s", select, _llm_config_log_summary(config))
    return config, _clean_llm_config(config)


class GenericAgent:
    def __init__(
        self,
        name="GenericLLMClient",
        system_prompt="You are a helpful AI assistant.",
        is_termination_msg=None,
        default_auto_reply="",
    ):
        assert LLM_CONFIG, "LLM config is not loaded"
        self.llm_config = LLM_CONFIG
        self._system_prompt = system_prompt
        # Use a different name for the assistant to avoid conflicts
        assistant_name = name if name != "GenericLLMClient" else "Assistant"
        self._assistant = ConversableAgent(
            name=assistant_name, system_message=system_prompt, llm_config=self.llm_config
        )
        self._user_proxy = ConversableAgent(
            name=f"{name}-tools",
            llm_config=False,
            is_termination_msg=is_termination_msg or (
                lambda msg: msg.get("content") is not None and "TERMINATE" in msg["content"]
            ),
            human_input_mode="NEVER",
            max_consecutive_auto_reply=1024,
            default_auto_reply=default_auto_reply,
        )

    def register_hook(self, func, description, **kwargs):
        register_function(
            func,
            caller=self._assistant,
            executor=self._user_proxy,
            description=description,
            **kwargs
        )

    @logm(NAME, True)
    def initiate(self, prompt, logger=None, max_turns=None):
        chat_log = {}

        chat_result = None
        error = None
        try:
            with _auto_reply_stdin():
                chat_result = self._user_proxy.initiate_chat(
                    self._assistant,
                    message=prompt,
                    max_turns=max_turns
                )
            print("")
        except Exception as e:
            _log_exception(logger, "Chat terminated with exception", e)
            error = str(e)
        finally:
            logger.info("Chat terminated")

            chat_log = {"system": self._system_prompt}
            if chat_result is not None:
                chat_log["history"] = chat_result.chat_history
                chat_log["cost"] = chat_result.cost
            else:
                chat_log["history"] = []
                chat_log["cost"] = "N/A"
            if error is not None:
                chat_log["error"] = error

        return chat_log

    @logm(NAME, True)
    def step(self, previous_chat_log, new_message=None, logger=None, max_turns=None):
        """
        Continues the chat. If new_message is provided, it's sent to the assistant.
        Otherwise, it just continues (useful if the chat was stopped for some reason).
        """
        chat_result = None
        error = None
        try:
            # We use the existing assistant and user_proxy which have the history
            with _auto_reply_stdin():
                chat_result = self._user_proxy.initiate_chat(
                    self._assistant,
                    message=new_message,
                    clear_history=False,
                    max_turns=max_turns
                )
        except Exception as e:
            _log_exception(logger, "Step chat terminated with exception", e)
            error = str(e)
        finally:
            previous_chat_log.pop("error", None)
            if chat_result is not None:
                previous_chat_log["history"] = chat_result.chat_history
                # Optionally accumulate cost
                if "cost" in previous_chat_log and isinstance(previous_chat_log["cost"], (int, float)):
                    previous_chat_log["cost"] += chat_result.cost
                else:
                    previous_chat_log["cost"] = chat_result.cost
            if error is not None:
                previous_chat_log["error"] = error
        
        return previous_chat_log

    @logm(NAME, False)
    def query(self, prompt, logger=None) -> str:
        """
        Sends a direct query to the LLM and returns its response.
        This does not initiate a full chat session and DOES NOT include conversation history.
        """
        prompt_text = str(prompt or "")
        head = prompt_text.splitlines()[0][:120] if prompt_text else ""
        logger.info("Invoking query(prompt_head=%r, chars=%d)", head, len(prompt_text))
        # Create a temporary assistant to ensure NO history is leaked
        temp_assistant = ConversableAgent(
            "query_assistant",
            system_message=self._system_prompt,
            llm_config=self.llm_config
        )
        
        silent_proxy = ConversableAgent(
            "silent_proxy",
            llm_config=False,
            human_input_mode="NEVER",
            max_consecutive_auto_reply=1,
        )

        with _auto_reply_stdin(), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            chat_result = silent_proxy.initiate_chat(
                temp_assistant,
                message=prompt,
                max_turns=1
            )

        if chat_result and chat_result.chat_history:
            last_message = chat_result.chat_history[-1]
            return last_message.get("content", "").strip()
        
        return ""

    @logm(NAME, False)
    def continue_conversation(self, previous_chat_log, new_message, logger=None) -> str:
        """
        Continue a conversation from a previous chat history by including it in the prompt.
        
        Args:
            previous_chat_log: A dict with keys "system" (system prompt) and "history" (list of messages)
            new_message: The new message to add to the conversation
        
        Returns:
            The assistant's response as a string
        """
        previous_history = previous_chat_log.get("history", [])
        logger.info(
            "Invoking continue_conversation(history_len=%d, new_message_chars=%d)",
            len(previous_history) if isinstance(previous_history, list) else 0,
            len(str(new_message or "")),
        )
        
        # Create a constraint-specific system prompt instead of reusing the debugger's system prompt
        # The new message already contains the task description, so we use a minimal system prompt
        # that focuses on the constraint generation task
        constraint_system_prompt = (
            "You are a C/C++ expert specializing in program analysis and constraint generation. "
            "Your task is to analyze debugging conversations and fuzzing results to generate accurate safety constraints."
        )
        
        if not isinstance(previous_history, list) or len(previous_history) == 0:
            # If no history, just do a simple query with the constraint system prompt
            assistant = ConversableAgent(
                name="constraint_assistant",
                system_message=constraint_system_prompt,
                llm_config=self.llm_config
            )
            user_proxy = ConversableAgent(
                name="constraint_user",
                llm_config=False,
                human_input_mode="NEVER",
                max_consecutive_auto_reply=1,
            )
            with _auto_reply_stdin(), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                chat_result = user_proxy.initiate_chat(
                    assistant,
                    message=new_message,
                    max_turns=1
                )
            if chat_result and chat_result.chat_history:
                last_message = chat_result.chat_history[-1]
                return last_message.get("content", "").strip()
            return ""
        
        # Build a prompt that includes the full conversation history as context
        history_text = "**Previous Debugging Conversation History (for context):**\n\n"
        for msg in previous_history:
            role = msg.get("role", "")
            content = msg.get("content", "")
            
            if role == "user":
                history_text += f"User: {content}\n\n"
            elif role == "assistant":
                # Include assistant's text content
                assistant_text = content if content else ""
                history_text += f"Assistant: {assistant_text}\n"
                
                # Include tool calls if present
                tool_calls = msg.get("tool_calls", [])
                if tool_calls:
                    history_text += "\n[Tool Calls]:\n"
                    for tool_call in tool_calls:
                        func_info = tool_call.get("function", {})
                        func_name = func_info.get("name", "unknown")
                        func_args = func_info.get("arguments", "{}")
                        history_text += f"- {func_name}({func_args})\n"
                    history_text += "\n"
                
            elif role == "tool":
                # Show the actual tool feedback content
                tool_name = msg.get("name", "tool")
                tool_content = content if content else ""
                
                # Also check tool_responses for additional feedback (usually same as content, but more structured)
                tool_responses = msg.get("tool_responses", [])
                if tool_responses and not tool_content:
                    # If no direct content but has tool_responses, extract from responses
                    for resp in tool_responses:
                        resp_content = resp.get("content", "")
                        if resp_content:
                            tool_content = resp_content
                            break
                
                if tool_content:
                    # Display tool feedback clearly
                    history_text += f"Tool Feedback ({tool_name}):\n{tool_content}\n\n"
                else:
                    history_text += f"[Tool {tool_name} was used - no feedback available]\n\n"
        
        # Combine history + new message
        # The new_message already contains the task description and requirements
        full_message = f"{history_text}\n{new_message}"
        
        # Create assistant with constraint-specific system prompt
        assistant = ConversableAgent(
            name="constraint_assistant",
            system_message=constraint_system_prompt,
            llm_config=self.llm_config
        )
        user_proxy = ConversableAgent(
            name="constraint_user",
            llm_config=False,
            human_input_mode="NEVER",
            max_consecutive_auto_reply=1,
        )
        
        with _auto_reply_stdin(), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            chat_result = user_proxy.initiate_chat(
                assistant,
                message=full_message,
                max_turns=1
            )
        
        if chat_result and chat_result.chat_history:
            last_message = chat_result.chat_history[-1]
            return last_message.get("content", "").strip()
        
        return ""
