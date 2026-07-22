import traceback
import sys
import os
from .mutators.base import MutatorBase
from .blocks import memory, integer
from typing import Optional, List, Dict, Any

class SynthesizedMutator(MutatorBase):
    """
    Base class for mutators synthesized by an Agent.
    Agent scripts will define a class 'AgentMutator' inheriting from this.
    """
    def __init__(self, suspect_object=None, debugger=None, logger=None):
        from utils.logger import get_logger
        self.logger = logger or get_logger("synthesized-mutator")
        super().__init__(self.logger)
        self._install_agent_helpers(suspect_object=suspect_object, debugger=debugger)

    def _install_agent_helpers(self, suspect_object=None, debugger=None):
        """Install debugger-backed helper methods expected by synthesized scripts."""
        self.suspect = suspect_object
        self.context = suspect_object 
        if debugger is not None:
            self.debugger = debugger
        elif not hasattr(self, "debugger"):
            self.debugger = None
        
        # Fallback debugger instance
        if self.debugger is None:
            try:
                from tools.debugger.driver import debugger_instance
                self.debugger = debugger_instance()
            except Exception:
                pass

        # Blocks accessible to Agent
        self.blocks = {
            "memory": memory,
            "integer": integer,
            "write_buf": lambda addr, data: f"LOGIC:WRITE({addr}, {data})",
            "read_buf": lambda addr, size: f"LOGIC:READ({addr}, {size})",
            "get_addr": lambda symbol: memory.get_addr(self.debugger, symbol) if self.debugger else None,
            "add_guard": lambda file, line, condition, ret_val: f"LOGIC:GUARD({file if file else self.suspect['file']}:{line if line != -1 else self.suspect['line']}) IF({condition}) THEN RETURN({ret_val})",
            "logic_return": lambda condition, ret_val: f"LOGIC:IF({condition}) THEN RETURN({ret_val})",
            "logic_assign": lambda condition, var, val: f"LOGIC:IF({condition}) THEN ASSIGN({var}={val})",
            # Move execution to another source location, then perform an action there.
            # action can be either a raw assignment expression like "pe_offset=60"
            # or another LOGIC:... directive.
            "at": lambda file, line, action: f"LOGIC:AT({file}:{line}) THEN {action}",
        }

        # Bind methods to self for convenience (e.g. self.add_guard)
        for name, func in self.blocks.items():
            if name not in ["memory", "integer"]:
                setattr(self, name, func)

    def compose(self) -> list[str]:
        """
        To be implemented by the Agent.
        Returns a list of debugger assignment expressions or values.
        """
        raise NotImplementedError("Agent must implement compose()")

    def generate_candidates(self, suspect_object: dict) -> set:
        try:
            candidates = self.compose()
            return set(candidates)
        except Exception as e:
            self.logger.error(f"SynthesizedMutator execution error: {e}")
            self.logger.debug(traceback.format_exc())
            return set()

class MutationOrchestrator:
    """
    Handles the lifecycle of agent-synthesized mutation scripts.
    Executes Python code safely and extracts candidates.
    """
    def __init__(self, debugger, logger):
        self.debugger = debugger
        self.logger = logger

    def run_agent_script(self, suspect_object: dict, script_code: str) -> tuple[set, Optional[str]]:
        self.logger.info("Executing Agent-synthesized mutation script...")
        self.logger.debug(f"Synthesized Code:\n{script_code}")
        
        # Prepare execution environment
        exec_globals = {
            "SynthesizedMutator": SynthesizedMutator,
            "memory": memory,
            "integer": integer,
            "write_buf": lambda addr, data: f"LOGIC:WRITE({addr}, {data})",
            "read_buf": lambda addr, size: f"LOGIC:READ({addr}, {size})",
            "get_addr": lambda symbol: memory.get_addr(self.debugger, symbol),
            "add_guard": lambda file, line, condition, ret_val: f"LOGIC:GUARD({file if file else suspect_object['file']}:{line if line != -1 else suspect_object['line']}) IF({condition}) THEN RETURN({ret_val})",
            "logic_return": lambda condition, ret_val: f"LOGIC:IF({condition}) THEN RETURN({ret_val})",
            "logic_assign": lambda condition, var, val: f"LOGIC:IF({condition}) THEN ASSIGN({var}={val})",
            "at": lambda file, line, action: f"LOGIC:AT({file}:{line}) THEN {action}",
        }
        
        def _execute_script():
            exec(script_code, exec_globals)
            
            # Find the AgentMutator class
            agent_class = None
            for item in exec_globals.values():
                if isinstance(item, type) and issubclass(item, SynthesizedMutator) and item is not SynthesizedMutator:
                    agent_class = item
                    break
            
            if not agent_class:
                raise RuntimeError("No subclass of SynthesizedMutator found in script. Please define 'class AgentMutator(SynthesizedMutator):'.")

            # Instantiate and run. Agent-authored subclasses may omit __init__ or
            # define a narrow __init__; always patch in the helper API afterwards.
            try:
                mutator_instance = agent_class(suspect_object, self.debugger, self.logger)
            except TypeError as first_error:
                try:
                    mutator_instance = agent_class()
                except TypeError:
                    raise first_error
            if isinstance(mutator_instance, SynthesizedMutator):
                mutator_instance._install_agent_helpers(suspect_object=suspect_object, debugger=self.debugger)
                mutator_instance.logger = self.logger
            return mutator_instance.generate_candidates(suspect_object)

        try:
            return _execute_script(), None
        except Exception as e:
            err_msg = str(e)
            self.logger.error(f"Script execution failed: {err_msg}")
            return set(), traceback.format_exc()

# Keep FuzzingStrategies for backward compatibility if needed, 
# but for now we focus on the Script Orchestrator.
class FuzzingStrategies: 
    pass
