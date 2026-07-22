from utils.seed_records import demonic_seed_records, record_values


class MutatorBase:
    def __init__(self, logger=None):
        self.logger = logger

    def _available_seed_values(self, suspect_object: dict) -> list:
        values = record_values(demonic_seed_records(suspect_object))
        return [value for value in values if not self._is_unavailable_debugger_value(value)]

    def _is_unavailable_debugger_value(self, value) -> bool:
        text = str(value or "").lower()
        return any(marker in text for marker in ("error:", "timeout", "not available", "unavailable", "lldb_eval"))
