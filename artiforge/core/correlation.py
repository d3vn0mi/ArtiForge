"""Event correlation context — shared identifiers across related events."""

from __future__ import annotations

from dataclasses import dataclass

from artiforge.core.models import Host


@dataclass
class SessionState:
    """Tracks a single logon session."""
    logon_id: str
    logon_guid: str
    user: str


@dataclass
class ProcessState:
    """Tracks a single process lifecycle."""
    process_guid: str
    process_id: str
    image: str
    parent_guid: str | None = None
    parent_id: str | None = None
    parent_image: str | None = None


class CorrelationContext:
    """Per-(phase, host) state shared across event generators."""

    def __init__(self, host: Host) -> None:
        self.host = host
        self._sessions: dict[str, SessionState] = {}
        self._processes: dict[str, ProcessState] = {}
        self._current_session_label: str | None = None
        self._current_process_label: str | None = None

    def register_session(self, logon_id: str, logon_guid: str,
                         user: str, label: str = "default") -> SessionState:
        state = SessionState(logon_id=logon_id, logon_guid=logon_guid, user=user)
        self._sessions[label] = state
        self._current_session_label = label
        return state

    def get_session(self, label: str = "default") -> SessionState | None:
        return self._sessions.get(label)

    @property
    def current_session(self) -> SessionState | None:
        if self._current_session_label is None:
            return None
        return self._sessions.get(self._current_session_label)

    def register_process(self, process_guid: str, process_id: str,
                         image: str, label: str = "default") -> ProcessState:
        current = self.current_process
        state = ProcessState(
            process_guid=process_guid,
            process_id=process_id,
            image=image,
            parent_guid=current.process_guid if current else None,
            parent_id=current.process_id if current else None,
            parent_image=current.image if current else None,
        )
        self._processes[label] = state
        self._current_process_label = label
        return state

    def get_process(self, label: str = "default") -> ProcessState | None:
        return self._processes.get(label)

    @property
    def current_process(self) -> ProcessState | None:
        if self._current_process_label is None:
            return None
        return self._processes.get(self._current_process_label)
