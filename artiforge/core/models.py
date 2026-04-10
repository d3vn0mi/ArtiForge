"""Pydantic models for ArtiForge lab specifications and generated artifacts."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


# ── Infrastructure ────────────────────────────────────────────────────────────

class User(BaseModel):
    username: str
    domain: str
    rid: int = 1001

    @property
    def sid(self) -> str:
        """Placeholder SID — host provides the sid_prefix."""
        return f"S-1-5-21-PLACEHOLDER-{self.rid}"

    @property
    def full(self) -> str:
        return f"{self.domain}\\{self.username}"


class Host(BaseModel):
    name: str                       # e.g. WIN-WS1  (injected by engine)
    ip: str
    fqdn: str
    os: str = "Windows 10"
    sid_prefix: str = "S-1-5-21-1111111111-2222222222-3333333333"
    users: list[User] = Field(default_factory=list)

    def user_sid(self, rid: int) -> str:
        return f"{self.sid_prefix}-{rid}"

    def get_user(self, username: str) -> User | None:
        for u in self.users:
            if u.username == username:
                return u
        return None


class Infrastructure(BaseModel):
    domain: str
    hosts: dict[str, Host]

    @model_validator(mode="before")
    @classmethod
    def inject_host_names(cls, data: Any) -> Any:
        hosts_raw = data.get("hosts", {})
        for name, host_data in hosts_raw.items():
            if isinstance(host_data, dict):
                host_data["name"] = name
        return data


# ── Noise specification ───────────────────────────────────────────────────────

class NoiseSpec(BaseModel):
    """Configures background noise events injected into the timeline."""
    host: str
    spread_minutes: int = Field(default=60, ge=1)
    logon_pairs: int = Field(default=0, ge=0)
    process_spawns: int = Field(default=0, ge=0)
    dns_queries: int = Field(default=0, ge=0)


# ── Attack specification ───────────────────────────────────────────────────────

class EventSpec(BaseModel):
    """A single event to generate, as declared in the YAML."""
    channel: str                    # Security | System | Sysmon | Application
    eid: int
    offset_seconds: int = Field(default=0, ge=0)
    host: str | None = None         # override phase-level host
    user: str | None = None         # override phase-level user
    provider: str | None = None      # overrides channel-based provider name when set
    fields: dict[str, Any] = Field(default_factory=dict)
    repeat: int = Field(default=1, ge=1)
    repeat_gap_seconds: int = Field(default=30, ge=0)
    jitter_seconds: int = Field(default=0, ge=0)        # ±N second timestamp jitter
    repeat_jitter_seconds: int = Field(default=0, ge=0)  # ±N jitter between repeats


class FileArtifactSpec(BaseModel):
    """A file to generate on disk as part of the lab staging."""
    type: Literal["lnk", "xsl", "inf", "xml_task", "binary_placeholder", "raw"]
    dest: str                       # Windows-style path (for documentation / metadata)
    content_template: str | None = None
    lnk_target: str | None = None
    lnk_args: str | None = None


class Phase(BaseModel):
    id: int
    name: str
    mitre: list[str] = Field(default_factory=list)
    offset_minutes: int = 0
    host: str | None = None         # default host for events in this phase
    user: str | None = None         # default user for events in this phase
    events: list[EventSpec] = Field(default_factory=list)
    file_artifacts: list[FileArtifactSpec] = Field(default_factory=list)


class AttackSpec(BaseModel):
    base_time: datetime
    malicious_account: str = "svc_backup_admin"
    phases: list[Phase] = Field(default_factory=list)
    noise: list[NoiseSpec] = Field(default_factory=list)


class LabMeta(BaseModel):
    id: str
    name: str
    description: str = ""
    mitre_version: str = "v18"
    lab_schema_version: str = "1"


class LabSpec(BaseModel):
    lab: LabMeta
    infrastructure: Infrastructure
    attack: AttackSpec


# ── Generated artifacts ────────────────────────────────────────────────────────

class GeneratedEvent(BaseModel):
    """A fully rendered Windows event, ready for export."""
    record_id: int
    timestamp: datetime
    channel: str
    eid: int
    host: str
    computer: str                   # FQDN
    provider_name: str
    provider_guid: str
    task: int = 0
    keywords: str = "0x8020000000000000"
    level: int = 0
    event_data: dict[str, str] = Field(default_factory=dict)
    phase_id: int = 0
    phase_name: str = ""
    mitre_techniques: list[str] = Field(default_factory=list)  # ATT&CK technique IDs

    @property
    def event_id(self) -> int:
        return self.eid


class GeneratedFile(BaseModel):
    """A file artifact to write to the output directory."""
    phase_id: int
    filename: str                   # local output filename
    windows_dest: str               # for display / documentation
    content: str | bytes
    binary: bool = False


class ArtifactBundle(BaseModel):
    lab_id: str
    lab_name: str
    base_time: datetime
    events: list[GeneratedEvent] = Field(default_factory=list)
    files: list[GeneratedFile] = Field(default_factory=list)

    model_config = ConfigDict(arbitrary_types_allowed=True)

