"""Timestamp arithmetic for ArtiForge phases and events."""

from datetime import datetime, timedelta, timezone


def resolve(base: datetime, offset_minutes: int, offset_seconds: int = 0) -> datetime:
    """Return base + phase offset + event offset, UTC-aware."""
    if base.tzinfo is None:
        base = base.replace(tzinfo=timezone.utc)
    return base + timedelta(minutes=offset_minutes, seconds=offset_seconds)


def format_system_time(dt: datetime) -> str:
    """Format for Windows Event XML SystemTime attribute."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f") + "0Z"


def parse_base_time(raw: str | datetime) -> datetime:
    """Accept ISO string or datetime; always return UTC-aware datetime."""
    if isinstance(raw, datetime):
        return raw.replace(tzinfo=timezone.utc) if raw.tzinfo is None else raw
    # pydantic already parsed the datetime from YAML — this covers plain strings
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    raise ValueError(f"Cannot parse base_time: {raw!r}")
