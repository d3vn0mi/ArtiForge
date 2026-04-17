"""EvtxWriter — context manager for writing EVTX binary files."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Union

from evtxforge.binxml import encode_event
from evtxforge.constants import CHUNK_DATA_OFFSET, CHUNK_SIZE
from evtxforge.crc32 import datetime_to_filetime
from evtxforge.structures import pack_chunk, pack_event_record, pack_file_header


class EvtxWriter:
    """Write Windows EVTX binary event log files.

    Usage:
        with EvtxWriter("output.evtx") as writer:
            writer.write_event(channel=..., event_id=..., ...)
    """

    def __init__(self, path: Union[str, Path]) -> None:
        self._path = Path(path)
        self._next_record_id = 1
        self._chunks: list[bytes] = []
        self._current_chunk_events: bytearray = bytearray()
        self._current_chunk_first_id: int | None = None
        self._current_chunk_last_id: int = 0
        self._current_chunk_record_count: int = 0

    def __enter__(self) -> EvtxWriter:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self._finalize()
        return False

    def write_event(
        self,
        channel: str,
        event_id: int,
        provider_name: str,
        provider_guid: str,
        computer: str,
        timestamp: datetime,
        event_data: dict[str, str],
        record_id: int | None = None,
        level: int = 0,
        task: int = 0,
        keywords: int = 0x8020000000000000,
    ) -> None:
        if record_id is None:
            record_id = self._next_record_id
        self._next_record_id = record_id + 1

        binxml = encode_event(
            channel=channel, event_id=event_id,
            provider_name=provider_name, provider_guid=provider_guid,
            computer=computer, timestamp=timestamp,
            event_data=event_data, record_id=record_id,
            level=level, task=task, keywords=keywords,
        )

        filetime = datetime_to_filetime(timestamp)
        record = pack_event_record(record_id, filetime, binxml)

        max_data = CHUNK_SIZE - CHUNK_DATA_OFFSET
        if len(self._current_chunk_events) + len(record) > max_data:
            self._flush_chunk()

        if self._current_chunk_first_id is None:
            self._current_chunk_first_id = record_id
        self._current_chunk_last_id = record_id
        self._current_chunk_record_count += 1

        self._current_chunk_events.extend(record)

    def _flush_chunk(self) -> None:
        if not self._current_chunk_events:
            return
        chunk = pack_chunk(
            event_records_data=bytes(self._current_chunk_events),
            first_record_num=0,
            last_record_num=self._current_chunk_record_count - 1,
            first_record_id=self._current_chunk_first_id or 1,
            last_record_id=self._current_chunk_last_id,
        )
        self._chunks.append(chunk)
        self._current_chunk_events = bytearray()
        self._current_chunk_first_id = None
        self._current_chunk_last_id = 0
        self._current_chunk_record_count = 0

    def _finalize(self) -> None:
        self._flush_chunk()
        if not self._chunks:
            empty_chunk = pack_chunk(
                event_records_data=b"",
                first_record_num=0, last_record_num=0,
                first_record_id=0, last_record_id=0,
            )
            self._chunks.append(empty_chunk)

        num_chunks = len(self._chunks)
        file_header = pack_file_header(
            num_chunks=num_chunks,
            next_record_id=self._next_record_id,
            last_chunk_number=num_chunks - 1,
        )

        self._path.parent.mkdir(parents=True, exist_ok=True)
        with open(self._path, "wb") as f:
            f.write(file_header)
            for chunk in self._chunks:
                f.write(chunk)
