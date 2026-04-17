"""BinXML encoder for Windows Event Log events.

Encodes the <Event> XML structure as a BinXML binary token stream.
Uses inline elements (no templates) for simplicity.
"""

from __future__ import annotations

import struct
from datetime import datetime, timezone
from io import BytesIO

from evtxforge.constants import (
    EVENT_NS,
    FRAGMENT_HEADER,
    TOKEN_ATTRIBUTE,
    TOKEN_ATTRIBUTE_MORE,
    TOKEN_CLOSE_EMPTY_ELEMENT,
    TOKEN_CLOSE_START_ELEMENT,
    TOKEN_END_ELEMENT,
    TOKEN_EOF,
    TOKEN_OPEN_START_ELEMENT,
    TOKEN_OPEN_START_ELEMENT_ATTR,
    TOKEN_VALUE,
    VALUE_TYPE_STRING,
)
from evtxforge.crc32 import datetime_to_filetime


def encode_name(name: str) -> bytes:
    """Encode a BinXmlName structure.

    Layout: 4-byte next_offset (0) + 2-byte hash (0) + 2-byte char_count
            + UTF-16LE string + 2-byte NUL terminator.
    """
    encoded = name.encode("utf-16-le")
    char_count = len(name)
    buf = struct.pack("<IHH", 0, 0, char_count)
    buf += encoded + b"\x00\x00"
    return buf


def encode_string_value(text: str) -> bytes:
    """Encode a BinXML string value (token + type + char_count + UTF-16LE)."""
    encoded = text.encode("utf-16-le")
    char_count = len(text)
    return struct.pack("<BBH", TOKEN_VALUE, VALUE_TYPE_STRING, char_count) + encoded


def _open_element(buf: BytesIO, name: str, has_attributes: bool = False) -> None:
    """Write an open-start-element token with inline name."""
    token = TOKEN_OPEN_START_ELEMENT_ATTR if has_attributes else TOKEN_OPEN_START_ELEMENT
    name_bytes = encode_name(name)
    buf.write(struct.pack("<B", token))
    buf.write(struct.pack("<H", 0xFFFF))  # dependency id (not set)
    buf.write(struct.pack("<I", 0))       # data size placeholder
    buf.write(name_bytes)


def _close_start_element(buf: BytesIO) -> None:
    buf.write(struct.pack("<B", TOKEN_CLOSE_START_ELEMENT))


def _close_empty_element(buf: BytesIO) -> None:
    buf.write(struct.pack("<B", TOKEN_CLOSE_EMPTY_ELEMENT))


def _end_element(buf: BytesIO) -> None:
    buf.write(struct.pack("<B", TOKEN_END_ELEMENT))


def _write_attribute(buf: BytesIO, name: str, value: str,
                     more: bool = False) -> None:
    """Write an attribute (name + string value)."""
    token = TOKEN_ATTRIBUTE_MORE if more else TOKEN_ATTRIBUTE
    name_bytes = encode_name(name)
    value_bytes = encode_string_value(value)
    buf.write(struct.pack("<B", token))
    buf.write(name_bytes)
    buf.write(value_bytes)


def _write_attributes(buf: BytesIO, attrs: dict[str, str]) -> None:
    """Write an attribute list with data-size prefix."""
    attr_buf = BytesIO()
    items = list(attrs.items())
    for i, (name, value) in enumerate(items):
        more = i < len(items) - 1
        _write_attribute(attr_buf, name, value, more=more)
    attr_content = attr_buf.getvalue()
    buf.write(struct.pack("<I", len(attr_content)))
    buf.write(attr_content)


def _write_text_element(buf: BytesIO, name: str, text: str) -> None:
    """Write <Name>text</Name>."""
    _open_element(buf, name)
    _close_start_element(buf)
    buf.write(encode_string_value(text))
    _end_element(buf)


def _write_empty_element_with_attrs(buf: BytesIO, name: str,
                                     attrs: dict[str, str]) -> None:
    """Write <Name attr1="val1" attr2="val2"/>."""
    _open_element(buf, name, has_attributes=True)
    _write_attributes(buf, attrs)
    _close_empty_element(buf)


def encode_event(
    channel: str,
    event_id: int,
    provider_name: str,
    provider_guid: str,
    computer: str,
    timestamp: datetime,
    event_data: dict[str, str],
    record_id: int,
    level: int = 0,
    task: int = 0,
    keywords: int = 0x8020000000000000,
) -> bytes:
    """Encode a Windows event as a BinXML fragment."""
    buf = BytesIO()

    # Fragment header
    buf.write(FRAGMENT_HEADER)

    # <Event xmlns="...">
    _open_element(buf, "Event", has_attributes=True)
    _write_attributes(buf, {"xmlns": EVENT_NS})
    _close_start_element(buf)

    # <System>
    _open_element(buf, "System")
    _close_start_element(buf)

    # <Provider Name="..." Guid="..."/>
    _write_empty_element_with_attrs(buf, "Provider", {
        "Name": provider_name,
        "Guid": provider_guid,
    })

    _write_text_element(buf, "EventID", str(event_id))
    _write_text_element(buf, "Version", "0")
    _write_text_element(buf, "Level", str(level))
    _write_text_element(buf, "Task", str(task))
    _write_text_element(buf, "Keywords", f"0x{keywords:016x}")

    time_str = timestamp.strftime("%Y-%m-%dT%H:%M:%S.") + f"{timestamp.microsecond:06d}0Z"
    _write_empty_element_with_attrs(buf, "TimeCreated", {
        "SystemTime": time_str,
    })

    _write_text_element(buf, "EventRecordID", str(record_id))
    _write_text_element(buf, "Channel", channel)
    _write_text_element(buf, "Computer", computer)

    # </System>
    _end_element(buf)

    # <EventData>
    _open_element(buf, "EventData")
    _close_start_element(buf)

    for key, value in event_data.items():
        _open_element(buf, "Data", has_attributes=True)
        _write_attributes(buf, {"Name": key})
        _close_start_element(buf)
        buf.write(encode_string_value(str(value) if value is not None else ""))
        _end_element(buf)

    # </EventData>
    _end_element(buf)

    # </Event>
    _end_element(buf)

    # EOF
    buf.write(struct.pack("<B", TOKEN_EOF))

    return buf.getvalue()
