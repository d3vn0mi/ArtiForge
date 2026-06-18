"""Tests for BinXML encoding."""

import struct
import pytest
from datetime import datetime, timezone

from evtxforge.constants import (
    FRAGMENT_HEADER,
    TOKEN_EOF,
    TOKEN_OPEN_START_ELEMENT,
    TOKEN_OPEN_START_ELEMENT_ATTR,
    TOKEN_CLOSE_START_ELEMENT,
    TOKEN_END_ELEMENT,
    TOKEN_VALUE,
    VALUE_TYPE_STRING,
)


def test_encode_name_structure():
    """BinXmlName: 4-byte next + 2-byte hash + 2-byte len + UTF-16LE + NUL."""
    from evtxforge.binxml import encode_name
    result = encode_name("Event")
    assert len(result) == 4 + 2 + 2 + 6 * 2
    char_count = struct.unpack_from("<H", result, 6)[0]
    assert char_count == 5
    text = result[8:8 + 5 * 2].decode("utf-16-le")
    assert text == "Event"
    assert result[-2:] == b"\x00\x00"


def test_encode_string_value():
    """String value: token + type + char_count + UTF-16LE (no NUL)."""
    from evtxforge.binxml import encode_string_value
    result = encode_string_value("marcus.webb")
    assert result[0] == TOKEN_VALUE
    assert result[1] == VALUE_TYPE_STRING
    char_count = struct.unpack_from("<H", result, 2)[0]
    assert char_count == 11
    text = result[4:4 + 11 * 2].decode("utf-16-le")
    assert text == "marcus.webb"


def test_encode_event_starts_with_fragment_header():
    from evtxforge.binxml import encode_event
    result = encode_event(
        channel="Security",
        event_id=4624,
        provider_name="Microsoft-Windows-Security-Auditing",
        provider_guid="{54849625-5478-4994-A5BA-3E3B0328C30D}",
        computer="WIN-WS1.lab.local",
        timestamp=datetime(2026, 2, 19, 9, 12, 0, tzinfo=timezone.utc),
        event_data={"TargetUserName": "marcus.webb"},
        record_id=1000,
    )
    assert result[:4] == FRAGMENT_HEADER


def test_encode_event_ends_with_eof():
    from evtxforge.binxml import encode_event
    result = encode_event(
        channel="Security",
        event_id=4624,
        provider_name="Microsoft-Windows-Security-Auditing",
        provider_guid="{54849625-5478-4994-A5BA-3E3B0328C30D}",
        computer="WIN-WS1.lab.local",
        timestamp=datetime(2026, 2, 19, 9, 12, 0, tzinfo=timezone.utc),
        event_data={},
        record_id=1000,
    )
    assert result[-1] == TOKEN_EOF


def test_encode_event_produces_bytes():
    from evtxforge.binxml import encode_event
    result = encode_event(
        channel="Security",
        event_id=4624,
        provider_name="Test",
        provider_guid="{00000000-0000-0000-0000-000000000000}",
        computer="PC1",
        timestamp=datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        event_data={"Key1": "Value1", "Key2": "Value2"},
        record_id=1,
    )
    assert isinstance(result, bytes)
    assert len(result) > 50


def test_encode_event_empty_event_data():
    from evtxforge.binxml import encode_event
    result = encode_event(
        channel="System",
        event_id=7036,
        provider_name="Service Control Manager",
        provider_guid="{00000000-0000-0000-0000-000000000000}",
        computer="PC1",
        timestamp=datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        event_data={},
        record_id=1,
    )
    assert result[:4] == FRAGMENT_HEADER
    assert result[-1] == TOKEN_EOF
