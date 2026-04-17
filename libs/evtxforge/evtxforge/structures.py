"""EVTX binary structure packing — file header, chunk, event record."""

from __future__ import annotations

import struct

from evtxforge.constants import (
    CHUNK_HEADER_SIZE,
    CHUNK_MAGIC,
    CHUNK_SIZE,
    FILE_HEADER_SIZE,
    FILE_MAGIC,
    MAJOR_VERSION,
    MINOR_VERSION,
    RECORD_MAGIC,
)
from evtxforge.crc32 import compute_crc32


def pack_file_header(
    num_chunks: int,
    next_record_id: int,
    last_chunk_number: int,
    flags: int = 0,
) -> bytes:
    """Pack a 4096-byte EVTX file header."""
    buf = bytearray(FILE_HEADER_SIZE)
    buf[0:8] = FILE_MAGIC
    struct.pack_into("<Q", buf, 8, 0)
    struct.pack_into("<Q", buf, 16, last_chunk_number)
    struct.pack_into("<Q", buf, 24, next_record_id)
    struct.pack_into("<I", buf, 32, 128)
    struct.pack_into("<H", buf, 36, MINOR_VERSION)
    struct.pack_into("<H", buf, 38, MAJOR_VERSION)
    struct.pack_into("<H", buf, 40, FILE_HEADER_SIZE)
    struct.pack_into("<H", buf, 42, num_chunks)
    struct.pack_into("<I", buf, 120, flags)
    crc = compute_crc32(bytes(buf[:120]))
    struct.pack_into("<I", buf, 124, crc)
    return bytes(buf)


def pack_event_record(record_id: int, filetime: int, binxml: bytes) -> bytes:
    """Pack a single EVTX event record."""
    total_size = 4 + 4 + 8 + 8 + len(binxml) + 4
    buf = bytearray(total_size)
    buf[0:4] = RECORD_MAGIC
    struct.pack_into("<I", buf, 4, total_size)
    struct.pack_into("<Q", buf, 8, record_id)
    struct.pack_into("<Q", buf, 16, filetime)
    buf[24:24 + len(binxml)] = binxml
    struct.pack_into("<I", buf, total_size - 4, total_size)
    return bytes(buf)


def pack_chunk(
    event_records_data: bytes,
    first_record_num: int,
    last_record_num: int,
    first_record_id: int,
    last_record_id: int,
) -> bytes:
    """Pack a 65536-byte EVTX chunk with header and event data."""
    buf = bytearray(CHUNK_SIZE)
    data_len = len(event_records_data)
    free_space_offset = CHUNK_HEADER_SIZE + data_len

    buf[CHUNK_HEADER_SIZE:CHUNK_HEADER_SIZE + data_len] = event_records_data

    buf[0:8] = CHUNK_MAGIC
    struct.pack_into("<Q", buf, 8, first_record_num)
    struct.pack_into("<Q", buf, 16, last_record_num)
    struct.pack_into("<Q", buf, 24, first_record_id)
    struct.pack_into("<Q", buf, 32, last_record_id)
    struct.pack_into("<I", buf, 40, 128)

    last_record_offset = _find_last_record_offset(event_records_data)
    struct.pack_into("<I", buf, 44, CHUNK_HEADER_SIZE + last_record_offset)
    struct.pack_into("<I", buf, 48, free_space_offset)

    event_crc = compute_crc32(event_records_data)
    struct.pack_into("<I", buf, 52, event_crc)

    header_crc = compute_crc32(bytes(buf[:120]) + bytes(buf[128:512]))
    struct.pack_into("<I", buf, 124, header_crc)

    return bytes(buf)


def _find_last_record_offset(event_records_data: bytes) -> int:
    """Walk event records to find the byte offset of the last one."""
    offset = 0
    last_offset = 0
    while offset < len(event_records_data):
        if offset + 8 > len(event_records_data):
            break
        size = struct.unpack_from("<I", event_records_data, offset + 4)[0]
        if size == 0:
            break
        last_offset = offset
        offset += size
    return last_offset
