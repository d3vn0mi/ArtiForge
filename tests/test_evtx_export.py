"""Round-trip tests: generate EVTX → read back → verify."""

import pytest
import struct
from pathlib import Path

from artiforge.core import engine
from artiforge.exporters import evtx_exporter
from evtxforge.constants import FILE_HEADER_SIZE, CHUNK_SIZE, FILE_MAGIC, CHUNK_MAGIC


@pytest.fixture
def uc3_bundle():
    spec = engine.load_lab("uc3")
    return engine.run(spec, seed=42)


@pytest.fixture
def evtx_dir(tmp_path, uc3_bundle):
    out = tmp_path / "evtx"
    evtx_exporter.export(uc3_bundle, out)
    return out


def test_evtx_files_created(evtx_dir):
    files = list(evtx_dir.glob("*.evtx"))
    assert len(files) > 0


def test_evtx_file_per_host_channel(evtx_dir, uc3_bundle):
    expected_pairs = {(ev.host, ev.channel) for ev in uc3_bundle.events}
    files = list(evtx_dir.glob("*.evtx"))
    assert len(files) == len(expected_pairs)


def test_evtx_file_starts_with_magic(evtx_dir):
    for f in evtx_dir.glob("*.evtx"):
        data = f.read_bytes()
        assert data[:8] == FILE_MAGIC, f"{f.name} missing file magic"


def test_evtx_file_size_correct(evtx_dir):
    for f in evtx_dir.glob("*.evtx"):
        size = f.stat().st_size
        assert size >= FILE_HEADER_SIZE + CHUNK_SIZE
        assert (size - FILE_HEADER_SIZE) % CHUNK_SIZE == 0


def test_evtx_chunk_magic(evtx_dir):
    for f in evtx_dir.glob("*.evtx"):
        data = f.read_bytes()
        assert data[FILE_HEADER_SIZE:FILE_HEADER_SIZE + 8] == CHUNK_MAGIC


def test_evtx_header_crc_valid(evtx_dir):
    from evtxforge.crc32 import compute_crc32
    for f in evtx_dir.glob("*.evtx"):
        data = f.read_bytes()
        stored = struct.unpack_from("<I", data, 124)[0]
        computed = compute_crc32(data[:120])
        assert stored == computed, f"{f.name} file header CRC mismatch"


def test_evtx_event_count_matches(evtx_dir, uc3_bundle):
    total_records = 0
    for f in evtx_dir.glob("*.evtx"):
        data = f.read_bytes()
        chunk_offset = FILE_HEADER_SIZE
        while chunk_offset < len(data):
            free_space = struct.unpack_from("<I", data, chunk_offset + 48)[0]
            pos = chunk_offset + 512
            while pos < chunk_offset + free_space:
                magic = data[pos:pos + 4]
                if magic != b"\x2a\x2a\x00\x00":
                    break
                rec_size = struct.unpack_from("<I", data, pos + 4)[0]
                if rec_size == 0:
                    break
                total_records += 1
                pos += rec_size
            chunk_offset += CHUNK_SIZE
    assert total_records == len(uc3_bundle.events)


@pytest.mark.xfail(reason="python-evtx may not parse inline BinXML")
def test_evtx_readback_with_python_evtx(evtx_dir):
    try:
        import Evtx.Evtx as evtx
    except ImportError:
        pytest.skip("python-evtx not installed")

    for f in evtx_dir.glob("*.evtx"):
        with evtx.Evtx(str(f)) as log:
            records = list(log.records())
            assert len(records) > 0, f"{f.name} has no parseable records"
            for record in records:
                xml = record.xml()
                assert "<Event" in xml
                assert "<EventID>" in xml
