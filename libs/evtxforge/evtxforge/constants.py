"""Magic bytes, BinXML tokens, and version constants for the EVTX format."""

# ── File / Chunk magic ────────────────────────────────────────────────────
FILE_MAGIC = b"ElfFile\x00"
CHUNK_MAGIC = b"ElfChnk\x00"
RECORD_MAGIC = b"\x2a\x2a\x00\x00"

# ── Sizes ─────────────────────────────────────────────────────────────────
FILE_HEADER_SIZE = 4096
FILE_HEADER_DATA_SIZE = 128
CHUNK_SIZE = 65536
CHUNK_HEADER_SIZE = 512
CHUNK_DATA_OFFSET = 512

# ── Version ───────────────────────────────────────────────────────────────
MAJOR_VERSION = 3
MINOR_VERSION = 1

# ── FILETIME epoch ────────────────────────────────────────────────────────
FILETIME_EPOCH_DIFF = 116444736000000000

# ── BinXML tokens ─────────────────────────────────────────────────────────
TOKEN_EOF = 0x00
TOKEN_OPEN_START_ELEMENT = 0x01
TOKEN_OPEN_START_ELEMENT_ATTR = 0x41
TOKEN_CLOSE_START_ELEMENT = 0x02
TOKEN_CLOSE_EMPTY_ELEMENT = 0x03
TOKEN_END_ELEMENT = 0x04
TOKEN_VALUE = 0x05
TOKEN_ATTRIBUTE = 0x06
TOKEN_ATTRIBUTE_MORE = 0x46
TOKEN_FRAGMENT_HEADER = 0x0F

# ── BinXML value types ────────────────────────────────────────────────────
VALUE_TYPE_NULL = 0x00
VALUE_TYPE_STRING = 0x01
VALUE_TYPE_UINT8 = 0x04
VALUE_TYPE_UINT16 = 0x06
VALUE_TYPE_UINT32 = 0x08
VALUE_TYPE_UINT64 = 0x0A
VALUE_TYPE_FILETIME = 0x11
VALUE_TYPE_HEX32 = 0x14
VALUE_TYPE_HEX64 = 0x15

# ── BinXML fragment header ────────────────────────────────────────────────
FRAGMENT_HEADER = bytes([TOKEN_FRAGMENT_HEADER, 0x01, 0x01, 0x00])

# ── Event XML namespace ───────────────────────────────────────────────────
EVENT_NS = "http://schemas.microsoft.com/win/2004/08/events/event"
