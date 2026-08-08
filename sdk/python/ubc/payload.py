"""One-shot plain UBC v1 encoding and decoding."""

from __future__ import annotations

import hashlib
import hmac
import struct
from collections.abc import Iterable
from dataclasses import dataclass

from .errors import ErrorCode, UbcError
from .header import AEAD_NONE, FLAG_HAS_METADATA, HASH_SHA256, HEADER_SIZE, VERSION, Header, parse_header
from .metadata import MetadataEntry, encode_metadata, parse_metadata

DEFAULT_CHUNK_SIZE = 1 << 20
DEFAULT_MAX_META_BYTES = 16 << 20
DEFAULT_MAX_CHUNK_LEN = 64 << 20
DEFAULT_MAX_CHUNK_COUNT = 1 << 20
DEFAULT_MAX_TOTAL_SIZE = 1 << 30
_FOOTER_SIZE = 36
_FOOTER_MAGIC = b"UBCE"


@dataclass(frozen=True, slots=True)
class DecodeOptions:
    """Resource limits applied while decoding untrusted containers."""

    max_meta_bytes: int = DEFAULT_MAX_META_BYTES
    max_chunk_len: int = DEFAULT_MAX_CHUNK_LEN
    max_chunk_count: int = DEFAULT_MAX_CHUNK_COUNT
    max_total_size: int = DEFAULT_MAX_TOTAL_SIZE
    key: bytes | None = None

    def __post_init__(self) -> None:
        if self.key is not None and not isinstance(self.key, bytes):
            raise ValueError("key must be bytes when provided")
        for value in (
            self.max_meta_bytes,
            self.max_chunk_len,
            self.max_chunk_count,
            self.max_total_size,
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError("decode limits must be non-negative integers")


def encode_plain(
    data: bytes | bytearray | memoryview,
    entries: Iterable[MetadataEntry] = (),
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> bytes:
    """Encode plaintext bytes as a complete, SHA-256-rooted UBC container."""
    plaintext = bytes(data)
    metadata = encode_metadata(entries)
    chunk_count = (len(plaintext) + chunk_size - 1) // chunk_size if chunk_size > 0 else 0
    header = Header(
        version=VERSION,
        flags=FLAG_HAS_METADATA if metadata else 0,
        hash_algo=HASH_SHA256,
        aead_algo=AEAD_NONE,
        chunk_size=chunk_size,
        chunk_count=chunk_count,
        total_size=len(plaintext),
        base_nonce=b"\x00" * 12,
    ).to_bytes()

    output = bytearray(header)
    output.extend(metadata)
    root = hashlib.sha256()
    root.update(header)
    root.update(metadata)
    for offset in range(0, len(plaintext), chunk_size):
        chunk = plaintext[offset : offset + chunk_size]
        output.extend(struct.pack("<I", len(chunk)))
        output.extend(chunk)
        root.update(hashlib.sha256(chunk).digest())
    output.extend(root.digest())
    output.extend(_FOOTER_MAGIC)
    return bytes(output)


def decode_plain(
    container: bytes | bytearray | memoryview,
    options: DecodeOptions | None = None,
) -> tuple[bytes, list[MetadataEntry]]:
    """Fully verify and decode a non-encrypted UBC container held in memory."""
    if options is None:
        options = DecodeOptions()
    if not isinstance(options, DecodeOptions):
        raise TypeError("options must be a DecodeOptions instance")

    view = memoryview(container)
    header = parse_header(view)
    header_bytes = bytes(view[:HEADER_SIZE])
    offset = HEADER_SIZE
    metadata: list[MetadataEntry] = []
    metadata_region = b""
    if header.has_metadata:
        metadata, consumed = parse_metadata(view[offset:], max_bytes=options.max_meta_bytes)
        metadata_region = bytes(view[offset : offset + consumed])
        offset += consumed

    if header.encrypted:
        raise UbcError(ErrorCode.MISSING_KEY)
    if header.chunk_count > options.max_chunk_count or header.total_size > options.max_total_size:
        raise UbcError(ErrorCode.TRUNCATED)

    root = hashlib.sha256()
    root.update(header_bytes)
    root.update(metadata_region)
    plaintext = bytearray()
    for _ in range(header.chunk_count):
        if len(view) - offset < 4:
            raise UbcError(ErrorCode.TRUNCATED)
        (chunk_length,) = struct.unpack("<I", view[offset : offset + 4])
        offset += 4
        if chunk_length > options.max_chunk_len or chunk_length > len(view) - offset:
            raise UbcError(ErrorCode.TRUNCATED)
        if chunk_length > header.total_size - len(plaintext):
            raise UbcError(ErrorCode.ROOT_MISMATCH)
        chunk = view[offset : offset + chunk_length]
        offset += chunk_length
        root.update(hashlib.sha256(chunk).digest())
        plaintext.extend(chunk)

    if len(view) - offset < _FOOTER_SIZE:
        raise UbcError(ErrorCode.TRUNCATED)
    footer = view[offset : offset + _FOOTER_SIZE]
    if bytes(footer[32:]) != _FOOTER_MAGIC:
        raise UbcError(ErrorCode.TRUNCATED)
    if len(plaintext) != header.total_size or not hmac.compare_digest(footer[:32], root.digest()):
        raise UbcError(ErrorCode.ROOT_MISMATCH)
    if len(view) != offset + _FOOTER_SIZE:
        raise UbcError(ErrorCode.TRAILING_DATA)
    return bytes(plaintext), metadata
