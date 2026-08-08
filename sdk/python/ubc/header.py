"""UBC v1 header encoding and validation."""

from __future__ import annotations

from dataclasses import dataclass
import struct

from .errors import ErrorCode, UbcError

HEADER_SIZE = 40
VERSION = 1
HASH_SHA256 = 0
HASH_HMAC_SHA256 = 1
AEAD_NONE = 0
AEAD_AES_256_GCM = 1
FLAG_ENCRYPTED = 1 << 0
FLAG_HAS_METADATA = 1 << 1

_MAGIC = b"UBC1"
_ALLOWED_FLAGS = FLAG_ENCRYPTED | FLAG_HAS_METADATA
_MAX_ENCRYPTED_CHUNK_SIZE = 0xFFFF_FFEF


@dataclass(frozen=True, slots=True)
class Header:
    version: int
    flags: int
    hash_algo: int
    aead_algo: int
    chunk_size: int
    chunk_count: int
    total_size: int
    base_nonce: bytes

    @property
    def encrypted(self) -> bool:
        return bool(self.flags & FLAG_ENCRYPTED)

    @property
    def has_metadata(self) -> bool:
        return bool(self.flags & FLAG_HAS_METADATA)

    def to_bytes(self) -> bytes:
        _validate_header(self)
        return _MAGIC + struct.pack(
            "<BBBBIQQ12s",
            self.version,
            self.flags,
            self.hash_algo,
            self.aead_algo,
            self.chunk_size,
            self.chunk_count,
            self.total_size,
            self.base_nonce,
        )


def parse_header(data: bytes | bytearray | memoryview) -> Header:
    view = memoryview(data)
    if len(view) < HEADER_SIZE:
        raise UbcError(ErrorCode.TRUNCATED)
    if bytes(view[:4]) != _MAGIC:
        raise UbcError(ErrorCode.BAD_MAGIC)

    version, flags, hash_algo, aead_algo, chunk_size, chunk_count, total_size, base_nonce = (
        struct.unpack("<BBBBIQQ12s", view[4:HEADER_SIZE])
    )
    header = Header(
        version=version,
        flags=flags,
        hash_algo=hash_algo,
        aead_algo=aead_algo,
        chunk_size=chunk_size,
        chunk_count=chunk_count,
        total_size=total_size,
        base_nonce=base_nonce,
    )
    _validate_header(header)
    return header


def _validate_header(header: Header) -> None:
    if header.version != VERSION:
        raise UbcError(ErrorCode.UNSUPPORTED_VERSION)
    if header.hash_algo not in (HASH_SHA256, HASH_HMAC_SHA256) or header.aead_algo not in (
        AEAD_NONE,
        AEAD_AES_256_GCM,
    ):
        raise UbcError(ErrorCode.UNSUPPORTED_ALGORITHM)
    if header.flags & ~_ALLOWED_FLAGS:
        raise UbcError(ErrorCode.RESERVED_BITS)
    if not 0 <= header.chunk_size <= 0xFFFF_FFFF:
        raise UbcError(ErrorCode.RESERVED_BITS)
    if not 0 <= header.chunk_count <= 0xFFFF_FFFF_FFFF_FFFF:
        raise UbcError(ErrorCode.RESERVED_BITS)
    if not 0 <= header.total_size <= 0xFFFF_FFFF_FFFF_FFFF:
        raise UbcError(ErrorCode.RESERVED_BITS)
    if len(header.base_nonce) != 12:
        raise UbcError(ErrorCode.RESERVED_BITS)

    if header.encrypted:
        if (
            header.aead_algo != AEAD_AES_256_GCM
            or header.hash_algo != HASH_HMAC_SHA256
            or header.chunk_size == 0
            or header.chunk_size > _MAX_ENCRYPTED_CHUNK_SIZE
        ):
            raise UbcError(ErrorCode.RESERVED_BITS)
        return
    if (
        header.aead_algo != AEAD_NONE
        or header.hash_algo != HASH_SHA256
        or header.chunk_size == 0
        or header.base_nonce != b"\x00" * 12
    ):
        raise UbcError(ErrorCode.RESERVED_BITS)
