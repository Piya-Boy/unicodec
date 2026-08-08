"""Streaming UBC v1 encoding, decoding, verification, and inspection."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import struct
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from typing import BinaryIO

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .crypto import _GCM_TAG_SIZE, _chunk_aad, _chunk_nonce, _root_key
from .errors import ErrorCode, UbcError
from .header import (
    AEAD_AES_256_GCM,
    AEAD_NONE,
    FLAG_ENCRYPTED,
    FLAG_HAS_METADATA,
    HASH_HMAC_SHA256,
    HASH_SHA256,
    HEADER_SIZE,
    VERSION,
    Header,
    parse_header,
)
from .metadata import MetadataEntry, encode_metadata, parse_metadata
from .payload import DEFAULT_CHUNK_SIZE, DecodeOptions, _FOOTER_MAGIC, _FOOTER_SIZE

_READ_BLOCK_SIZE = 32 << 10


@dataclass(frozen=True, slots=True)
class EncodeOptions:
    """Options for a streaming encoder.

    ``base_nonce`` exists only for deterministic conformance tests. Production
    callers must leave it unset so a fresh cryptographically secure nonce is used.
    """

    chunk_size: int = DEFAULT_CHUNK_SIZE
    key: bytes | None = None
    base_nonce: bytes | None = None

    def __post_init__(self) -> None:
        if isinstance(self.chunk_size, bool) or not isinstance(self.chunk_size, int) or not 0 < self.chunk_size <= 0xFFFF_FFFF:
            raise UbcError(ErrorCode.RESERVED_BITS)
        if self.key is not None and (not isinstance(self.key, bytes) or len(self.key) != 32):
            raise UbcError(ErrorCode.RESERVED_BITS)
        if self.base_nonce is not None and (not isinstance(self.base_nonce, bytes) or len(self.base_nonce) != 12):
            raise UbcError(ErrorCode.RESERVED_BITS)
        if self.key is None and self.base_nonce is not None:
            raise UbcError(ErrorCode.RESERVED_BITS)


@dataclass(frozen=True, slots=True)
class VerifyReport:
    ok: bool
    error: ErrorCode | None = None
    failed_chunk: int | None = None


@dataclass(frozen=True, slots=True)
class ContainerFlags:
    encrypted: bool
    has_metadata: bool


@dataclass(frozen=True, slots=True)
class ContainerInfo:
    version: int
    flags: ContainerFlags
    hash_algo: int
    aead_algo: int
    chunk_size: int
    chunk_count: int
    total_size: int
    metadata: tuple[MetadataEntry, ...]


class Encoder:
    """A write-then-close encoder that spools plaintext until header sizes are known."""

    def __init__(
        self,
        sink: BinaryIO,
        entries: Iterable[MetadataEntry] = (),
        options: EncodeOptions | None = None,
    ) -> None:
        if not hasattr(sink, "write"):
            raise TypeError("sink must provide write(bytes)")
        self._sink = sink
        self._options = EncodeOptions() if options is None else options
        if not isinstance(self._options, EncodeOptions):
            raise TypeError("options must be an EncodeOptions instance")
        self._metadata = encode_metadata(entries)
        self._spool = tempfile.TemporaryFile(mode="w+b")
        self._total_size = 0
        self._closed = False

    def write(self, data: bytes | bytearray | memoryview) -> int:
        if self._closed:
            raise ValueError("encoder is closed")
        written = self._spool.write(bytes(data))
        self._total_size += written
        return written

    def close(self) -> None:
        if self._closed:
            raise ValueError("encoder is closed")
        self._closed = True
        try:
            self._write_container()
        finally:
            self._spool.close()

    def _write_container(self) -> None:
        chunk_count = (self._total_size + self._options.chunk_size - 1) // self._options.chunk_size
        encrypted = self._options.key is not None
        base_nonce = (
            self._options.base_nonce or secrets.token_bytes(12)
            if encrypted
            else b"\x00" * 12
        )
        header = Header(
            version=VERSION,
            flags=(FLAG_ENCRYPTED if encrypted else 0) | (FLAG_HAS_METADATA if self._metadata else 0),
            hash_algo=HASH_HMAC_SHA256 if encrypted else HASH_SHA256,
            aead_algo=AEAD_AES_256_GCM if encrypted else AEAD_NONE,
            chunk_size=self._options.chunk_size,
            chunk_count=chunk_count,
            total_size=self._total_size,
            base_nonce=base_nonce,
        ).to_bytes()
        root = hmac.new(_root_key(self._options.key, base_nonce), digestmod=hashlib.sha256) if encrypted else hashlib.sha256()
        root.update(header)
        root.update(self._metadata)
        metadata_digest = hashlib.sha256(self._metadata).digest()
        cipher = AESGCM(self._options.key) if encrypted else None

        _write_all(self._sink, header)
        _write_all(self._sink, self._metadata)
        self._spool.seek(0)
        for index in range(chunk_count):
            remaining = self._total_size - index * self._options.chunk_size
            plain = _read_exact(self._spool, min(self._options.chunk_size, remaining))
            body = cipher.encrypt(_chunk_nonce(base_nonce, index), plain, _chunk_aad(header, metadata_digest, index)) if cipher else plain
            _write_all(self._sink, struct.pack("<I", len(body)))
            _write_all(self._sink, body)
            root.update(hashlib.sha256(body).digest())
        _write_all(self._sink, root.digest())
        _write_all(self._sink, _FOOTER_MAGIC)


class Decoder:
    """A pull-based plaintext reader that validates each encrypted chunk before release."""

    def __init__(self, source: BinaryIO, options: DecodeOptions | None = None) -> None:
        if not hasattr(source, "read"):
            raise TypeError("source must provide read(size)")
        self._source = source
        self._options = DecodeOptions() if options is None else options
        if not isinstance(self._options, DecodeOptions):
            raise TypeError("options must be a DecodeOptions instance")
        self._header_bytes = _read_exact(source, HEADER_SIZE)
        self._header = parse_header(self._header_bytes)
        self._metadata_raw = b""
        self._metadata: list[MetadataEntry] = []
        if self._header.has_metadata:
            self._metadata_raw = _read_metadata_region(source, self._options.max_meta_bytes)
            self._metadata, _ = parse_metadata(self._metadata_raw, max_bytes=self._options.max_meta_bytes)
        if self._header.encrypted and (self._options.key is None or len(self._options.key) != 32):
            raise UbcError(ErrorCode.MISSING_KEY)
        if self._header.chunk_count > self._options.max_chunk_count or self._header.total_size > self._options.max_total_size:
            raise UbcError(ErrorCode.TRUNCATED)

        self._metadata_digest = hashlib.sha256(self._metadata_raw).digest()
        self._root = hmac.new(_root_key(self._options.key, self._header.base_nonce), digestmod=hashlib.sha256) if self._header.encrypted else hashlib.sha256()
        self._root.update(self._header_bytes)
        self._root.update(self._metadata_raw)
        self._cipher = AESGCM(self._options.key) if self._header.encrypted else None
        self._chunk_index = 0
        self._plain_total = 0
        self._pending: bytes | None = None
        self._pending_offset = 0
        self._finalized = False
        self._terminal_error: UbcError | None = None

    @property
    def metadata(self) -> tuple[MetadataEntry, ...]:
        return tuple(MetadataEntry(entry.tag, bytes(entry.value)) for entry in self._metadata)

    def read(self, size: int = -1) -> bytes:
        if not isinstance(size, int):
            raise TypeError("size must be an integer")
        if self._terminal_error is not None:
            raise self._terminal_error
        if size == 0:
            return b""
        if size < 0:
            output = bytearray()
            while not self._finalized or self._pending is not None:
                output.extend(self.read(_READ_BLOCK_SIZE))
            return bytes(output)

        try:
            while self._pending is None and not self._finalized:
                self._load_next_chunk()
        except UbcError as error:
            self._terminal_error = error
            raise
        if self._pending is None:
            return b""
        end = min(self._pending_offset + size, len(self._pending))
        output = self._pending[self._pending_offset : end]
        self._pending_offset = end
        if self._pending_offset == len(self._pending):
            self._pending = None
            self._pending_offset = 0
        return output

    def _load_next_chunk(self) -> None:
        if self._chunk_index == self._header.chunk_count:
            self._finalize()
            return
        (chunk_length,) = struct.unpack("<I", _read_exact(self._source, 4))
        if chunk_length > self._options.max_chunk_len:
            raise UbcError(ErrorCode.TRUNCATED)
        body = _read_exact(self._source, chunk_length)
        self._root.update(hashlib.sha256(body).digest())
        plain = body
        if self._cipher is not None:
            if len(body) < _GCM_TAG_SIZE:
                raise UbcError(ErrorCode.CHUNK_AUTH)
            try:
                plain = self._cipher.decrypt(
                    _chunk_nonce(self._header.base_nonce, self._chunk_index),
                    body,
                    _chunk_aad(self._header_bytes, self._metadata_digest, self._chunk_index),
                )
            except InvalidTag as error:
                raise UbcError(ErrorCode.CHUNK_AUTH) from error
        if len(plain) > self._header.total_size - self._plain_total:
            raise UbcError(ErrorCode.ROOT_MISMATCH)
        self._plain_total += len(plain)
        self._chunk_index += 1
        self._pending = plain or None
        self._pending_offset = 0

    def _finalize(self) -> None:
        footer = _read_exact(self._source, _FOOTER_SIZE)
        if footer[32:] != _FOOTER_MAGIC:
            raise UbcError(ErrorCode.TRUNCATED)
        if self._plain_total != self._header.total_size or not hmac.compare_digest(footer[:32], self._root.digest()):
            raise UbcError(ErrorCode.ROOT_MISMATCH)
        if self._source.read(1):
            raise UbcError(ErrorCode.TRAILING_DATA)
        self._finalized = True


def new_encoder(sink: BinaryIO, entries: Iterable[MetadataEntry] = (), options: EncodeOptions | None = None) -> Encoder:
    return Encoder(sink, entries, options)


def new_decoder(source: BinaryIO, options: DecodeOptions | None = None) -> Decoder:
    return Decoder(source, options)


def verify(source: BinaryIO, options: DecodeOptions | None = None) -> VerifyReport:
    try:
        decoder = Decoder(source, options)
        while decoder.read(_READ_BLOCK_SIZE):
            pass
    except UbcError as error:
        failed_chunk = decoder._chunk_index if "decoder" in locals() and decoder._chunk_index < decoder._header.chunk_count else None
        return VerifyReport(ok=False, error=error.code, failed_chunk=failed_chunk)
    return VerifyReport(ok=True)


def inspect(source: BinaryIO, options: DecodeOptions | None = None) -> ContainerInfo:
    if not hasattr(source, "read"):
        raise TypeError("source must provide read(size)")
    max_meta_bytes = DecodeOptions().max_meta_bytes if options is None else options.max_meta_bytes
    header_bytes = _read_exact(source, HEADER_SIZE)
    header = parse_header(header_bytes)
    metadata: list[MetadataEntry] = []
    if header.has_metadata:
        metadata_raw = _read_metadata_region(source, max_meta_bytes)
        metadata, _ = parse_metadata(metadata_raw, max_bytes=max_meta_bytes)
    return ContainerInfo(
        version=header.version,
        flags=ContainerFlags(encrypted=header.encrypted, has_metadata=header.has_metadata),
        hash_algo=header.hash_algo,
        aead_algo=header.aead_algo,
        chunk_size=header.chunk_size,
        chunk_count=header.chunk_count,
        total_size=header.total_size,
        metadata=tuple(MetadataEntry(entry.tag, bytes(entry.value)) for entry in metadata),
    )


def _read_metadata_region(source: BinaryIO, max_meta_bytes: int) -> bytes:
    prefix = _read_exact(source, 4)
    (metadata_length,) = struct.unpack("<I", prefix)
    if metadata_length == 0 or metadata_length > max_meta_bytes:
        raise UbcError(ErrorCode.META_MALFORMED)
    try:
        return prefix + _read_exact(source, metadata_length)
    except UbcError as error:
        if error.code == ErrorCode.TRUNCATED:
            raise UbcError(ErrorCode.META_MALFORMED) from error
        raise


def _read_exact(source: BinaryIO, length: int) -> bytes:
    data = bytearray()
    while len(data) < length:
        chunk = source.read(min(_READ_BLOCK_SIZE, length - len(data)))
        if not chunk:
            raise UbcError(ErrorCode.TRUNCATED)
        data.extend(chunk)
    return bytes(data)


def _write_all(sink: BinaryIO, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = sink.write(view)
        if written is None or written <= 0:
            raise OSError("sink made no progress")
        view = view[written:]
