"""One-shot encrypted UBC v1 encoding and decoding."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import struct
from collections.abc import Iterable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import ErrorCode, UbcError
from .header import (
    AEAD_AES_256_GCM,
    FLAG_ENCRYPTED,
    FLAG_HAS_METADATA,
    HASH_HMAC_SHA256,
    HEADER_SIZE,
    VERSION,
    Header,
    parse_header,
)
from .metadata import MetadataEntry, encode_metadata, parse_metadata
from .payload import DEFAULT_CHUNK_SIZE, DecodeOptions, _FOOTER_MAGIC, _FOOTER_SIZE

_GCM_TAG_SIZE = 16
_ROOT_INFO = b"UBC1 root authentication"


def encode_encrypted(
    data: bytes | bytearray | memoryview,
    key: bytes,
    entries: Iterable[MetadataEntry] = (),
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    *,
    base_nonce: bytes | None = None,
) -> bytes:
    """Encode an AES-256-GCM UBC container with a keyed root authentication tag.

    ``base_nonce`` is only for deterministic conformance testing. Production callers
    must leave it unset so a CSPRNG nonce is generated for each container.
    """
    _validate_encode_key(key)
    if base_nonce is None:
        base_nonce = secrets.token_bytes(12)
    elif not isinstance(base_nonce, bytes) or len(base_nonce) != 12:
        raise UbcError(ErrorCode.RESERVED_BITS)

    plaintext = bytes(data)
    metadata = encode_metadata(entries)
    chunk_count = (len(plaintext) + chunk_size - 1) // chunk_size if chunk_size > 0 else 0
    header = Header(
        version=VERSION,
        flags=FLAG_ENCRYPTED | (FLAG_HAS_METADATA if metadata else 0),
        hash_algo=HASH_HMAC_SHA256,
        aead_algo=AEAD_AES_256_GCM,
        chunk_size=chunk_size,
        chunk_count=chunk_count,
        total_size=len(plaintext),
        base_nonce=base_nonce,
    ).to_bytes()

    metadata_digest = hashlib.sha256(metadata).digest()
    cipher = AESGCM(key)
    root = hmac.new(_root_key(key, base_nonce), digestmod=hashlib.sha256)
    root.update(header)
    root.update(metadata)
    output = bytearray(header)
    output.extend(metadata)
    for index, offset in enumerate(range(0, len(plaintext), chunk_size)):
        chunk = plaintext[offset : offset + chunk_size]
        ciphertext = cipher.encrypt(
            _chunk_nonce(base_nonce, index), chunk, _chunk_aad(header, metadata_digest, index)
        )
        output.extend(struct.pack("<I", len(ciphertext)))
        output.extend(ciphertext)
        root.update(hashlib.sha256(ciphertext).digest())
    output.extend(root.digest())
    output.extend(_FOOTER_MAGIC)
    return bytes(output)


def decode_encrypted(
    container: bytes | bytearray | memoryview,
    options: DecodeOptions | None = None,
) -> tuple[bytes, list[MetadataEntry]]:
    """Fully verify and decode an encrypted UBC container held in memory."""
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

    if not header.encrypted or options.key is None or len(options.key) != 32:
        raise UbcError(ErrorCode.MISSING_KEY)
    if header.chunk_count > options.max_chunk_count or header.total_size > options.max_total_size:
        raise UbcError(ErrorCode.TRUNCATED)

    metadata_digest = hashlib.sha256(metadata_region).digest()
    cipher = AESGCM(options.key)
    root = hmac.new(_root_key(options.key, header.base_nonce), digestmod=hashlib.sha256)
    root.update(header_bytes)
    root.update(metadata_region)
    plaintext = bytearray()
    for index in range(header.chunk_count):
        if len(view) - offset < 4:
            raise UbcError(ErrorCode.TRUNCATED)
        (chunk_length,) = struct.unpack("<I", view[offset : offset + 4])
        offset += 4
        if chunk_length > options.max_chunk_len or chunk_length > len(view) - offset:
            raise UbcError(ErrorCode.TRUNCATED)
        body = bytes(view[offset : offset + chunk_length])
        offset += chunk_length
        root.update(hashlib.sha256(body).digest())
        if len(body) < _GCM_TAG_SIZE:
            raise UbcError(ErrorCode.CHUNK_AUTH)
        try:
            chunk = cipher.decrypt(
                _chunk_nonce(header.base_nonce, index),
                body,
                _chunk_aad(header_bytes, metadata_digest, index),
            )
        except InvalidTag as error:
            raise UbcError(ErrorCode.CHUNK_AUTH) from error
        if len(chunk) > header.total_size - len(plaintext):
            raise UbcError(ErrorCode.ROOT_MISMATCH)
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


def _root_key(key: bytes, base_nonce: bytes) -> bytes:
    prk = hmac.new(base_nonce, key, hashlib.sha256).digest()
    return hmac.new(prk, _ROOT_INFO + b"\x01", hashlib.sha256).digest()


def _chunk_nonce(base_nonce: bytes, index: int) -> bytes:
    index_bytes = index.to_bytes(12, "little")
    return bytes(left ^ right for left, right in zip(base_nonce, index_bytes, strict=True))


def _chunk_aad(header: bytes, metadata_digest: bytes, index: int) -> bytes:
    return header + metadata_digest + struct.pack("<Q", index)


def _validate_encode_key(key: bytes) -> None:
    if not isinstance(key, bytes) or len(key) != 32:
        raise UbcError(ErrorCode.RESERVED_BITS)
