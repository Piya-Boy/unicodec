"""Universal Binary Container reference SDK."""

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
from .payload import (
    DEFAULT_CHUNK_SIZE,
    DEFAULT_MAX_CHUNK_COUNT,
    DEFAULT_MAX_CHUNK_LEN,
    DEFAULT_MAX_META_BYTES,
    DEFAULT_MAX_TOTAL_SIZE,
    DecodeOptions,
    decode_plain,
    encode_plain,
)

__all__ = [
    "AEAD_AES_256_GCM",
    "AEAD_NONE",
    "DEFAULT_CHUNK_SIZE",
    "DEFAULT_MAX_CHUNK_COUNT",
    "DEFAULT_MAX_CHUNK_LEN",
    "DEFAULT_MAX_META_BYTES",
    "DEFAULT_MAX_TOTAL_SIZE",
    "DecodeOptions",
    "ErrorCode",
    "FLAG_ENCRYPTED",
    "FLAG_HAS_METADATA",
    "HASH_HMAC_SHA256",
    "HASH_SHA256",
    "HEADER_SIZE",
    "Header",
    "MetadataEntry",
    "UbcError",
    "VERSION",
    "encode_metadata",
    "encode_plain",
    "decode_plain",
    "parse_header",
    "parse_metadata",
]
