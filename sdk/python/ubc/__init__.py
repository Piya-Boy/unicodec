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

__all__ = [
    "AEAD_AES_256_GCM",
    "AEAD_NONE",
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
    "parse_header",
    "parse_metadata",
]
