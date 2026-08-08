"""Stable UBC error identifiers."""

from enum import StrEnum


class ErrorCode(StrEnum):
    BAD_MAGIC = "ERR_BAD_MAGIC"
    UNSUPPORTED_VERSION = "ERR_UNSUPPORTED_VER"
    UNSUPPORTED_ALGORITHM = "ERR_UNSUPPORTED_ALGO"
    RESERVED_BITS = "ERR_RESERVED_BITS"
    TRUNCATED = "ERR_TRUNCATED"
    ROOT_MISMATCH = "ERR_ROOT_MISMATCH"
    CHUNK_AUTH = "ERR_CHUNK_AUTH"
    MISSING_KEY = "ERR_MISSING_KEY"
    META_MALFORMED = "ERR_META_MALFORMED"
    TRAILING_DATA = "ERR_TRAILING_DATA"


class UbcError(Exception):
    """A UBC failure with a portable error identifier."""

    def __init__(self, code: ErrorCode) -> None:
        self.code = code
        super().__init__(code)
