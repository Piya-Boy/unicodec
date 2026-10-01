package dev.ubc;

/** Stable UBC error identifiers (SPEC.md section 5). Identical across every SDK. */
public enum ErrorCode {
    ERR_BAD_MAGIC,
    ERR_UNSUPPORTED_VER,
    ERR_UNSUPPORTED_ALGO,
    ERR_RESERVED_BITS,
    ERR_TRUNCATED,
    ERR_ROOT_MISMATCH,
    ERR_CHUNK_AUTH,
    ERR_MISSING_KEY,
    ERR_META_MALFORMED,
    ERR_TRAILING_DATA
}
