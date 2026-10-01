<?php

declare(strict_types=1);

namespace Ubc;

/** Stable UBC error identifiers (SPEC.md section 5). Identical across every SDK. */
enum ErrorCode: string
{
    case BadMagic = 'ERR_BAD_MAGIC';
    case UnsupportedVersion = 'ERR_UNSUPPORTED_VER';
    case UnsupportedAlgorithm = 'ERR_UNSUPPORTED_ALGO';
    case ReservedBits = 'ERR_RESERVED_BITS';
    case Truncated = 'ERR_TRUNCATED';
    case RootMismatch = 'ERR_ROOT_MISMATCH';
    case ChunkAuth = 'ERR_CHUNK_AUTH';
    case MissingKey = 'ERR_MISSING_KEY';
    case MetaMalformed = 'ERR_META_MALFORMED';
    case TrailingData = 'ERR_TRAILING_DATA';
}
