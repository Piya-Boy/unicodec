namespace Ubc;

/// <summary>Stable UBC error identifiers (SPEC.md section 5). Identical across every SDK.</summary>
public enum ErrorCode
{
    ErrBadMagic,
    ErrUnsupportedVer,
    ErrUnsupportedAlgo,
    ErrReservedBits,
    ErrTruncated,
    ErrRootMismatch,
    ErrChunkAuth,
    ErrMissingKey,
    ErrMetaMalformed,
    ErrTrailingData,
}
