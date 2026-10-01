namespace Ubc;

/// <summary>A UBC failure carrying a portable, stable error identifier.</summary>
public sealed class UbcException : Exception
{
    public ErrorCode Code { get; }

    public UbcException(ErrorCode code)
        : base(code.ToStableId())
    {
        Code = code;
    }
}

public static class ErrorCodeExtensions
{
    /// <summary>The stable, cross-SDK identifier string (e.g. "ERR_BAD_MAGIC") for this code.</summary>
    public static string ToStableId(this ErrorCode code) => code switch
    {
        ErrorCode.ErrBadMagic => "ERR_BAD_MAGIC",
        ErrorCode.ErrUnsupportedVer => "ERR_UNSUPPORTED_VER",
        ErrorCode.ErrUnsupportedAlgo => "ERR_UNSUPPORTED_ALGO",
        ErrorCode.ErrReservedBits => "ERR_RESERVED_BITS",
        ErrorCode.ErrTruncated => "ERR_TRUNCATED",
        ErrorCode.ErrRootMismatch => "ERR_ROOT_MISMATCH",
        ErrorCode.ErrChunkAuth => "ERR_CHUNK_AUTH",
        ErrorCode.ErrMissingKey => "ERR_MISSING_KEY",
        ErrorCode.ErrMetaMalformed => "ERR_META_MALFORMED",
        ErrorCode.ErrTrailingData => "ERR_TRAILING_DATA",
        _ => throw new ArgumentOutOfRangeException(nameof(code), code, "unknown error code"),
    };
}
