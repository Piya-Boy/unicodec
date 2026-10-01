namespace Ubc;

/// <summary>Result of Streaming.Verify.</summary>
public sealed class VerifyReport
{
    public bool Ok { get; }
    public ErrorCode? Error { get; }

    public VerifyReport(bool ok, ErrorCode? error)
    {
        Ok = ok;
        Error = error;
    }
}
