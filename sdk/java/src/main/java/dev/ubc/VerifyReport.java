package dev.ubc;

/** Result of {@link Streaming#verify}. */
public final class VerifyReport {
    public final boolean ok;
    public final ErrorCode error;

    public VerifyReport(boolean ok, ErrorCode error) {
        this.ok = ok;
        this.error = error;
    }
}
