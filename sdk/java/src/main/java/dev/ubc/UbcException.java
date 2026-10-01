package dev.ubc;

/** A UBC failure carrying a portable, stable error identifier. */
public final class UbcException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    private final ErrorCode code;

    public UbcException(ErrorCode code) {
        super(code.name());
        this.code = code;
    }

    public ErrorCode code() {
        return code;
    }
}
