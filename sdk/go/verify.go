package ubc

import "io"

// VerifyReport is the result of Verify. It never carries plaintext.
type VerifyReport struct {
	OK    bool
	Error ErrorCode
}

// Verify runs the full decode pipeline over source without releasing plaintext,
// confirming per-chunk authentication (encrypted mode) and the container root.
// It reports success or the stable error identifier of the first failure.
//
// This is the two-pass verify-before-use path for untrusted input referenced in
// SPEC.md §5: callers verify first, then decode via NewDecoder if OK.
func Verify(source io.Reader, options DecodeOptions) VerifyReport {
	decoder, err := NewDecoder(source, options)
	if err != nil {
		return report(err)
	}
	if _, err := io.Copy(io.Discard, decoder); err != nil {
		return report(err)
	}
	return VerifyReport{OK: true}
}

func report(err error) VerifyReport {
	if code := ErrorCodeOf(err); code != "" {
		return VerifyReport{Error: code}
	}
	return VerifyReport{Error: CodeTruncated}
}
