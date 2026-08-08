package ubc

import "errors"

type ErrorCode string

const (
	CodeBadMagic        ErrorCode = "ERR_BAD_MAGIC"
	CodeUnsupportedVer  ErrorCode = "ERR_UNSUPPORTED_VER"
	CodeUnsupportedAlgo ErrorCode = "ERR_UNSUPPORTED_ALGO"
	CodeReservedBits    ErrorCode = "ERR_RESERVED_BITS"
	CodeTruncated       ErrorCode = "ERR_TRUNCATED"
	CodeMetaMalformed   ErrorCode = "ERR_META_MALFORMED"
	CodeRootMismatch    ErrorCode = "ERR_ROOT_MISMATCH"
	CodeChunkAuth       ErrorCode = "ERR_CHUNK_AUTH"
	CodeMissingKey      ErrorCode = "ERR_MISSING_KEY"
	CodeTrailingData    ErrorCode = "ERR_TRAILING_DATA"
)

type Error struct {
	Code ErrorCode
}

func (e *Error) Error() string { return string(e.Code) }

func (e *Error) Is(target error) bool {
	other, ok := target.(*Error)
	return ok && e.Code == other.Code
}

var (
	ErrBadMagic        = &Error{Code: CodeBadMagic}
	ErrUnsupportedVer  = &Error{Code: CodeUnsupportedVer}
	ErrUnsupportedAlgo = &Error{Code: CodeUnsupportedAlgo}
	ErrReservedBits    = &Error{Code: CodeReservedBits}
	ErrTruncated       = &Error{Code: CodeTruncated}
	ErrMetaMalformed   = &Error{Code: CodeMetaMalformed}
	ErrRootMismatch    = &Error{Code: CodeRootMismatch}
	ErrChunkAuth       = &Error{Code: CodeChunkAuth}
	ErrMissingKey      = &Error{Code: CodeMissingKey}
	ErrTrailingData    = &Error{Code: CodeTrailingData}
)

func ErrorCodeOf(err error) ErrorCode {
	var ubcError *Error
	if errors.As(err, &ubcError) {
		return ubcError.Code
	}
	return ""
}
