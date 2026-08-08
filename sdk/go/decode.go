package ubc

import (
	"bytes"
	"io"
)

// DecodeBytes fully verifies and decodes a UBC container held in memory.
// Metadata is returned only after the complete container has been verified.
func DecodeBytes(container []byte, options DecodeOptions) ([]byte, []MetadataEntry, error) {
	decoder, err := NewDecoder(bytes.NewReader(container), options)
	if err != nil {
		return nil, nil, err
	}
	plaintext, err := io.ReadAll(decoder)
	if err != nil {
		return nil, nil, err
	}
	return plaintext, decoder.Metadata(), nil
}
