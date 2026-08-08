package ubc

import (
	"bytes"
	"errors"
	"io"
	"os"
	"testing"
)

func TestDecodeBytesMatchesStreamingVectors(t *testing.T) {
	tests := []struct {
		name  string
		input string
		key   []byte
	}{
		{name: "plain-metadata", input: "one-byte"},
		{name: "plain-multi-3m", input: "multi-3m"},
		{name: "encrypted-metadata", input: "one-byte", key: vectorKey},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			container, err := os.ReadFile("../../spec/vectors/expected/" + test.name + ".ubc")
			if err != nil {
				t.Fatal(err)
			}
			want, err := os.ReadFile("../../spec/vectors/inputs/" + test.input + ".bin")
			if err != nil {
				t.Fatal(err)
			}

			got, metadata, err := DecodeBytes(container, DecodeOptions{Key: test.key})
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatal("decoded plaintext differs from vector input")
			}

			decoder, err := NewDecoder(bytes.NewReader(container), DecodeOptions{Key: test.key})
			if err != nil {
				t.Fatal(err)
			}
			streamed, err := io.ReadAll(decoder)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, streamed) || !metadataEqual(metadata, decoder.Metadata()) {
				t.Fatal("DecodeBytes differs from streaming Decoder")
			}
			if test.name == "plain-metadata" || test.name == "encrypted-metadata" {
				if !metadataEqual(metadata, vectorMetadata) {
					t.Fatal("decoded metadata differs from vector")
				}
			}
		})
	}
}

func TestDecodeBytesMetadataIsDefensiveCopy(t *testing.T) {
	container, err := os.ReadFile("../../spec/vectors/expected/plain-metadata.ubc")
	if err != nil {
		t.Fatal(err)
	}
	_, metadata, err := DecodeBytes(container, DecodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	metadata[0].Value[0] ^= 0xff

	decoder, err := NewDecoder(bytes.NewReader(container), DecodeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(decoder); err != nil {
		t.Fatal(err)
	}
	if !metadataEqual(decoder.Metadata(), vectorMetadata) {
		t.Fatal("caller mutation affected decoder metadata")
	}
}

func TestDecodeBytesPropagatesNegativeVectorErrors(t *testing.T) {
	tests := []struct {
		name string
		key  []byte
		want error
	}{
		{name: "root-mismatch", want: ErrRootMismatch},
		{name: "chunk-auth", key: vectorKey, want: ErrChunkAuth},
		{name: "meta-out-of-order", want: ErrMetaMalformed},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			container, err := os.ReadFile("../../spec/vectors/expected/negative-" + test.name + ".ubc")
			if err != nil {
				t.Fatal(err)
			}
			plaintext, metadata, err := DecodeBytes(container, DecodeOptions{Key: test.key})
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if plaintext != nil || metadata != nil {
				t.Fatal("DecodeBytes returned data with a failed decode")
			}
		})
	}
}
