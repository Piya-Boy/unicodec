package ubc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

type bodyGuardReader struct {
	data              []byte
	position          int
	maxOffset         int
	readPastMaxOffset bool
}

func (r *bodyGuardReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.position >= r.maxOffset {
		r.readPastMaxOffset = true
		return 0, errors.New("body read attempted")
	}
	available := r.maxOffset - r.position
	if len(p) > available {
		r.readPastMaxOffset = true
	}
	if available > len(r.data)-r.position {
		available = len(r.data) - r.position
	}
	if available == 0 {
		return 0, io.EOF
	}
	if len(p) > available {
		p = p[:available]
	}
	n := copy(p, r.data[r.position:r.position+available])
	r.position += n
	return n, nil
}

var vectorKey = []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}
var vectorNonce = [12]byte{0xf0, 0xe0, 0xd0, 0xc0, 0xb0, 0xa0, 0x90, 0x80, 0x70, 0x60, 0x50, 0x40}
var vectorMetadata = []MetadataEntry{
	{Tag: 1, Value: []byte("รายงาน-2026.txt")},
	{Tag: 2, Value: []byte("text/plain")},
	{Tag: 3, Value: []byte{0, 0xa8, 0xda, 0x76, 0x9b, 1, 0, 0}},
	{Tag: 0x1000, Value: []byte{0, 0xff, 0x7f}},
}

func TestStreamingEncoderMatchesVectors(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
		entries  []MetadataEntry
		options  EncodeOptions
	}{
		{"plain-empty", "empty", "plain-empty", nil, EncodeOptions{ChunkSize: 1 << 20}},
		{"plain-one-byte", "one-byte", "plain-one-byte", nil, EncodeOptions{ChunkSize: 1 << 20}},
		{"plain-chunk", "chunk-1m", "plain-chunk-1m", nil, EncodeOptions{ChunkSize: 1 << 20}},
		{"plain-boundary", "chunk-1m-plus-one", "plain-chunk-1m-plus-one", nil, EncodeOptions{ChunkSize: 1 << 20}},
		{"plain-multi", "multi-3m", "plain-multi-3m", nil, EncodeOptions{ChunkSize: 1 << 20}},
		{"plain-metadata", "one-byte", "plain-metadata", vectorMetadata, EncodeOptions{ChunkSize: 1 << 20}},
		{"encrypted-empty", "empty", "encrypted-empty", nil, EncodeOptions{Key: vectorKey, ChunkSize: 1 << 20, BaseNonce: &vectorNonce}},
		{"encrypted-one-byte", "one-byte", "encrypted-one-byte", nil, EncodeOptions{Key: vectorKey, ChunkSize: 1 << 20, BaseNonce: &vectorNonce}},
		{"encrypted-chunk", "chunk-1m", "encrypted-chunk-1m", nil, EncodeOptions{Key: vectorKey, ChunkSize: 1 << 20, BaseNonce: &vectorNonce}},
		{"encrypted-boundary", "chunk-1m-plus-one", "encrypted-chunk-1m-plus-one", nil, EncodeOptions{Key: vectorKey, ChunkSize: 1 << 20, BaseNonce: &vectorNonce}},
		{"encrypted-multi", "multi-3m", "encrypted-multi-3m", nil, EncodeOptions{Key: vectorKey, ChunkSize: 1 << 20, BaseNonce: &vectorNonce}},
		{"encrypted-metadata", "one-byte", "encrypted-metadata", vectorMetadata, EncodeOptions{Key: vectorKey, ChunkSize: 1 << 20, BaseNonce: &vectorNonce}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input, err := os.ReadFile("../../spec/vectors/inputs/" + test.input + ".bin")
			if err != nil {
				t.Fatal(err)
			}
			var got bytes.Buffer
			encoder, err := NewEncoder(&got, test.entries, test.options)
			if err != nil {
				t.Fatal(err)
			}
			for len(input) != 0 {
				n := 17
				if n > len(input) {
					n = len(input)
				}
				if written, err := encoder.Write(input[:n]); err != nil || written != n {
					t.Fatalf("Write() = %d, %v", written, err)
				}
				input = input[n:]
			}
			if err := encoder.Close(); err != nil {
				t.Fatal(err)
			}
			want, err := os.ReadFile("../../spec/vectors/expected/" + test.expected + ".ubc")
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got.Bytes(), want) {
				t.Fatal("streaming output differs from vector")
			}
		})
	}
}

func TestStreamingDecoderVectors(t *testing.T) {
	positive := []struct {
		name string
		key  []byte
	}{
		{"plain-empty", nil}, {"plain-one-byte", nil}, {"plain-chunk-1m", nil},
		{"plain-chunk-1m-plus-one", nil}, {"plain-multi-3m", nil}, {"plain-metadata", nil},
		{"encrypted-empty", vectorKey}, {"encrypted-one-byte", vectorKey},
		{"encrypted-chunk-1m", vectorKey}, {"encrypted-chunk-1m-plus-one", vectorKey}, {"encrypted-multi-3m", vectorKey}, {"encrypted-metadata", vectorKey},
	}
	for _, test := range positive {
		t.Run(test.name, func(t *testing.T) {
			container, err := os.ReadFile("../../spec/vectors/expected/" + test.name + ".ubc")
			if err != nil {
				t.Fatal(err)
			}
			decoder, err := NewDecoder(bytes.NewReader(container), DecodeOptions{Key: test.key})
			if err != nil {
				t.Fatal(err)
			}
			got, err := io.ReadAll(decoder)
			if err != nil {
				t.Fatal(err)
			}
			inputName := test.name
			for _, prefix := range []string{"plain-", "encrypted-"} {
				inputName = strings.TrimPrefix(inputName, prefix)
			}
			if inputName == "metadata" {
				inputName = "one-byte"
			}
			want, err := os.ReadFile("../../spec/vectors/inputs/" + inputName + ".bin")
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatal("decoded plaintext differs from vector input")
			}
			if strings.HasSuffix(test.name, "metadata") && !metadataEqual(decoder.Metadata(), vectorMetadata) {
				t.Fatal("decoded metadata differs from vector")
			}
		})
	}
}

func metadataEqual(got, want []MetadataEntry) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i].Tag != want[i].Tag || !bytes.Equal(got[i].Value, want[i].Value) {
			return false
		}
	}
	return true
}

func TestStreamingDecoderRejectsNegativeVectors(t *testing.T) {
	tests := []struct {
		name string
		want error
		key  []byte
	}{
		{"bad-magic", ErrBadMagic, nil}, {"version-two", ErrUnsupportedVer, nil},
		{"hash-algo", ErrUnsupportedAlgo, nil}, {"aead-algo", ErrUnsupportedAlgo, nil},
		{"reserved-flag", ErrReservedBits, nil}, {"inconsistent-encryption", ErrReservedBits, nil},
		{"truncated", ErrTruncated, nil}, {"root-mismatch", ErrRootMismatch, nil},
		{"chunk-auth", ErrChunkAuth, vectorKey}, {"missing-key", ErrMissingKey, nil},
		{"meta-out-of-order", ErrMetaMalformed, nil}, {"meta-duplicate", ErrMetaMalformed, nil},
		{"meta-overrun", ErrMetaMalformed, nil}, {"oversized-clen", ErrTruncated, nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			container, err := os.ReadFile("../../spec/vectors/expected/negative-" + test.name + ".ubc")
			if err != nil {
				t.Fatal(err)
			}
			decoder, err := NewDecoder(bytes.NewReader(container), DecodeOptions{Key: test.key})
			if err == nil {
				_, err = io.ReadAll(decoder)
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestDecoderRejectsDoSCapsBeforeReadingBody(t *testing.T) {
	tests := []struct {
		name      string
		header    Header
		afterHead []byte
		options   DecodeOptions
		read      bool
		want      error
		maxOffset int
	}{
		{
			name:      "meta_len",
			header:    Header{Version: Version, Flags: FlagHasMetadata, HashAlgo: HashSHA256},
			afterHead: appendUint32(nil, uint32(DefaultMaxMetaBytes+1)),
			want:      ErrMetaMalformed,
			maxOffset: HeaderSize + 4,
		},
		{
			name:      "clen",
			header:    Header{Version: Version, HashAlgo: HashSHA256, ChunkCount: 1, TotalSize: 1},
			afterHead: appendUint32(nil, uint32(DefaultMaxChunkLen+1)),
			read:      true,
			want:      ErrTruncated,
			maxOffset: HeaderSize + 4,
		},
		{
			name:      "chunk_count",
			header:    Header{Version: Version, HashAlgo: HashSHA256, ChunkCount: DefaultMaxChunkCount + 1},
			want:      ErrTruncated,
			maxOffset: HeaderSize,
		},
		{
			name:      "total_size",
			header:    Header{Version: Version, HashAlgo: HashSHA256, TotalSize: DefaultMaxTotalSize + 1},
			want:      ErrTruncated,
			maxOffset: HeaderSize,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			headerBytes, err := test.header.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			reader := &bodyGuardReader{
				data:      append(headerBytes, test.afterHead...),
				maxOffset: test.maxOffset,
			}
			decoder, err := NewDecoder(reader, test.options)
			if err == nil && test.read {
				_, err = decoder.Read(make([]byte, 1))
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if reader.position != test.maxOffset {
				t.Fatalf("read through offset %d, want %d", reader.position, test.maxOffset)
			}
			if reader.readPastMaxOffset {
				t.Fatal("attempted to read container body after rejecting cap")
			}
		})
	}
}

func TestDecoderRejectsExplicitDoSCapsBeforeReadingBody(t *testing.T) {
	tests := []struct {
		name      string
		header    Header
		afterHead []byte
		options   DecodeOptions
		read      bool
		want      error
		maxOffset int
	}{
		{
			name:      "meta_len",
			header:    Header{Version: Version, Flags: FlagHasMetadata, HashAlgo: HashSHA256},
			afterHead: appendUint32(nil, 2),
			options:   DecodeOptions{MaxMetaBytes: 1},
			want:      ErrMetaMalformed,
			maxOffset: HeaderSize + 4,
		},
		{
			name:      "clen",
			header:    Header{Version: Version, HashAlgo: HashSHA256, ChunkCount: 1, TotalSize: 1},
			afterHead: appendUint32(nil, 2),
			options:   DecodeOptions{MaxChunkLen: 1},
			read:      true,
			want:      ErrTruncated,
			maxOffset: HeaderSize + 4,
		},
		{
			name:      "chunk_count",
			header:    Header{Version: Version, HashAlgo: HashSHA256, ChunkCount: 2},
			options:   DecodeOptions{MaxChunkCount: 1},
			want:      ErrTruncated,
			maxOffset: HeaderSize,
		},
		{
			name:      "total_size",
			header:    Header{Version: Version, HashAlgo: HashSHA256, TotalSize: 2},
			options:   DecodeOptions{MaxTotalSize: 1},
			want:      ErrTruncated,
			maxOffset: HeaderSize,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			headerBytes, err := test.header.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			reader := &bodyGuardReader{
				data:      append(headerBytes, test.afterHead...),
				maxOffset: test.maxOffset,
			}
			decoder, err := NewDecoder(reader, test.options)
			if err == nil && test.read {
				_, err = decoder.Read(make([]byte, 1))
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if reader.position != test.maxOffset {
				t.Fatalf("read through offset %d, want %d", reader.position, test.maxOffset)
			}
			if reader.readPastMaxOffset {
				t.Fatal("attempted to read container body after rejecting cap")
			}
		})
	}
}

func TestDecoderHonorsExplicitDoSCaps(t *testing.T) {
	container, err := os.ReadFile("../../spec/vectors/expected/plain-metadata.ubc")
	if err != nil {
		t.Fatal(err)
	}
	metaLength := binary.LittleEndian.Uint32(container[HeaderSize : HeaderSize+4])
	decoder, err := NewDecoder(bytes.NewReader(container), DecodeOptions{
		MaxMetaBytes:  uint64(metaLength),
		MaxChunkLen:   1,
		MaxChunkCount: 1,
		MaxTotalSize:  1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(decoder); err != nil {
		t.Fatal(err)
	}
}

func appendUint32(data []byte, value uint32) []byte {
	var encoded [4]byte
	binary.LittleEndian.PutUint32(encoded[:], value)
	return append(data, encoded[:]...)
}
