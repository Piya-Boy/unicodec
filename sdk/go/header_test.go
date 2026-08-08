package ubc

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestHeaderRoundTripsVectorHeaders(t *testing.T) {
	paths, err := filepath.Glob("../../spec/vectors/expected/*.ubc")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		name := filepath.Base(path)
		if len(name) < 6 || name[:6] == "negati" {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		header, err := ParseHeader(data)
		if err != nil {
			t.Fatalf("ParseHeader(%s): %v", name, err)
		}
		encoded, err := header.MarshalBinary()
		if err != nil {
			t.Fatalf("MarshalBinary(%s): %v", name, err)
		}
		if string(encoded) != string(data[:HeaderSize]) {
			t.Fatalf("header mismatch for %s", name)
		}
	}
}

func TestParseHeaderRejectsNegativeHeaderVectors(t *testing.T) {
	tests := []struct {
		name string
		want error
	}{
		{"negative-bad-magic.ubc", ErrBadMagic},
		{"negative-version-two.ubc", ErrUnsupportedVer},
		{"negative-hash-algo.ubc", ErrUnsupportedAlgo},
		{"negative-aead-algo.ubc", ErrUnsupportedAlgo},
		{"negative-reserved-flag.ubc", ErrReservedBits},
		{"negative-inconsistent-encryption.ubc", ErrReservedBits},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("../../spec/vectors/expected", test.name))
			if err != nil {
				t.Fatal(err)
			}
			_, err = ParseHeader(data)
			if !errors.Is(err, test.want) {
				t.Fatalf("ParseHeader() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestParseHeaderRejectsTruncatedData(t *testing.T) {
	_, err := ParseHeader(make([]byte, HeaderSize-1))
	if !errors.Is(err, ErrTruncated) {
		t.Fatalf("ParseHeader() error = %v, want %v", err, ErrTruncated)
	}
}
