package ubc

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

func TestMetadataMatchesVector(t *testing.T) {
	container, err := os.ReadFile("../../spec/vectors/expected/plain-metadata.ubc")
	if err != nil {
		t.Fatal(err)
	}
	entries, used, err := ParseMetadata(container[HeaderSize:])
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeMetadata(entries)
	if err != nil {
		t.Fatal(err)
	}
	if used != len(encoded) || !bytes.Equal(encoded, container[HeaderSize:HeaderSize+used]) {
		t.Fatal("metadata does not round-trip vector bytes")
	}
}

func TestMetadataSortsAndRejectsMalformed(t *testing.T) {
	encoded, err := EncodeMetadata([]MetadataEntry{{Tag: 0x1000, Value: []byte{1}}, {Tag: 1, Value: []byte{2}}})
	if err != nil {
		t.Fatal(err)
	}
	entries, _, err := ParseMetadata(encoded)
	if err != nil || entries[0].Tag != 1 || entries[1].Tag != 0x1000 {
		t.Fatalf("sorted parse = %#v, %v", entries, err)
	}
	if _, err := EncodeMetadata([]MetadataEntry{{Tag: 1}, {Tag: 1}}); !errors.Is(err, ErrMetaMalformed) {
		t.Fatal("duplicate accepted")
	}
	for _, data := range [][]byte{{0}, {1, 0, 0, 0}, {6, 0, 0, 0, 1, 0, 1, 0, 0, 0}} {
		if _, _, err := ParseMetadata(data); !errors.Is(err, ErrMetaMalformed) {
			t.Fatalf("malformed data accepted: %x", data)
		}
	}
}

func TestMetadataRejectsNegativeVectors(t *testing.T) {
	for _, name := range []string{"negative-meta-out-of-order.ubc", "negative-meta-duplicate.ubc", "negative-meta-overrun.ubc"} {
		data, err := os.ReadFile("../../spec/vectors/expected/" + name)
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = ParseMetadata(data[HeaderSize:])
		if !errors.Is(err, ErrMetaMalformed) || ErrorCodeOf(err) != CodeMetaMalformed {
			t.Fatalf("%s: %v", name, err)
		}
	}
}
